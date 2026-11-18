//! AES-256-GCM envelope and local key rotation for reference destinations.
//!
//! The database may store the tenant, capability reference, channel, version,
//! key id, nonce and ciphertext. Plaintext exists only in `Destination` at the
//! gateway boundary.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use chrono::{DateTime, Utc};
use kavach_domain::authority::AuthorityChange;
use kavach_domain::mandate::is_capability_ref;
use kavach_mandate::VerifiedAuthorityUpdate;
use kavach_ports::{Destination, PortError, ReferenceResolver};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};
use sqlx::{PgPool, Postgres, Row, Transaction};
use zeroize::Zeroizing;

const ENVELOPE_VERSION: u8 = 1;
const AAD_DOMAIN: &[u8] = b"kavach-reference-vault-v1\0";
const MAX_DESTINATION_BYTES: usize = 4096;

/// Active local AES-256 key and decrypt-only previous keys.
/// Key bytes and paths are never included in formatting or errors.
pub struct ReferenceVaultKey {
    key_id: String,
    key: Zeroizing<[u8; 32]>,
    previous: BTreeMap<String, Zeroizing<[u8; 32]>>,
}

/// Ciphertext envelope for a destination. Tenant, subject and channel remain
/// separate index columns and must be supplied again when opening it.
#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedDestination {
    pub(crate) format_version: u8,
    pub(crate) key_id: String,
    pub(crate) nonce: [u8; 12],
    pub(crate) ciphertext: Vec<u8>,
}

impl EncryptedDestination {
    #[must_use]
    pub fn format_version(&self) -> u8 {
        self.format_version
    }

    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    #[must_use]
    pub fn nonce(&self) -> &[u8; 12] {
        &self.nonce
    }

    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

impl fmt::Debug for EncryptedDestination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EncryptedDestination(<redacted>)")
    }
}

/// Read-only Postgres adapter for encrypted destination rows.
#[derive(Clone)]
pub struct PostgresReferenceResolver {
    pool: PgPool,
    key: std::sync::Arc<ReferenceVaultKey>,
}

impl PostgresReferenceResolver {
    #[must_use]
    pub fn new(pool: PgPool, key: ReferenceVaultKey) -> Self {
        Self {
            pool,
            key: std::sync::Arc::new(key),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppliedReferenceDestination {
    pub replayed: bool,
}

/// Persists signed destinations as authenticated ciphertext. The first source
/// system owns each tenant/reference/channel key; later updates must be newer.
#[derive(Clone)]
pub struct PostgresReferenceDestinationStore {
    pool: PgPool,
    key: std::sync::Arc<ReferenceVaultKey>,
}

impl PostgresReferenceDestinationStore {
    #[must_use]
    pub fn new(pool: PgPool, key: ReferenceVaultKey) -> Self {
        Self {
            pool,
            key: std::sync::Arc::new(key),
        }
    }

    pub async fn apply(
        &self,
        verified: &VerifiedAuthorityUpdate,
    ) -> Result<AppliedReferenceDestination, PortError> {
        let event = verified.event();
        let AuthorityChange::ReferenceDestination(record) = &event.change else {
            return Err(PortError::invalid(
                "authority update is not a reference destination change",
            ));
        };
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| reference_unavailable())?;
        lock_reference_tenant(&mut tx, &event.tenant_id).await?;
        if reference_update_replay(&mut tx, verified).await? {
            tx.commit().await.map_err(|_| reference_unavailable())?;
            return Ok(AppliedReferenceDestination { replayed: true });
        }

        let current = sqlx::query(
            "SELECT version, source_system, source_occurred_at FROM reference_destinations \
             WHERE tenant_id = $1 AND subject_ref = $2 AND channel = $3 FOR UPDATE",
        )
        .bind(&event.tenant_id)
        .bind(&record.subject_ref)
        .bind(&record.channel)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| reference_unavailable())?;
        let previous_version = if let Some(row) = current {
            let version: i64 = row
                .try_get("version")
                .map_err(|_| reference_unavailable())?;
            let source_system: Option<String> = row
                .try_get("source_system")
                .map_err(|_| reference_unavailable())?;
            let source_occurred_at: Option<DateTime<Utc>> = row
                .try_get("source_occurred_at")
                .map_err(|_| reference_unavailable())?;
            let source_system = source_system.ok_or_else(|| {
                PortError::rejected("reference destination has no signed source binding")
            })?;
            let source_occurred_at = source_occurred_at.ok_or_else(|| reference_unavailable())?;
            if source_system != event.system {
                return Err(PortError::rejected(
                    "reference destination source system changed",
                ));
            }
            if event.occurred_at <= source_occurred_at {
                return Err(PortError::rejected(
                    "reference destination update is not newer than the current record",
                ));
            }
            version
        } else {
            0
        };
        let next_version = previous_version
            .checked_add(1)
            .ok_or_else(reference_unavailable)?;
        let destination = Destination::new(record.destination.expose().to_owned());
        let encrypted = self.key.seal(
            &event.tenant_id,
            &record.subject_ref,
            &record.channel,
            next_version,
            &destination,
        )?;
        let metadata = serde_json::json!({
            "tenant_id": event.tenant_id,
            "subject_ref": record.subject_ref,
            "channel": record.channel,
        });
        sqlx::query(
            "INSERT INTO authority_updates \
             (tenant_id, source_system, update_id, kind, subject_ref, channel, \
              payload_sha256, record, occurred_at) \
             VALUES ($1, $2, $3, 'reference_destination', $4, $5, $6, $7, $8)",
        )
        .bind(&event.tenant_id)
        .bind(&event.system)
        .bind(&event.update_id)
        .bind(&record.subject_ref)
        .bind(&record.channel)
        .bind(verified.payload_sha256())
        .bind(metadata)
        .bind(event.occurred_at)
        .execute(&mut *tx)
        .await
        .map_err(|_| reference_unavailable())?;
        if previous_version == 0 {
            sqlx::query(
                "INSERT INTO reference_destinations \
                 (tenant_id, subject_ref, channel, version, format_version, key_id, nonce, \
                  ciphertext, source_system, update_id, source_occurred_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
            )
            .bind(&event.tenant_id)
            .bind(&record.subject_ref)
            .bind(&record.channel)
            .bind(next_version)
            .bind(i16::from(encrypted.format_version()))
            .bind(encrypted.key_id())
            .bind(encrypted.nonce().as_slice())
            .bind(encrypted.ciphertext())
            .bind(&event.system)
            .bind(&event.update_id)
            .bind(event.occurred_at)
            .execute(&mut *tx)
            .await
            .map_err(|_| reference_unavailable())?;
        } else {
            let updated = sqlx::query(
                "UPDATE reference_destinations SET version = $4, format_version = $5, \
                    key_id = $6, nonce = $7, ciphertext = $8, update_id = $9, \
                    source_occurred_at = $10, updated_at = NOW() \
                 WHERE tenant_id = $1 AND subject_ref = $2 AND channel = $3 AND version = $11",
            )
            .bind(&event.tenant_id)
            .bind(&record.subject_ref)
            .bind(&record.channel)
            .bind(next_version)
            .bind(i16::from(encrypted.format_version()))
            .bind(encrypted.key_id())
            .bind(encrypted.nonce().as_slice())
            .bind(encrypted.ciphertext())
            .bind(&event.update_id)
            .bind(event.occurred_at)
            .bind(previous_version)
            .execute(&mut *tx)
            .await
            .map_err(|_| reference_unavailable())?;
            if updated.rows_affected() != 1 {
                return Err(reference_unavailable());
            }
        }
        tx.commit().await.map_err(|_| reference_unavailable())?;
        Ok(AppliedReferenceDestination { replayed: false })
    }
}

fn reference_unavailable() -> PortError {
    PortError::unavailable("reference destination store is unavailable")
}

async fn lock_reference_tenant(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
) -> Result<(), PortError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('kavach-authority:' || $1, 0))")
        .bind(tenant_id)
        .execute(&mut **tx)
        .await
        .map_err(|_| reference_unavailable())?;
    Ok(())
}

async fn reference_update_replay(
    tx: &mut Transaction<'_, Postgres>,
    verified: &VerifiedAuthorityUpdate,
) -> Result<bool, PortError> {
    let event = verified.event();
    let old_digest: Option<String> = sqlx::query_scalar(
        "SELECT payload_sha256 FROM authority_updates \
         WHERE tenant_id = $1 AND source_system = $2 AND update_id = $3",
    )
    .bind(&event.tenant_id)
    .bind(&event.system)
    .bind(&event.update_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| reference_unavailable())?;
    match old_digest {
        Some(digest) if digest == verified.payload_sha256() => Ok(true),
        Some(_) => Err(PortError::rejected(
            "update id reused with different content",
        )),
        None => Ok(false),
    }
}

impl ReferenceResolver for PostgresReferenceResolver {
    async fn resolve(
        &self,
        tenant_id: &str,
        subject_ref: &str,
        channel: &str,
    ) -> Result<Destination, PortError> {
        validate_scope(tenant_id, subject_ref, channel, 1)?;
        let row = sqlx::query(
            "SELECT version, format_version, key_id, nonce, ciphertext FROM reference_destinations \
             WHERE tenant_id = $1 AND subject_ref = $2 AND channel = $3",
        )
        .bind(tenant_id)
        .bind(subject_ref)
        .bind(channel)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| PortError::unavailable("reference vault is unavailable"))?
        .ok_or_else(|| PortError::rejected("no destination is registered for this reference"))?;
        let version: i64 = row
            .try_get("version")
            .map_err(|_| PortError::unavailable("reference vault record is unavailable"))?;
        let format_version: i16 = row
            .try_get("format_version")
            .map_err(|_| PortError::unavailable("reference vault record is unavailable"))?;
        let format_version = u8::try_from(format_version)
            .map_err(|_| PortError::unavailable("reference vault record is unavailable"))?;
        let key_id: String = row
            .try_get("key_id")
            .map_err(|_| PortError::unavailable("reference vault record is unavailable"))?;
        let nonce_bytes: Vec<u8> = row
            .try_get("nonce")
            .map_err(|_| PortError::unavailable("reference vault record is unavailable"))?;
        let nonce: [u8; 12] = nonce_bytes
            .try_into()
            .map_err(|_| PortError::unavailable("reference vault record is unavailable"))?;
        let ciphertext: Vec<u8> = row
            .try_get("ciphertext")
            .map_err(|_| PortError::unavailable("reference vault record is unavailable"))?;
        let encrypted = EncryptedDestination {
            format_version,
            key_id,
            nonce,
            ciphertext,
        };
        self.key
            .open(&encrypted, tenant_id, subject_ref, channel, version)
            .map_err(|_| PortError::unavailable("reference vault record could not be opened"))
    }

    fn describe(&self) -> String {
        "Postgres encrypted reference vault".into()
    }
}

impl ReferenceVaultKey {
    /// Loads a 32-byte key from an owner-managed file containing 64 hex
    /// characters and, optionally, one final line feed.
    pub fn from_file(path: &Path, key_id: &str) -> Result<Self, String> {
        validate_key_id(key_id)?;
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|_| "reference vault key file is unavailable".to_string())?;
        if !metadata.is_file() || metadata.file_type().is_symlink() || !owner_only(&metadata) {
            return Err("reference vault key file must be a regular owner-only file".into());
        }
        if !matches!(metadata.len(), 64 | 65) {
            return Err("reference vault key file must contain 64 hexadecimal characters".into());
        }
        let text = Zeroizing::new(
            std::fs::read_to_string(path)
                .map_err(|_| "reference vault key file could not be read".to_string())?,
        );
        let encoded = text.strip_suffix('\n').unwrap_or(&text);
        if encoded.len() != 64 {
            return Err("reference vault key file must contain 64 hexadecimal characters".into());
        }
        let mut key = Zeroizing::new([0u8; 32]);
        hex::decode_to_slice(encoded, &mut *key)
            .map_err(|_| "reference vault key file is not valid hexadecimal".to_string())?;
        Ok(Self {
            key_id: key_id.to_owned(),
            key,
            previous: BTreeMap::new(),
        })
    }

    /// Adds a decrypt-only key. Previous keys never encrypt new destinations.
    pub fn add_previous(&mut self, previous: Self) -> Result<(), String> {
        if !previous.previous.is_empty() {
            return Err("add each previous reference vault key separately".into());
        }
        if self.key_id == previous.key_id || self.previous.contains_key(&previous.key_id) {
            return Err("reference vault key ids must be unique".into());
        }
        if self.key.as_ref() == previous.key.as_ref()
            || self
                .previous
                .values()
                .any(|key| key.as_ref() == previous.key.as_ref())
        {
            return Err("reference vault key material must be unique".into());
        }
        self.previous.insert(previous.key_id, previous.key);
        Ok(())
    }

    /// The non-secret id used for new ciphertext.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Encrypts a destination with scope bound as authenticated data.
    pub fn seal(
        &self,
        tenant_id: &str,
        subject_ref: &str,
        channel: &str,
        record_version: i64,
        destination: &Destination,
    ) -> Result<EncryptedDestination, kavach_ports::PortError> {
        validate_scope(tenant_id, subject_ref, channel, record_version)?;
        let value = destination.expose();
        if value.is_empty() || value.len() > MAX_DESTINATION_BYTES {
            return Err(kavach_ports::PortError::invalid(
                "reference destination size is invalid",
            ));
        }
        let mut plaintext = Zeroizing::new(value.as_bytes().to_vec());
        let cipher = cipher(&self.key)?;
        let mut nonce = [0u8; 12];
        SystemRandom::new().fill(&mut nonce).map_err(|_| {
            kavach_ports::PortError::unavailable("reference vault randomness failed")
        })?;
        let aad = reference_aad(
            ENVELOPE_VERSION,
            &self.key_id,
            tenant_id,
            subject_ref,
            channel,
            record_version,
        )?;
        cipher
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad.as_slice()),
                &mut *plaintext,
            )
            .map_err(|_| {
                kavach_ports::PortError::unavailable("reference vault encryption failed")
            })?;
        Ok(EncryptedDestination {
            format_version: ENVELOPE_VERSION,
            key_id: self.key_id.clone(),
            nonce,
            ciphertext: plaintext.to_vec(),
        })
    }

    /// Opens only under the exact index values and version used to seal it.
    pub fn open(
        &self,
        encrypted: &EncryptedDestination,
        tenant_id: &str,
        subject_ref: &str,
        channel: &str,
        record_version: i64,
    ) -> Result<Destination, kavach_ports::PortError> {
        validate_scope(tenant_id, subject_ref, channel, record_version)?;
        if encrypted.format_version != ENVELOPE_VERSION
            || encrypted.ciphertext.len() > MAX_DESTINATION_BYTES + 16
        {
            return Err(kavach_ports::PortError::rejected(
                "reference vault envelope is invalid",
            ));
        }
        let key = if encrypted.key_id == self.key_id {
            &self.key
        } else {
            self.previous.get(&encrypted.key_id).ok_or_else(|| {
                kavach_ports::PortError::unavailable(
                    "reference vault decryption key is unavailable",
                )
            })?
        };
        let cipher = cipher(key)?;
        let aad = reference_aad(
            encrypted.format_version,
            &encrypted.key_id,
            tenant_id,
            subject_ref,
            channel,
            record_version,
        )?;
        let mut plaintext = Zeroizing::new(encrypted.ciphertext.clone());
        let bytes = cipher
            .open_in_place(
                Nonce::assume_unique_for_key(encrypted.nonce),
                Aad::from(aad.as_slice()),
                &mut plaintext,
            )
            .map_err(|_| {
                kavach_ports::PortError::rejected("reference vault authentication failed")
            })?;
        if bytes.is_empty() || bytes.len() > MAX_DESTINATION_BYTES {
            return Err(kavach_ports::PortError::rejected(
                "reference vault plaintext size is invalid",
            ));
        }
        let value = Zeroizing::new(
            std::str::from_utf8(bytes)
                .map_err(|_| {
                    kavach_ports::PortError::rejected("reference vault plaintext is invalid")
                })?
                .to_owned(),
        );
        Ok(Destination::new(value.as_str().to_owned()))
    }
}

fn validate_key_id(key_id: &str) -> Result<(), String> {
    if key_id.is_empty() || key_id.len() > 128 || key_id.chars().any(char::is_control) {
        return Err("reference vault key id must be 1–128 non-control characters".into());
    }
    Ok(())
}

#[cfg(unix)]
fn owner_only(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode().trailing_zeros() >= 6
}

#[cfg(not(unix))]
fn owner_only(_metadata: &std::fs::Metadata) -> bool {
    false
}

fn validate_scope(
    tenant_id: &str,
    subject_ref: &str,
    channel: &str,
    record_version: i64,
) -> Result<(), kavach_ports::PortError> {
    if tenant_id.trim().is_empty()
        || !is_capability_ref(subject_ref)
        || channel.is_empty()
        || channel.len() > 32
        || !channel
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        || record_version <= 0
    {
        return Err(kavach_ports::PortError::invalid(
            "reference vault scope is invalid",
        ));
    }
    Ok(())
}

fn cipher(key: &[u8; 32]) -> Result<LessSafeKey, kavach_ports::PortError> {
    UnboundKey::new(&AES_256_GCM, key)
        .map(LessSafeKey::new)
        .map_err(|_| kavach_ports::PortError::invalid("invalid reference vault key"))
}

fn reference_aad(
    envelope_version: u8,
    key_id: &str,
    tenant_id: &str,
    subject_ref: &str,
    channel: &str,
    record_version: i64,
) -> Result<Vec<u8>, kavach_ports::PortError> {
    let mut aad = Vec::from(AAD_DOMAIN);
    aad.push(envelope_version);
    let version_bytes = record_version.to_be_bytes();
    for value in [
        key_id.as_bytes(),
        tenant_id.as_bytes(),
        subject_ref.as_bytes(),
        channel.as_bytes(),
        version_bytes.as_slice(),
    ] {
        let length = u32::try_from(value.len())
            .map_err(|_| kavach_ports::PortError::invalid("reference vault scope is too long"))?;
        aad.extend_from_slice(&length.to_be_bytes());
        aad.extend_from_slice(value);
    }
    Ok(aad)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn key_file(contents: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "kavach-reference-vault-key-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::write(&path, contents).expect("write test key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .expect("secure test key mode");
        }
        path
    }

    fn key(hex: &str, id: &str) -> ReferenceVaultKey {
        let path = key_file(&format!("{hex}\n"));
        let loaded = ReferenceVaultKey::from_file(&path, id).expect("load key");
        fs::remove_file(path).expect("remove test key");
        loaded
    }

    #[test]
    fn seals_and_opens_only_with_the_original_scope() {
        let key = key(&"ab".repeat(32), "reference-v1");
        let destination = Destination::new("+910000000001");
        let encrypted = key
            .seal("tenant-a", "ref:borrower:B-1", "sms", 7, &destination)
            .expect("seal destination");
        assert!(!encrypted
            .ciphertext
            .windows(destination.expose().len())
            .any(|window| window == destination.expose().as_bytes()));
        assert_eq!(
            key.open(&encrypted, "tenant-a", "ref:borrower:B-1", "sms", 7)
                .expect("open destination")
                .expose(),
            destination.expose()
        );
        for (tenant, subject, channel, version) in [
            ("tenant-b", "ref:borrower:B-1", "sms", 7),
            ("tenant-a", "ref:borrower:B-2", "sms", 7),
            ("tenant-a", "ref:borrower:B-1", "voice", 7),
            ("tenant-a", "ref:borrower:B-1", "sms", 8),
        ] {
            assert!(key
                .open(&encrypted, tenant, subject, channel, version)
                .is_err());
        }
        let mut changed = encrypted.clone();
        changed.key_id = "unknown-key".into();
        assert!(key
            .open(&changed, "tenant-a", "ref:borrower:B-1", "sms", 7)
            .is_err());
        changed = encrypted;
        changed.ciphertext[0] ^= 1;
        assert!(key
            .open(&changed, "tenant-a", "ref:borrower:B-1", "sms", 7)
            .is_err());
    }

    #[test]
    fn rotated_key_is_decrypt_only_and_files_are_strict() {
        let old_key = key(&"cd".repeat(32), "reference-v1");
        let old_ciphertext = old_key
            .seal(
                "tenant-a",
                "ref:borrower:B-1",
                "sms",
                1,
                &Destination::new("+910000000001"),
            )
            .expect("seal with old key");
        let mut active = key(&"ef".repeat(32), "reference-v2");
        active.add_previous(old_key).expect("add decrypt-only key");
        assert_eq!(active.key_id(), "reference-v2");
        assert_eq!(
            active
                .open(&old_ciphertext, "tenant-a", "ref:borrower:B-1", "sms", 1)
                .expect("open with previous key")
                .expose(),
            "+910000000001"
        );
        assert!(
            active
                .seal(
                    "tenant-a",
                    "ref:borrower:B-1",
                    "sms",
                    2,
                    &Destination::new("+910000000002"),
                )
                .expect("seal with active key")
                .key_id
                == "reference-v2"
        );
        assert!(active
            .add_previous(key(&"ef".repeat(32), "duplicate-material"))
            .is_err());

        for malformed in ["", "ab", &format!("{} ", "ab".repeat(32)), &"zz".repeat(32)] {
            let path = key_file(malformed);
            assert!(ReferenceVaultKey::from_file(&path, "reference-v1").is_err());
            fs::remove_file(path).expect("remove malformed key file");
        }
    }

    #[cfg(unix)]
    #[test]
    fn refuses_group_readable_and_symlink_key_files() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let exposed = key_file(&"ab".repeat(32));
        fs::set_permissions(&exposed, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(ReferenceVaultKey::from_file(&exposed, "reference-v1").is_err());
        fs::set_permissions(&exposed, fs::Permissions::from_mode(0o600)).unwrap();
        let link = std::env::temp_dir().join(format!(
            "kavach-reference-vault-link-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        symlink(&exposed, &link).expect("create test symlink");
        assert!(ReferenceVaultKey::from_file(&link, "reference-v1").is_err());
        fs::remove_file(link).unwrap();
        fs::remove_file(exposed).unwrap();
    }

    #[test]
    fn refuses_invalid_scope_and_destination() {
        let key = key(&"11".repeat(32), "reference-v1");
        let destination = Destination::new("+910000000001");
        assert!(key
            .seal("tenant-a", "raw-subject", "sms", 1, &destination)
            .is_err());
        assert!(key
            .seal("tenant-a", "ref:borrower:B-1", "SMS", 1, &destination)
            .is_err());
        assert!(key
            .seal("tenant-a", "ref:borrower:B-1", "sms", 0, &destination)
            .is_err());
        assert!(key
            .seal(
                "tenant-a",
                "ref:borrower:B-1",
                "sms",
                1,
                &Destination::new(""),
            )
            .is_err());
        assert_eq!(
            format!(
                "{:?}",
                key.seal("tenant-a", "ref:borrower:B-1", "sms", 1, &destination)
                    .unwrap()
            ),
            "EncryptedDestination(<redacted>)"
        );
    }
}

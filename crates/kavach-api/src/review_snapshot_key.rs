//! Key-file loading and rotation for encrypted D17 review snapshots.
//!
//! The file contains exactly 32 bytes as 64 hexadecimal characters, optionally
//! followed by one line feed. Production deployments should keep it owner-only
//! and back it up with the encrypted snapshot database.

use std::collections::BTreeMap;
use std::path::Path;

use zeroize::Zeroizing;

/// Active AES-256-GCM key and decrypt-only previous keys for D17 snapshots.
/// Neither key bytes nor their file paths are included in `Debug` or logs.
pub struct ReviewSnapshotKey {
    key_id: String,
    key: Zeroizing<[u8; 32]>,
    previous: BTreeMap<String, Zeroizing<[u8; 32]>>,
}

impl ReviewSnapshotKey {
    /// Loads a stable 256-bit key from an owner-managed hex file.
    pub fn from_file(path: &Path, key_id: &str) -> Result<Self, String> {
        if key_id.is_empty() || key_id.len() > 128 || key_id.chars().any(char::is_control) {
            return Err("--review-snapshot-key-id must be 1–128 non-control characters".into());
        }
        let text = Zeroizing::new(
            std::fs::read_to_string(path)
                .map_err(|_| "--review-snapshot-key-file could not be read".to_string())?,
        );
        let encoded = text.strip_suffix('\n').unwrap_or(&text);
        if encoded.len() != 64 {
            return Err(
                "--review-snapshot-key-file must contain exactly 64 hexadecimal characters".into(),
            );
        }
        let mut key = Zeroizing::new([0u8; 32]);
        hex::decode_to_slice(encoded, &mut *key)
            .map_err(|_| "--review-snapshot-key-file is not valid hexadecimal".to_string())?;
        Ok(Self {
            key_id: key_id.to_owned(),
            key,
            previous: BTreeMap::new(),
        })
    }

    /// Adds a decrypt-only key for envelopes created before the active key
    /// changed. Previous keys are never used to seal new snapshots.
    pub fn add_previous(&mut self, previous: Self) -> Result<(), String> {
        if self.key_id == previous.key_id || self.previous.contains_key(&previous.key_id) {
            return Err("review snapshot key ids must be unique".into());
        }
        if self.key.as_ref() == previous.key.as_ref()
            || self
                .previous
                .values()
                .any(|key| key.as_ref() == previous.key.as_ref())
        {
            return Err("review snapshot key material must be unique".into());
        }
        self.previous.insert(previous.key_id, previous.key);
        Ok(())
    }

    /// The non-secret rotation identifier written into authenticated snapshot
    /// envelopes.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Encrypts a bound projection without exposing the key to the caller.
    pub fn seal(
        &self,
        snapshot: &kavach_dataplane::ReviewActionSnapshot,
        record_id: &str,
        action_hash: &str,
    ) -> Result<kavach_dataplane::EncryptedReviewSnapshot, kavach_ports::PortError> {
        kavach_dataplane::EncryptedReviewSnapshot::seal(
            snapshot,
            &self.key_id,
            record_id,
            action_hash,
            &self.key,
        )
    }

    /// Decrypts only the requested tenant, record, and action using the
    /// envelope's active or configured previous key id.
    pub fn open(
        &self,
        snapshot: &kavach_dataplane::EncryptedReviewSnapshot,
        tenant_id: &str,
        record_id: &str,
        action_hash: &str,
    ) -> Result<kavach_dataplane::ReviewActionSnapshot, kavach_ports::PortError> {
        let (key_id, key) = if snapshot.key_id == self.key_id {
            (&self.key_id, &self.key)
        } else if let Some(key) = self.previous.get(&snapshot.key_id) {
            (&snapshot.key_id, key)
        } else {
            return Err(kavach_ports::PortError::rejected(
                "review snapshot encryption key is unavailable",
            ));
        };
        snapshot.open(key_id, tenant_id, record_id, action_hash, key)
    }
}

/// Encrypts and inserts a review projection, treating an identical retry as
/// success only after decrypting and comparing the already stored projection.
pub async fn persist<S: kavach_ports::ReviewSnapshotStore>(
    key: &ReviewSnapshotKey,
    store: &S,
    snapshot: &kavach_dataplane::ReviewActionSnapshot,
    record_id: &str,
    action_hash: &str,
    expires_at: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), kavach_ports::PortError> {
    if expires_at <= now || snapshot.action_hash()? != action_hash {
        return Err(kavach_ports::PortError::rejected(
            "review snapshot binding or lifetime is invalid",
        ));
    }
    if let Some(existing) = store.get_live(&snapshot.tenant_id, record_id, now).await? {
        return verify_existing(key, &existing, snapshot, action_hash);
    }
    let sealed = key.seal(snapshot, record_id, action_hash)?;
    let stored = kavach_ports::EncryptedReviewSnapshot {
        version: sealed.version,
        key_id: sealed.key_id,
        tenant_id: sealed.tenant_id,
        record_id: sealed.record_id,
        action_hash: sealed.action_hash,
        nonce: sealed.nonce,
        ciphertext: sealed.ciphertext,
        expires_at,
    };
    match store.insert(stored, now).await {
        Ok(()) => Ok(()),
        Err(error) if error.class == kavach_ports::ErrorClass::Rejected => {
            let existing = store
                .get_live(&snapshot.tenant_id, record_id, now)
                .await?
                .ok_or(error)?;
            verify_existing(key, &existing, snapshot, action_hash)
        }
        Err(error) => Err(error),
    }
}

fn verify_existing(
    key: &ReviewSnapshotKey,
    stored: &kavach_ports::EncryptedReviewSnapshot,
    expected: &kavach_dataplane::ReviewActionSnapshot,
    action_hash: &str,
) -> Result<(), kavach_ports::PortError> {
    let envelope = kavach_dataplane::EncryptedReviewSnapshot {
        version: stored.version,
        key_id: stored.key_id.clone(),
        tenant_id: stored.tenant_id.clone(),
        record_id: stored.record_id.clone(),
        action_hash: stored.action_hash.clone(),
        nonce: stored.nonce,
        ciphertext: stored.ciphertext.clone(),
    };
    let opened = key.open(&envelope, &stored.tenant_id, &stored.record_id, action_hash)?;
    if opened == *expected {
        Ok(())
    } else {
        Err(kavach_ports::PortError::rejected(
            "stored review projection does not match the committed action",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use std::fs;

    fn temp_file(contents: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "kavach-review-key-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::write(&path, contents).expect("write test key file");
        path
    }

    #[test]
    fn loads_exact_hex_key_and_keeps_rotation_id() {
        let path = temp_file(&format!("{}\n", "ab".repeat(32)));
        let key = ReviewSnapshotKey::from_file(&path, "review-v1").expect("key");
        let _ = fs::remove_file(path);
        assert_eq!(key.key_id(), "review-v1");
    }

    #[test]
    fn refuses_short_malformed_and_ambiguous_key_files() {
        for value in ["", "ab", &format!("{} ", "ab".repeat(32)), &"zz".repeat(32)] {
            let path = temp_file(value);
            assert!(ReviewSnapshotKey::from_file(&path, "review-v1").is_err());
            let _ = fs::remove_file(path);
        }
    }

    #[test]
    fn refuses_unbounded_or_controlled_key_ids() {
        let path = temp_file(&"ab".repeat(32));
        assert!(ReviewSnapshotKey::from_file(&path, "").is_err());
        assert!(ReviewSnapshotKey::from_file(&path, "bad\nid").is_err());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn refuses_duplicate_rotation_ids_and_key_material() {
        let active_path = temp_file(&"ab".repeat(32));
        let duplicate_id_path = temp_file(&"cd".repeat(32));
        let duplicate_material_path = temp_file(&"ab".repeat(32));
        let mut active = ReviewSnapshotKey::from_file(&active_path, "review-v2").expect("active");
        assert!(active
            .add_previous(
                ReviewSnapshotKey::from_file(&duplicate_id_path, "review-v2").expect("same id")
            )
            .is_err());
        assert!(active
            .add_previous(
                ReviewSnapshotKey::from_file(&duplicate_material_path, "review-v1")
                    .expect("same material")
            )
            .is_err());
        let _ = fs::remove_file(active_path);
        let _ = fs::remove_file(duplicate_id_path);
        let _ = fs::remove_file(duplicate_material_path);
    }

    #[tokio::test]
    async fn persists_only_ciphertext_and_accepts_matching_retries() {
        let path = temp_file(&format!("{}\n", "cd".repeat(32)));
        let key = ReviewSnapshotKey::from_file(&path, "review-v1").expect("key");
        let _ = fs::remove_file(path);
        let now = chrono::Utc::now();
        let snapshot = kavach_dataplane::ReviewActionSnapshot {
            tenant_id: "tenant-1".into(),
            agent_id: "agent-1".into(),
            identity_key: "issuer:subject".into(),
            tool_registry_digest: "sha256:registry".into(),
            mandate_id: "mandate-1".into(),
            request_id: "request-1".into(),
            action: "propose_plan".into(),
            subject_ref: "ref:borrower:B-9382".into(),
            channel: None,
            waiver_bps: Some(3500),
            requested_fields: std::collections::BTreeSet::new(),
            parameters: std::collections::BTreeMap::new(),
        };
        let action_hash = snapshot.action_hash().expect("digest");
        let store = kavach_storage::MemoryReviewSnapshotStore::default();
        let expires_at = now + Duration::minutes(30);
        persist(
            &key,
            &store,
            &snapshot,
            "record-1",
            &action_hash,
            expires_at,
            now,
        )
        .await
        .expect("persist");
        persist(
            &key,
            &store,
            &snapshot,
            "record-1",
            &action_hash,
            expires_at,
            now,
        )
        .await
        .expect("matching retry");
        let rotated_path = temp_file(&format!("{}\n", "ef".repeat(32)));
        let mut rotated =
            ReviewSnapshotKey::from_file(&rotated_path, "review-v2").expect("new key");
        let _ = fs::remove_file(rotated_path);
        rotated.add_previous(key).expect("retain old decrypt key");
        persist(
            &rotated,
            &store,
            &snapshot,
            "record-1",
            &action_hash,
            expires_at,
            now,
        )
        .await
        .expect("matching retry decrypts with previous key");
        persist(
            &rotated,
            &store,
            &snapshot,
            "record-2",
            &action_hash,
            expires_at,
            now,
        )
        .await
        .expect("new snapshot uses active key");
        let newly_sealed =
            kavach_ports::ReviewSnapshotStore::get_live(&store, "tenant-1", "record-2", now)
                .await
                .expect("read new snapshot")
                .expect("new snapshot exists");
        assert_eq!(newly_sealed.key_id, "review-v2");
        let mut altered = snapshot.clone();
        altered.subject_ref = "ref:borrower:B-9999".into();
        let altered_hash = altered.action_hash().expect("altered digest");
        assert!(persist(
            &rotated,
            &store,
            &altered,
            "record-1",
            &altered_hash,
            expires_at,
            now,
        )
        .await
        .is_err());
        let stored =
            kavach_ports::ReviewSnapshotStore::get_live(&store, "tenant-1", "record-1", now)
                .await
                .expect("read")
                .expect("snapshot");
        assert!(!stored
            .ciphertext
            .windows(b"B-9382".len())
            .any(|part| part == b"B-9382"));
    }
}

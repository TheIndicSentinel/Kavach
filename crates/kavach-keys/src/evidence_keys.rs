//! Keys for agent evidence (H5a-3b): an in-memory Ed25519 evidence signer and
//! the subject-pseudonym secret.
//!
//! - The evidence key signs agent records and outcomes only; it is loaded once
//!   (no disk read under the partition lock).
//! - `SubjectKeys` derives two independent HMAC keys from one 32-byte secret
//!   (`subject pseudonym`, `params MAC`), each binding the tenant, so values
//!   are not comparable across tenants or purposes. Borrower references are
//!   low-entropy: anyone with the secret and the database could enumerate
//!   them, so the secret is treated like a signing key (owner-only file).

use std::path::Path;

use ed25519_dalek::{Signer, SigningKey};
use hmac::{Hmac, Mac};
use kavach_ports::agent_evidence::EvidenceSigner;
use kavach_ports::{KeyAlgorithm, PortError, PublicKey};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const PSEUDONYM_LABEL: &[u8] = b"kavach-subject-pseudonym-v1";
const PARAMS_MAC_LABEL: &[u8] = b"kavach-params-mac-v1";
const RECORD_PSEUDONYM_LABEL: &[u8] = b"kavach-record-pseudonym-v1";

/// Ed25519 evidence signer holding its key in memory.
pub struct Ed25519EvidenceSigner {
    kid: String,
    key: SigningKey,
}

impl std::fmt::Debug for Ed25519EvidenceSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ed25519EvidenceSigner")
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

impl Ed25519EvidenceSigner {
    pub fn from_seed(kid: &str, seed: [u8; 32]) -> Result<Self, PortError> {
        crate::validate_kid(kid)?;
        Ok(Self {
            kid: kid.into(),
            key: SigningKey::from_bytes(&seed),
        })
    }

    /// Loads `<dir>/<kid>.ed25519` once (owner-only, as `LocalFileKeyProvider`).
    pub fn from_key_dir(dir: &Path, kid: &str) -> Result<Self, PortError> {
        let seed = crate::read_seed_file(&dir.join(format!("{kid}.ed25519")), kid)?;
        Self::from_seed(kid, seed)
    }

    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            kid: self.kid.clone(),
            algorithm: KeyAlgorithm::Ed25519,
            bytes: self.key.verifying_key().to_bytes(),
        }
    }
}

impl EvidenceSigner for Ed25519EvidenceSigner {
    fn key_id(&self) -> &str {
        &self.kid
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, PortError> {
        Ok(self.key.sign(message).to_bytes().to_vec())
    }
}

/// Derives the subject pseudonym, the parameters MAC and the pseudonym of a
/// system-of-record record (a loan), each under its own key.
pub struct SubjectKeys {
    pseudonym: [u8; 32],
    params: [u8; 32],
    record: [u8; 32],
}

impl std::fmt::Debug for SubjectKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SubjectKeys(..)")
    }
}

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac takes any key length");
    for part in parts {
        // Length-prefixed, so ("ab","c") and ("a","bc") differ.
        mac.update(&u64::try_from(part.len()).unwrap_or(u64::MAX).to_be_bytes());
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

impl SubjectKeys {
    #[must_use]
    pub fn from_secret(secret: [u8; 32]) -> Self {
        Self {
            pseudonym: hmac(&secret, &[PSEUDONYM_LABEL]),
            params: hmac(&secret, &[PARAMS_MAC_LABEL]),
            record: hmac(&secret, &[RECORD_PSEUDONYM_LABEL]),
        }
    }

    /// Reads a hex file holding exactly 32 bytes, owner-only on Unix.
    pub fn from_file(path: &Path) -> Result<Self, PortError> {
        Ok(Self::from_secret(crate::read_seed_file(
            path,
            "subject-pseudonym",
        )?))
    }

    /// `psn:<hex>` for a subject reference within a tenant.
    #[must_use]
    pub fn pseudonym(&self, tenant_id: &str, subject_ref: &str) -> String {
        format!(
            "psn:{}",
            hex::encode(hmac(
                &self.pseudonym,
                &[tenant_id.as_bytes(), subject_ref.as_bytes()]
            ))
        )
    }

    /// `psn:<hex>` for a system-of-record record (`record_ref` of `system`)
    /// within a tenant, under a key of its own: it never equals a subject's
    /// pseudonym, and evidence never holds the reference itself (ADR-012 §7).
    #[must_use]
    pub fn record_pseudonym(&self, tenant_id: &str, system: &str, record_ref: &str) -> String {
        format!(
            "psn:{}",
            hex::encode(hmac(
                &self.record,
                &[
                    tenant_id.as_bytes(),
                    system.as_bytes(),
                    record_ref.as_bytes()
                ]
            ))
        )
    }

    /// `mac:<hex>` over canonical parameters within a tenant.
    #[must_use]
    pub fn params_mac(&self, tenant_id: &str, canonical_params: &[u8]) -> String {
        format!(
            "mac:{}",
            hex::encode(hmac(
                &self.params,
                &[tenant_id.as_bytes(), canonical_params]
            ))
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_values_are_separated_by_purpose_and_tenant() {
        let keys = SubjectKeys::from_secret([7u8; 32]);
        let a = keys.pseudonym("t1", "ref:borrower:B-1");
        assert_eq!(a, keys.pseudonym("t1", "ref:borrower:B-1"), "deterministic");
        assert_ne!(a, keys.pseudonym("t2", "ref:borrower:B-1"), "tenant-bound");
        assert_ne!(
            a.trim_start_matches("psn:"),
            keys.params_mac("t1", b"ref:borrower:B-1")
                .trim_start_matches("mac:"),
            "pseudonym and params MAC use different keys"
        );
        assert_ne!(
            a,
            SubjectKeys::from_secret([8u8; 32]).pseudonym("t1", "ref:borrower:B-1")
        );
        let loan = keys.record_pseudonym("t1", "lms", "lms:loan/L-1");
        assert_eq!(loan, keys.record_pseudonym("t1", "lms", "lms:loan/L-1"));
        assert_ne!(loan, keys.record_pseudonym("t2", "lms", "lms:loan/L-1"));
        assert_ne!(loan, keys.record_pseudonym("t1", "crm", "lms:loan/L-1"));
        assert_ne!(
            loan,
            keys.pseudonym("t1", "lms:loan/L-1"),
            "a record and a subject never share a pseudonym"
        );
        assert!(!loan.contains("L-1"));
    }

    #[test]
    fn evidence_signatures_verify_with_the_public_key() {
        let signer = Ed25519EvidenceSigner::from_seed("evidence-1", [3u8; 32]).unwrap();
        let sig = signer.sign(b"m").unwrap();
        kavach_ports::verify_ed25519(&signer.public_key(), b"m", &sig).unwrap();
    }
}

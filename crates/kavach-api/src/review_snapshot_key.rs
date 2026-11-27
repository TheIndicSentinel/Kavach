//! Stable key-file loading for encrypted D17 review snapshots.
//!
//! The file contains exactly 32 bytes as 64 hexadecimal characters, optionally
//! followed by one line feed. Production deployments should keep it owner-only
//! and back it up with the encrypted snapshot database.

use std::path::Path;

use zeroize::Zeroizing;

/// Dedicated AES-256-GCM key and rotation identifier for review snapshots.
/// Neither key bytes nor their file path are included in `Debug` or logs.
pub struct ReviewSnapshotKey {
    key_id: String,
    key: Zeroizing<[u8; 32]>,
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
        })
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

    /// Decrypts only the requested tenant, record, and action using this key id.
    pub fn open(
        &self,
        snapshot: &kavach_dataplane::EncryptedReviewSnapshot,
        tenant_id: &str,
        record_id: &str,
        action_hash: &str,
    ) -> Result<kavach_dataplane::ReviewActionSnapshot, kavach_ports::PortError> {
        snapshot.open(&self.key_id, tenant_id, record_id, action_hash, &self.key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
}

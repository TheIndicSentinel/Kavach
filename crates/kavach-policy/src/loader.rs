use std::fs;
use std::path::Path;

use cel_interpreter::Program;
use kavach_domain::PolicyPack;
use sha2::{Digest, Sha256};

use crate::error::PolicyError;

/// A policy pack with CEL programs compiled at load time.
pub struct LoadedPolicyPack {
    pub pack: PolicyPack,
    pub compiled_rules: Vec<CompiledRule>,
    /// `sha256:<hex>` of the pack file bytes, when loaded from a file.
    pub digest: Option<String>,
}

impl LoadedPolicyPack {
    /// Fails when `expected` is set and does not equal the loaded pack's file digest.
    pub fn verify_pin(&self, expected: Option<&str>) -> Result<(), PolicyError> {
        let Some(expected) = expected else {
            return Ok(());
        };
        let expected = normalize_digest(expected);
        match self.digest.as_deref() {
            Some(actual) if actual == expected => Ok(()),
            actual => Err(PolicyError::DigestMismatch {
                expected,
                actual: actual.unwrap_or("none").to_string(),
            }),
        }
    }
}

/// `sha256:<lowercase hex>` of `bytes`.
pub fn pack_digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

/// Accepts a bare hex digest or a `sha256:`-prefixed one.
pub fn normalize_digest(digest: &str) -> String {
    let hex = digest
        .trim()
        .trim_start_matches("sha256:")
        .to_ascii_lowercase();
    format!("sha256:{hex}")
}

pub struct CompiledRule {
    pub id: String,
    pub program: Program,
    pub decision: kavach_domain::Decision,
    pub reason_code: String,
}

pub struct PackLoader;

impl PackLoader {
    pub fn load_from_path(path: &Path) -> Result<LoadedPolicyPack, PolicyError> {
        let bytes = fs::read(path)?;
        let pack: PolicyPack = serde_yaml::from_slice(&bytes)?;
        let mut loaded = Self::load_from_pack(pack)?;
        loaded.digest = Some(pack_digest(&bytes));
        Ok(loaded)
    }

    pub fn load_from_pack(pack: PolicyPack) -> Result<LoadedPolicyPack, PolicyError> {
        if pack.rules.is_empty() {
            return Err(PolicyError::Validation(
                "pack must contain at least one rule".into(),
            ));
        }

        let mut compiled_rules = Vec::with_capacity(pack.rules.len());
        for rule in &pack.rules {
            let program =
                Program::compile(&rule.expression).map_err(|e| PolicyError::CelCompile {
                    rule_id: rule.id.clone(),
                    message: e.to_string(),
                })?;
            compiled_rules.push(CompiledRule {
                id: rule.id.clone(),
                program,
                decision: rule.decision,
                reason_code: rule.reason_code.clone(),
            });
        }

        Ok(LoadedPolicyPack {
            pack,
            compiled_rules,
            digest: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn finance_pack_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packs/finance/v0.yaml")
    }

    #[test]
    fn digest_matches_file_bytes() {
        let path = finance_pack_path();
        let loaded = PackLoader::load_from_path(&path).expect("load pack");
        let expected = pack_digest(&fs::read(&path).expect("read pack"));
        assert_eq!(loaded.digest.as_deref(), Some(expected.as_str()));
        assert!(expected.starts_with("sha256:") && expected.len() == 7 + 64);
    }

    #[test]
    fn verify_pin_accepts_bare_or_prefixed_and_rejects_mismatch() {
        let loaded = PackLoader::load_from_path(&finance_pack_path()).expect("load pack");
        let digest = loaded.digest.clone().expect("digest");
        let bare = digest.trim_start_matches("sha256:").to_ascii_uppercase();
        loaded.verify_pin(None).expect("no pin");
        loaded.verify_pin(Some(&digest)).expect("prefixed pin");
        loaded.verify_pin(Some(&bare)).expect("bare pin");
        let err = loaded
            .verify_pin(Some(&"0".repeat(64)))
            .expect_err("mismatch must fail");
        assert!(matches!(err, PolicyError::DigestMismatch { .. }));
    }
}

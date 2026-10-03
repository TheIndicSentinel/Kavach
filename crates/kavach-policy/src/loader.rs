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

fn validate_limits(pack: &PolicyPack) -> Result<(), PolicyError> {
    if pack.rules.len() > MAX_RULES {
        return Err(PolicyError::Validation(format!(
            "pack has {} rules; limit is {MAX_RULES}",
            pack.rules.len()
        )));
    }
    if let Some(rule) = pack
        .rules
        .iter()
        .find(|r| r.expression.chars().count() > MAX_EXPRESSION_CHARS)
    {
        return Err(PolicyError::Validation(format!(
            "rule `{}` expression exceeds {MAX_EXPRESSION_CHARS} characters",
            rule.id
        )));
    }
    if let Some(limits) = &pack.cel_runtime_limits {
        if limits.timeout_ms == 0 || limits.timeout_ms > MAX_TIMEOUT_MS {
            return Err(PolicyError::Validation(format!(
                "cel_runtime_limits.timeout_ms must be 1..={MAX_TIMEOUT_MS}"
            )));
        }
    }
    Ok(())
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

/// Load-time bounds that stand in for CEL memory limits (the interpreter has
/// no allocation-limit API, and the timeout is only checked between rules).
/// Runs CEL work (the third-party parser or interpreter) and turns a panic
/// inside it into an error message. The parser has panicked on malformed
/// input (a trailing `&&`, found by the `cel_policy` fuzz target): a pack
/// with such a rule must be refused, and an evaluation that panics must be
/// a recorded BLOCK, never a crash.
pub(crate) fn contained<T>(work: impl FnOnce() -> T) -> Result<T, String> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(work)).map_err(|panic| {
        panic
            .downcast_ref::<&str>()
            .map(ToString::to_string)
            .or_else(|| panic.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "panic".into())
    })
}

pub const MAX_PACK_BYTES: usize = 256 * 1024;
pub const MAX_RULES: usize = 200;
pub const MAX_EXPRESSION_CHARS: usize = 2048;
pub const MAX_TIMEOUT_MS: u64 = 1000;

impl PackLoader {
    pub fn load_from_path(path: &Path) -> Result<LoadedPolicyPack, PolicyError> {
        let bytes = fs::read(path)?;
        if bytes.len() > MAX_PACK_BYTES {
            return Err(PolicyError::Validation(format!(
                "pack file is {} bytes; limit is {MAX_PACK_BYTES}",
                bytes.len()
            )));
        }
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
        validate_limits(&pack)?;

        let mut compiled_rules = Vec::with_capacity(pack.rules.len());
        for rule in &pack.rules {
            let compile_error = |message: String| PolicyError::CelCompile {
                rule_id: rule.id.clone(),
                message,
            };
            let program = contained(|| Program::compile(&rule.expression))
                .map_err(|panic| compile_error(format!("the CEL parser failed: {panic}")))?
                .map_err(|e| compile_error(e.to_string()))?;
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
    fn load_limits_reject_oversized_packs() {
        let base = PackLoader::load_from_path(&finance_pack_path())
            .expect("load pack")
            .pack;

        let mut long_expr = base.clone();
        long_expr.rules[0].expression = format!("true || {}", "true || ".repeat(400));
        assert!(PackLoader::load_from_pack(long_expr).is_err());

        let mut many_rules = base.clone();
        let rule = many_rules.rules[0].clone();
        many_rules.rules = vec![rule; MAX_RULES + 1];
        assert!(PackLoader::load_from_pack(many_rules).is_err());

        let mut slow = base;
        if let Some(limits) = slow.cel_runtime_limits.as_mut() {
            limits.timeout_ms = MAX_TIMEOUT_MS + 1;
        }
        assert!(PackLoader::load_from_pack(slow).is_err());
    }

    /// Found by the `cel_policy` fuzz target: the CEL parser panicked
    /// ("entered unreachable code") on an expression with a trailing `&&`.
    /// The pack is refused instead.
    #[test]
    fn an_expression_that_makes_the_parser_panic_is_refused() {
        let mut pack = PackLoader::load_from_path(&finance_pack_path())
            .expect("load pack")
            .pack;
        pack.rules[0].expression = r#"request.purpose.startsWith("credit") && "#.into();
        match PackLoader::load_from_pack(pack) {
            Err(PolicyError::CelCompile { rule_id, message }) => {
                assert!(!rule_id.is_empty());
                assert!(!message.is_empty());
            }
            other => panic!("expected a refused pack, got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn contained_work_returns_its_value_or_the_panic_message() {
        assert_eq!(contained(|| 7), Ok(7));
        assert_eq!(
            contained(|| -> u8 { panic!("boom") }),
            Err("boom".to_string())
        );
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

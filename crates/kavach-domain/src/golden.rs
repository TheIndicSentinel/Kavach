//! Golden fixture loader and structural validation for Phase 0.

use serde::Deserialize;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

use crate::decision::Decision;
use crate::error::DomainError;
use crate::request::EvaluateRequest;
use crate::response::GovernanceMode;

#[derive(Debug, Deserialize)]
pub struct GoldenFixture {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub model: GoldenModel,
    pub request: EvaluateRequest,
    pub expect: GoldenExpect,
}

#[derive(Debug, Deserialize)]
pub struct GoldenModel {
    pub model_id: String,
    pub model_version: String,
    pub sector: String,
    pub governance_mode: GovernanceMode,
    pub pack_id: String,
}

#[derive(Debug, Deserialize)]
pub struct GoldenExpect {
    #[serde(default)]
    pub policy_decision: Option<Decision>,
    pub returned_decision_enforce: Option<Decision>,
    pub returned_decision_sync_shadow: Option<Decision>,
    #[serde(default)]
    pub reason_codes_contains: Vec<String>,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub policy_decision_v0_pack: Option<Decision>,
    #[serde(default)]
    pub mvp_ui_expected: Option<Decision>,
}

pub fn load_fixtures(dir: &Path) -> Result<Vec<GoldenFixture>, DomainError> {
    let mut fixtures = Vec::new();
    for entry in walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "json"))
    {
        let content = fs::read_to_string(entry.path())
            .map_err(|e| DomainError::Golden(format!("read {}: {e}", entry.path().display())))?;
        let fixture: GoldenFixture = serde_json::from_str(&content)?;
        fixtures.push(fixture);
    }
    fixtures.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(fixtures)
}

pub fn workspace_golden_v0_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../golden/finance/v0")
}

pub fn assert_returned_decision_mapping(
    policy: Decision,
    mode: GovernanceMode,
    expected: Decision,
) -> Result<(), DomainError> {
    let mapped = crate::decision::map_returned_decision(policy, mode, true);
    if mapped != expected {
        return Err(DomainError::Golden(format!(
            "returned_decision mismatch: policy={policy}, mode={mode:?}, got={mapped}, want={expected}"
        )));
    }
    Ok(())
}

pub fn canonical_input_digest(input: &Value) -> String {
    use sha2::{Digest, Sha256};
    let canonical = serde_json::to_string(input).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_v0_golden_fixtures() {
        let dir = workspace_golden_v0_dir();
        let fixtures = load_fixtures(&dir).expect("load golden v0");
        assert!(fixtures.len() >= 4, "expected at least 4 v0 fixtures");
    }

    #[test]
    fn v0_fixtures_validate_consent_expectations() {
        let dir = workspace_golden_v0_dir();
        for fixture in load_fixtures(&dir).unwrap() {
            let consent_result = fixture.request.validate_consent();
            if fixture.name == "credit_missing_consent" {
                assert!(consent_result.is_err());
            } else {
                assert!(consent_result.is_ok());
            }
        }
    }

    #[test]
    fn v0_shadow_mapping_matches_expectations() {
        let dir = workspace_golden_v0_dir();
        for fixture in load_fixtures(&dir).unwrap() {
            let Some(policy) = fixture.expect.policy_decision else {
                continue;
            };
            if let Some(expected_shadow) = fixture.expect.returned_decision_sync_shadow {
                assert_returned_decision_mapping(policy, GovernanceMode::Shadow, expected_shadow)
                    .unwrap_or_else(|e| panic!("{}: {e}", fixture.name));
            }
            if let Some(expected_enforce) = fixture.expect.returned_decision_enforce {
                assert_returned_decision_mapping(policy, GovernanceMode::Enforce, expected_enforce)
                    .unwrap_or_else(|e| panic!("{}: {e}", fixture.name));
            }
        }
    }

    #[test]
    fn input_digest_is_stable() {
        let input = serde_json::json!({"debt_ratio": 0.32, "credit_score": 740});
        let d1 = canonical_input_digest(&input);
        let d2 = canonical_input_digest(&input);
        assert_eq!(d1, d2);
        assert_eq!(d1.len(), 64);
    }
}

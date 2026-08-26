use std::time::{Duration, Instant};

use kavach_domain::{Decision, EvaluateRequest};

use crate::cel_context::build_context;
use crate::error::PolicyError;
use crate::loader::LoadedPolicyPack;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEvaluation {
    pub policy_decision: Decision,
    pub reason_codes: Vec<String>,
    pub policy_hits: Vec<String>,
}

pub struct PolicyEngine;

impl PolicyEngine {
    pub fn evaluate(
        loaded: &LoadedPolicyPack,
        request: &EvaluateRequest,
    ) -> Result<PolicyEvaluation, PolicyError> {
        let timeout_ms = loaded
            .pack
            .cel_runtime_limits
            .as_ref()
            .map(|l| l.timeout_ms)
            .unwrap_or(10);

        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        let context = build_context(request)?;

        let mut policy_decision = Decision::Pass;
        let mut reason_codes = Vec::new();
        let mut policy_hits = Vec::new();

        for rule in &loaded.compiled_rules {
            if Instant::now() >= deadline {
                return Err(PolicyError::Timeout { timeout_ms });
            }

            let value = rule.program.execute(&context).map_err(|e| PolicyError::CelExecute {
                rule_id: rule.id.clone(),
                message: e.to_string(),
            })?;

            if !cel_bool(&value)? {
                continue;
            }

            policy_decision = Decision::max(policy_decision, rule.decision);
            policy_hits.push(rule.id.clone());
            if !reason_codes.contains(&rule.reason_code) {
                reason_codes.push(rule.reason_code.clone());
            }
        }

        Ok(PolicyEvaluation {
            policy_decision,
            reason_codes,
            policy_hits,
        })
    }
}

fn cel_bool(value: &cel_interpreter::objects::Value) -> Result<bool, PolicyError> {
    match value {
        cel_interpreter::objects::Value::Bool(b) => Ok(*b),
        other => Err(PolicyError::CelExecute {
            rule_id: "coerce".into(),
            message: format!("expected bool, got {other:?}"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PackLoader;
    use chrono::Utc;
    use kavach_domain::{Consent, golden::load_fixtures, golden::workspace_golden_v0_dir};
    use std::path::PathBuf;

    fn finance_pack_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packs/finance/v0.yaml")
    }

    fn load_finance_pack() -> LoadedPolicyPack {
        PackLoader::load_from_path(&finance_pack_path()).expect("load finance pack")
    }

    #[test]
    fn golden_v0_policy_decisions_match_expectations() {
        let loaded = load_finance_pack();
        let fixtures = load_fixtures(&workspace_golden_v0_dir()).expect("fixtures");

        for fixture in fixtures {
            let Some(expected) = fixture.expect.policy_decision else {
                continue;
            };

            let evaluation = PolicyEngine::evaluate(&loaded, &fixture.request)
                .unwrap_or_else(|e| panic!("{}: {e}", fixture.name));

            assert_eq!(
                evaluation.policy_decision, expected,
                "{}: policy_decision",
                fixture.name
            );

            for code in &fixture.expect.reason_codes_contains {
                assert!(
                    evaluation.reason_codes.iter().any(|c| c == code),
                    "{}: missing reason code {code}, got {:?}",
                    fixture.name,
                    evaluation.reason_codes
                );
            }
        }
    }

    #[test]
    fn consent_mismatch_blocks() {
        let loaded = load_finance_pack();
        let request = EvaluateRequest {
            model_id: "m".into(),
            model_version: "1".into(),
            purpose: "credit_decision".into(),
            consent: Consent {
                purpose_id: "marketing".into(),
                timestamp: Utc::now(),
                valid: None,
            },
            input: serde_json::json!({ "debt_ratio": 0.30 }),
            output: None,
            score: None,
            confidence: Some(0.85),
            decision_time: Utc::now(),
            correlation_id: "c1".into(),
            idempotency_key: None,
        };

        let evaluation = PolicyEngine::evaluate(&loaded, &request).expect("eval");
        assert_eq!(evaluation.policy_decision, Decision::Block);
        assert!(evaluation.reason_codes.contains(&"CONSENT_MISMATCH".to_string()));
    }
}

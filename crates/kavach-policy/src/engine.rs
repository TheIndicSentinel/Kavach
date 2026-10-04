use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use kavach_domain::{Decision, EvaluateRequest};

use crate::cel_context::{build_context, build_named_context};
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
    /// Evaluates with the current server time as `now`. Prefer
    /// [`PolicyEngine::evaluate_at`] with the caller's trusted time.
    pub fn evaluate(
        loaded: &LoadedPolicyPack,
        request: &EvaluateRequest,
    ) -> Result<PolicyEvaluation, PolicyError> {
        Self::evaluate_at(loaded, request, Utc::now())
    }

    /// Evaluates an evaluate request with trusted server time bound as `now`.
    pub fn evaluate_at(
        loaded: &LoadedPolicyPack,
        request: &EvaluateRequest,
        now: DateTime<Utc>,
    ) -> Result<PolicyEvaluation, PolicyError> {
        Self::run(loaded, &build_context(request, now)?)
    }

    /// Evaluates rules against an arbitrary JSON-serialisable value bound as
    /// variable `name`, plus `now` (used for agent-authorization refinement).
    pub fn evaluate_named<T: serde::Serialize>(
        loaded: &LoadedPolicyPack,
        name: &str,
        value: &T,
        now: DateTime<Utc>,
    ) -> Result<PolicyEvaluation, PolicyError> {
        Self::run(loaded, &build_named_context(name, value, now)?)
    }

    fn run(
        loaded: &LoadedPolicyPack,
        context: &cel::Context<'_>,
    ) -> Result<PolicyEvaluation, PolicyError> {
        let timeout_ms = loaded
            .pack
            .cel_runtime_limits
            .as_ref()
            .map_or(10, |l| l.timeout_ms);

        let deadline = Instant::now() + Duration::from_millis(timeout_ms);

        let mut policy_decision = Decision::Pass;
        let mut reason_codes = Vec::new();
        let mut policy_hits = Vec::new();

        for rule in &loaded.compiled_rules {
            if Instant::now() >= deadline {
                return Err(PolicyError::Timeout { timeout_ms });
            }

            let execute_error = |message: String| PolicyError::CelExecute {
                rule_id: rule.id.clone(),
                message,
            };
            let value = crate::loader::contained(|| rule.program.execute(context))
                .map_err(|panic| execute_error(format!("the CEL interpreter failed: {panic}")))?
                .map_err(|e| execute_error(e.to_string()))?;

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

fn cel_bool(value: &cel::objects::Value) -> Result<bool, PolicyError> {
    match value {
        cel::objects::Value::Bool(b) => Ok(*b),
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
    use kavach_domain::{golden::load_fixtures, golden::workspace_golden_v0_dir, Consent};
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
            consent: Some(Consent {
                purpose_id: "marketing".into(),
                timestamp: Utc::now(),
                valid: None,
            }),
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
        assert!(evaluation
            .reason_codes
            .contains(&"CONSENT_MISMATCH".to_string()));
    }

    /// Rules see trusted server time as `now`, for both the evaluate path and
    /// named JSON contexts (agent refinement).
    #[test]
    fn rules_can_use_trusted_now() {
        use chrono::TimeZone;
        let mut pack = load_finance_pack().pack;
        pack.rules.truncate(1);
        pack.rules[0].expression =
            r#"now >= timestamp("2026-10-01T00:00:00Z") && subject.kind == "borrower""#.into();
        pack.rules[0].decision = Decision::Alert;
        let loaded = crate::PackLoader::load_from_pack(pack).expect("pack");
        let value = serde_json::json!({ "kind": "borrower" });

        let after = Utc.with_ymd_and_hms(2026, 10, 2, 0, 0, 0).unwrap();
        let before = Utc.with_ymd_and_hms(2026, 9, 30, 0, 0, 0).unwrap();
        let hit = PolicyEngine::evaluate_named(&loaded, "subject", &value, after).expect("eval");
        assert_eq!(hit.policy_decision, Decision::Alert);
        let miss = PolicyEngine::evaluate_named(&loaded, "subject", &value, before).expect("eval");
        assert_eq!(miss.policy_decision, Decision::Pass);
    }
}

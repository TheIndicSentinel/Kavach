use chrono::{DateTime, Utc};
use kavach_domain::EvaluateRequest;
use kavach_policy::{
    LoadedPolicyPack, PolicyEngine as CelPolicyEngine, PolicyError, PolicyEvaluation,
};

/// Evaluates a loaded policy pack against a request with trusted time
/// (ADR-006 §4, ADR-003 §8).
pub trait PolicyEngine {
    fn evaluate(
        &self,
        loaded: &LoadedPolicyPack,
        request: &EvaluateRequest,
        now: DateTime<Utc>,
    ) -> Result<PolicyEvaluation, PolicyError>;
}

impl PolicyEngine for CelPolicyEngine {
    fn evaluate(
        &self,
        loaded: &LoadedPolicyPack,
        request: &EvaluateRequest,
        now: DateTime<Utc>,
    ) -> Result<PolicyEvaluation, PolicyError> {
        CelPolicyEngine::evaluate_at(loaded, request, now)
    }
}

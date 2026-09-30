use kavach_domain::EvaluateRequest;
use kavach_policy::{
    LoadedPolicyPack, PolicyEngine as CelPolicyEngine, PolicyError, PolicyEvaluation,
};

/// Evaluates a loaded policy pack against a request (ADR-006 §4).
pub trait PolicyEngine {
    fn evaluate(
        &self,
        loaded: &LoadedPolicyPack,
        request: &EvaluateRequest,
    ) -> Result<PolicyEvaluation, PolicyError>;
}

impl PolicyEngine for CelPolicyEngine {
    fn evaluate(
        &self,
        loaded: &LoadedPolicyPack,
        request: &EvaluateRequest,
    ) -> Result<PolicyEvaluation, PolicyError> {
        CelPolicyEngine::evaluate(loaded, request)
    }
}

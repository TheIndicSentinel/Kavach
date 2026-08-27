use std::time::Instant;

use chrono::{DateTime, Utc};
use jsonschema::Validator;
use kavach_domain::{
    decision::map_returned_decision_for_path, golden::canonical_input_digest, Decision,
    EvaluatePath, EvaluateRequest, EvaluateResponse, ModelRecord,
};
use kavach_evidence::AppendDecisionEvent;
use kavach_policy::{LoadedPolicyPack, PolicyEngine};

use crate::error::EvaluateError;
use crate::ports::{EvaluateIncident, EvidenceStore, IncidentRecorder};
use crate::validation::{compile_input_validator, validate_input, validate_model_binding};

#[derive(Debug, Clone)]
pub struct EvaluateConfig {
    pub clock_skew_max_seconds: i64,
    pub service_identity_id: String,
}

impl Default for EvaluateConfig {
    fn default() -> Self {
        Self {
            clock_skew_max_seconds: 300,
            service_identity_id: "kavach-evaluate".into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct EvaluateResult {
    pub response: EvaluateResponse,
    pub incident: Option<EvaluateIncident>,
}

pub struct EvaluateService<S, I> {
    pack: LoadedPolicyPack,
    model: ModelRecord,
    input_validator: Validator,
    evidence: S,
    incidents: I,
    config: EvaluateConfig,
}

impl<S, I> EvaluateService<S, I>
where
    S: EvidenceStore,
    I: IncidentRecorder,
{
    pub fn new(
        pack: LoadedPolicyPack,
        model: ModelRecord,
        evidence: S,
        incidents: I,
        config: EvaluateConfig,
    ) -> Result<Self, EvaluateError> {
        let input_validator = compile_input_validator(&model.input_schema)?;
        Ok(Self {
            pack,
            model,
            input_validator,
            evidence,
            incidents,
            config,
        })
    }

    #[must_use]
    pub fn evidence_store(&self) -> &S {
        &self.evidence
    }

    #[must_use]
    pub fn incidents(&self) -> &I {
        &self.incidents
    }

    #[must_use]
    pub fn model(&self) -> &ModelRecord {
        &self.model
    }

    pub fn evaluate(
        &mut self,
        path: EvaluatePath,
        request: &EvaluateRequest,
        server_now: DateTime<Utc>,
    ) -> Result<EvaluateResult, EvaluateError> {
        let started = Instant::now();

        validate_model_binding(&self.model, request)?;
        self.assert_pack_effective(request.decision_time)?;
        validate_input(&self.input_validator, &request.input)?;
        request
            .check_clock_skew(server_now, self.config.clock_skew_max_seconds)
            .map_err(EvaluateError::from_domain)?;
        request
            .validate_consent()
            .map_err(EvaluateError::from_domain)?;

        let evaluation = PolicyEngine::evaluate(&self.pack, request)?;
        let returned_decision = map_returned_decision_for_path(
            evaluation.policy_decision,
            self.model.governance_mode,
            path,
            true,
        );
        let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);

        let append = AppendDecisionEvent {
            pack_id: self.model.pack_id.clone(),
            pack_version: self.pack.pack.version.clone(),
            sector: self.model.sector.clone(),
            model_id: request.model_id.clone(),
            model_version: request.model_version.clone(),
            model_origin: self.model.origin,
            governance_mode: self.model.governance_mode,
            policy_decision: evaluation.policy_decision,
            returned_decision,
            reason_codes: evaluation.reason_codes.clone(),
            policy_hits: evaluation.policy_hits.clone(),
            pii_tokens: vec![],
            input_digest: canonical_input_digest(&request.input),
            latency_ms,
            decision_time: request.decision_time,
            evaluated_at: server_now,
            service_identity_id: self.config.service_identity_id.clone(),
            correlation_id: request.correlation_id.clone(),
            idempotency_key: request.idempotency_key.clone(),
        };

        match self.evidence.append(append) {
            Ok(event) => Ok(EvaluateResult {
                response: EvaluateResponse {
                    policy_decision: evaluation.policy_decision,
                    returned_decision,
                    evidence_id: Some(event.evidence_id),
                    reason_codes: evaluation.reason_codes,
                    policy_hits: evaluation.policy_hits,
                    latency_ms,
                },
                incident: None,
            }),
            Err(err) => Ok(self.record_evidence_failure(
                path,
                request,
                evaluation.policy_decision,
                evaluation.reason_codes,
                evaluation.policy_hits,
                latency_ms,
                &err,
            )),
        }
    }

    fn assert_pack_effective(&self, decision_time: DateTime<Utc>) -> Result<(), EvaluateError> {
        if decision_time < self.pack.pack.effective_from {
            return Err(EvaluateError::PackNotEffective);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn record_evidence_failure(
        &mut self,
        path: EvaluatePath,
        request: &EvaluateRequest,
        policy_decision: Decision,
        reason_codes: Vec<String>,
        policy_hits: Vec<String>,
        latency_ms: u64,
        err: &kavach_evidence::EvidenceError,
    ) -> EvaluateResult {
        use kavach_domain::GovernanceMode;

        let returned_decision = match (self.model.governance_mode, path) {
            (GovernanceMode::Enforce, _) => Decision::Block,
            (GovernanceMode::Shadow, EvaluatePath::Sync) => Decision::Pass,
            (GovernanceMode::Shadow, EvaluatePath::Batch) => policy_decision,
        };

        let incident = EvaluateIncident {
            correlation_id: request.correlation_id.clone(),
            model_id: request.model_id.clone(),
            reason: format!("evidence append failed: {err}"),
        };
        self.incidents.record(incident.clone());

        EvaluateResult {
            response: EvaluateResponse {
                policy_decision,
                returned_decision,
                evidence_id: None,
                reason_codes,
                policy_hits,
                latency_ms,
            },
            incident: Some(incident),
        }
    }
}

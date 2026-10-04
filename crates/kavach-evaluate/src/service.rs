use std::time::Instant;

use chrono::{DateTime, Utc};
use jsonschema::Validator;
use kavach_domain::{
    decision::map_returned_decision_for_path, golden::canonical_input_digest, Decision,
    EvaluatePath, EvaluateRequest, EvaluateResponse, ModelRecord,
};
use kavach_evidence::{AppendDecisionEvent, EvidenceError};
use kavach_policy::{LoadedPolicyPack, PolicyEngine, PolicyEvaluation};

use crate::error::EvaluateError;
use crate::ports::{EvaluateIncident, EvidenceStore, IncidentRecorder};
use crate::validation::{
    compile_input_validator, validate_input, validate_model_binding, validate_supplier_controls,
};

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

/// Reason code for a consent whose purpose differs from the request's.
pub const CONSENT_MISMATCH: &str = "CONSENT_MISMATCH";

/// Reason code for a CEL/runtime policy evaluation failure.
pub const POLICY_EVALUATION_ERROR: &str = "POLICY_EVALUATION_ERROR";

/// How the request's `decision_time` is validated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionTimeCheck {
    /// Within `clock_skew_max_seconds` of trusted server time (sync path).
    Skew,
    /// Within the job's declared window, inclusive (batch over historical data).
    Window {
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct EvaluateResult {
    pub response: EvaluateResponse,
    pub incident: Option<EvaluateIncident>,
    /// Set when an incident could not be persisted; callers must surface it
    /// (metric + log) so infra failures never become invisible.
    pub incident_write_error: Option<String>,
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

    pub fn reload_pack_and_model(
        &mut self,
        pack: LoadedPolicyPack,
        model: ModelRecord,
    ) -> Result<(), EvaluateError> {
        self.input_validator = compile_input_validator(&model.input_schema)?;
        self.pack = pack;
        self.model = model;
        Ok(())
    }

    /// Sync evaluate: `decision_time` must be within the configured skew of
    /// trusted server time.
    pub fn evaluate(
        &mut self,
        path: EvaluatePath,
        request: &EvaluateRequest,
        server_now: DateTime<Utc>,
    ) -> Result<EvaluateResult, EvaluateError> {
        self.evaluate_with_time_check(path, request, server_now, DecisionTimeCheck::Skew)
    }

    /// Evaluates with an explicit `decision_time` check (batch over historical
    /// data uses the job's declared window).
    pub fn evaluate_with_time_check(
        &mut self,
        path: EvaluatePath,
        request: &EvaluateRequest,
        server_now: DateTime<Utc>,
        time_check: DecisionTimeCheck,
    ) -> Result<EvaluateResult, EvaluateError> {
        let started = Instant::now();
        self.validate_request(request, server_now, time_check)?;

        // A CEL/runtime failure is a policy outcome, not a transport error:
        // BLOCK with a reason code, recorded as evidence, plus an incident.
        // The ADR-001 §5 matrix then maps it (enforce BLOCK, sync shadow PASS).
        let (mut evaluation, policy_error) =
            match PolicyEngine::evaluate_at(&self.pack, request, server_now) {
                Ok(evaluation) => (evaluation, None),
                Err(err) => (
                    PolicyEvaluation {
                        policy_decision: Decision::Block,
                        reason_codes: vec![POLICY_EVALUATION_ERROR.to_string()],
                        policy_hits: vec![],
                    },
                    Some(err),
                ),
            };
        // Consent is a decision step (ADR-001 §7 step 4, §9), not request
        // validation: a purpose mismatch is a recorded BLOCK with
        // CONSENT_MISMATCH, whatever rules the pack carries.
        if request.validate_consent().is_err() {
            evaluation.policy_decision = Decision::Block;
            if !evaluation
                .reason_codes
                .iter()
                .any(|c| c == CONSENT_MISMATCH)
            {
                evaluation.reason_codes.push(CONSENT_MISMATCH.to_string());
            }
        }
        let mut incidents = IncidentOutcome::default();
        if let Some(err) = &policy_error {
            self.record_incident(
                &mut incidents,
                request,
                format!("policy evaluation failed: {err}"),
            );
        }

        let returned_decision = map_returned_decision_for_path(
            evaluation.policy_decision,
            self.model.governance_mode,
            path,
            true,
        );
        let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let append = self.append_input(
            request,
            &evaluation,
            returned_decision,
            latency_ms,
            server_now,
        );

        let response = match self.evidence.append(append) {
            // Idempotent replays return the *stored* decisions (ADR-001 §11).
            Ok(event) => EvaluateResponse {
                policy_decision: event.policy_decision,
                returned_decision: event.returned_decision,
                evidence_id: Some(event.evidence_id),
                reason_codes: event.reason_codes,
                policy_hits: event.policy_hits,
                latency_ms,
            },
            Err(EvidenceError::IdempotencyConflict { reason, .. }) => {
                return Err(EvaluateError::IdempotencyConflict(reason));
            }
            Err(err) => {
                let returned = self.evidence_failure_decision(path, evaluation.policy_decision);
                self.record_incident(
                    &mut incidents,
                    request,
                    format!("evidence append failed: {err}"),
                );
                EvaluateResponse {
                    policy_decision: evaluation.policy_decision,
                    returned_decision: returned,
                    evidence_id: None,
                    reason_codes: evaluation.reason_codes,
                    policy_hits: evaluation.policy_hits,
                    latency_ms,
                }
            }
        };
        Ok(EvaluateResult {
            response,
            incident: incidents.incident,
            incident_write_error: incidents.write_error,
        })
    }

    fn validate_request(
        &self,
        request: &EvaluateRequest,
        server_now: DateTime<Utc>,
        time_check: DecisionTimeCheck,
    ) -> Result<(), EvaluateError> {
        validate_model_binding(&self.model, request)?;
        validate_supplier_controls(&self.model)?;
        // Pack selection uses trusted server time, never the client-supplied
        // `decision_time` (ADR-003 §8).
        self.assert_pack_effective(server_now)?;
        validate_input(&self.input_validator, &request.input)?;
        match time_check {
            DecisionTimeCheck::Skew => request
                .check_clock_skew(server_now, self.config.clock_skew_max_seconds)
                .map_err(EvaluateError::from_domain)?,
            DecisionTimeCheck::Window { from, to } => {
                if request.decision_time < from || request.decision_time > to {
                    return Err(EvaluateError::validation(format!(
                        "decision_time {} outside the batch window {from}..={to}",
                        request.decision_time
                    )));
                }
            }
        }
        Ok(())
    }

    fn append_input(
        &self,
        request: &EvaluateRequest,
        evaluation: &PolicyEvaluation,
        returned_decision: Decision,
        latency_ms: u64,
        server_now: DateTime<Utc>,
    ) -> AppendDecisionEvent {
        AppendDecisionEvent {
            // The pack that actually produced the decision, not the model's
            // declared binding.
            pack_id: self.pack.pack.id.clone(),
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
        }
    }

    fn assert_pack_effective(&self, server_now: DateTime<Utc>) -> Result<(), EvaluateError> {
        if server_now < self.pack.pack.effective_from {
            return Err(EvaluateError::PackNotEffective);
        }
        Ok(())
    }

    /// ADR-001 §5: returned decision when evidence cannot be written.
    fn evidence_failure_decision(&self, path: EvaluatePath, policy_decision: Decision) -> Decision {
        use kavach_domain::GovernanceMode;
        match (self.model.governance_mode, path) {
            (GovernanceMode::Enforce, _) => Decision::Block,
            (GovernanceMode::Shadow, EvaluatePath::Sync) => Decision::Pass,
            (GovernanceMode::Shadow, EvaluatePath::Batch) => policy_decision,
        }
    }

    /// Records an incident; a failed write is kept for the caller to surface.
    fn record_incident(
        &mut self,
        out: &mut IncidentOutcome,
        request: &EvaluateRequest,
        reason: String,
    ) {
        let incident = EvaluateIncident {
            correlation_id: request.correlation_id.clone(),
            model_id: request.model_id.clone(),
            reason,
        };
        if let Err(err) = self.incidents.record(incident.clone()) {
            out.write_error = Some(err.0);
        }
        out.incident = Some(incident);
    }
}

#[derive(Default)]
struct IncidentOutcome {
    incident: Option<EvaluateIncident>,
    write_error: Option<String>,
}

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use kavach_domain::{Decision, DecisionEvent, GovernanceMode, ModelOrigin, SCHEMA_VERSION};
use uuid::Uuid;

use crate::canonical::GENESIS_HASH;
use crate::chain::compute_event_hash;
use crate::error::EvidenceError;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdempotencyKey {
    pub model_id: String,
    pub correlation_id: String,
}

/// Input to append a new evidence row (no hash fields).
#[derive(Debug, Clone)]
pub struct AppendDecisionEvent {
    pub pack_id: String,
    pub pack_version: String,
    pub sector: String,
    pub model_id: String,
    pub model_version: String,
    pub model_origin: ModelOrigin,
    pub governance_mode: GovernanceMode,
    pub policy_decision: Decision,
    pub returned_decision: Decision,
    pub reason_codes: Vec<String>,
    pub policy_hits: Vec<String>,
    pub pii_tokens: Vec<String>,
    pub input_digest: String,
    pub latency_ms: u64,
    pub decision_time: DateTime<Utc>,
    pub evaluated_at: DateTime<Utc>,
    pub service_identity_id: String,
    pub correlation_id: String,
    pub idempotency_key: Option<String>,
}

/// In-memory append-only chain for Milestone A (Postgres adapter follows in A.4).
#[derive(Debug, Default)]
pub struct MemoryChain {
    events: Vec<DecisionEvent>,
    idempotency_index: HashMap<IdempotencyKey, String>,
}

impl MemoryChain {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn events(&self) -> &[DecisionEvent] {
        &self.events
    }

    #[must_use]
    pub fn head_hash(&self) -> String {
        self.events
            .last()
            .map_or_else(|| GENESIS_HASH.to_string(), |e| e.hash.clone())
    }

    pub fn get_by_idempotency(
        &self,
        model_id: &str,
        correlation_id: &str,
    ) -> Option<&DecisionEvent> {
        let key = IdempotencyKey {
            model_id: model_id.into(),
            correlation_id: correlation_id.into(),
        };
        let evidence_id = self.idempotency_index.get(&key)?;
        self.events
            .iter()
            .find(|event| event.evidence_id == *evidence_id)
    }

    pub fn append(&mut self, input: AppendDecisionEvent) -> Result<DecisionEvent, EvidenceError> {
        let idempotency = IdempotencyKey {
            model_id: input.model_id.clone(),
            correlation_id: input.correlation_id.clone(),
        };

        if let Some(existing) = self.idempotency_index.get(&idempotency) {
            if let Some(event) = self.events.iter().find(|e| e.evidence_id == *existing) {
                return Ok(event.clone());
            }
        }

        let prev_hash = self.head_hash();
        let event_id = Uuid::new_v4().to_string();
        let evidence_id = Uuid::new_v4().to_string();

        let mut event = DecisionEvent {
            schema_version: SCHEMA_VERSION.to_string(),
            event_id,
            evidence_id: evidence_id.clone(),
            prev_hash,
            hash: String::new(),
            pack_id: input.pack_id,
            pack_version: input.pack_version,
            sector: input.sector,
            model_id: input.model_id.clone(),
            model_version: input.model_version,
            model_origin: input.model_origin,
            governance_mode: input.governance_mode,
            policy_decision: input.policy_decision,
            returned_decision: input.returned_decision,
            reason_codes: input.reason_codes,
            policy_hits: input.policy_hits,
            pii_tokens: input.pii_tokens,
            input_digest: input.input_digest,
            latency_ms: input.latency_ms,
            decision_time: input.decision_time,
            evaluated_at: input.evaluated_at,
            service_identity_id: input.service_identity_id,
            correlation_id: input.correlation_id.clone(),
            idempotency_key: input.idempotency_key,
        };

        event.hash = compute_event_hash(&event.prev_hash, &event).map_err(EvidenceError::Json)?;
        verify_event_before_push(&event)?;

        self.idempotency_index.insert(idempotency, evidence_id);
        self.events.push(event.clone());
        Ok(event)
    }
}

fn verify_event_before_push(event: &DecisionEvent) -> Result<(), EvidenceError> {
    crate::chain::verify_event_hash(event)
}

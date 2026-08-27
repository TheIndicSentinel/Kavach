use kavach_domain::DecisionEvent;
use serde::Serialize;

/// Genesis previous hash — 64 zero hex digits (no prior event).
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Payload hashed for the chain — all fields except `hash`.
#[derive(Serialize)]
pub struct HashPayload<'a> {
    pub schema_version: &'a str,
    pub event_id: &'a str,
    pub evidence_id: &'a str,
    pub prev_hash: &'a str,
    pub pack_id: &'a str,
    pub pack_version: &'a str,
    pub sector: &'a str,
    pub model_id: &'a str,
    pub model_version: &'a str,
    pub model_origin: kavach_domain::ModelOrigin,
    pub governance_mode: kavach_domain::GovernanceMode,
    pub policy_decision: kavach_domain::Decision,
    pub returned_decision: kavach_domain::Decision,
    pub reason_codes: &'a [String],
    pub policy_hits: &'a [String],
    pub pii_tokens: &'a [String],
    pub input_digest: &'a str,
    pub latency_ms: u64,
    pub decision_time: chrono::DateTime<chrono::Utc>,
    pub evaluated_at: chrono::DateTime<chrono::Utc>,
    pub service_identity_id: &'a str,
    pub correlation_id: &'a str,
    pub idempotency_key: Option<&'a str>,
}

impl<'a> HashPayload<'a> {
    pub fn from_event(event: &'a DecisionEvent) -> Self {
        Self {
            schema_version: &event.schema_version,
            event_id: &event.event_id,
            evidence_id: &event.evidence_id,
            prev_hash: &event.prev_hash,
            pack_id: &event.pack_id,
            pack_version: &event.pack_version,
            sector: &event.sector,
            model_id: &event.model_id,
            model_version: &event.model_version,
            model_origin: event.model_origin,
            governance_mode: event.governance_mode,
            policy_decision: event.policy_decision,
            returned_decision: event.returned_decision,
            reason_codes: &event.reason_codes,
            policy_hits: &event.policy_hits,
            pii_tokens: &event.pii_tokens,
            input_digest: &event.input_digest,
            latency_ms: event.latency_ms,
            decision_time: event.decision_time,
            evaluated_at: event.evaluated_at,
            service_identity_id: &event.service_identity_id,
            correlation_id: &event.correlation_id,
            idempotency_key: event.idempotency_key.as_deref(),
        }
    }
}

pub fn canonical_payload_bytes(event: &DecisionEvent) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&HashPayload::from_event(event))
}

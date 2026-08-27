use kavach_domain::DecisionEvent;

/// Canonical redacted `input_digest` for tombstoned evidence rows.
pub const TOMBSTONE_INPUT_DIGEST: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Redacted correlation id — hash chain fields are preserved.
pub const TOMBSTONE_CORRELATION_ID: &str = "ERASED";

/// Redacted service identity for tombstoned export views.
pub const TOMBSTONE_SERVICE_IDENTITY: &str = "ERASED";

/// Apply a read/export view that redacts identifiable metadata while keeping chain fields.
#[must_use]
pub fn redact_tombstoned_event(event: &DecisionEvent) -> DecisionEvent {
    DecisionEvent {
        reason_codes: Vec::new(),
        policy_hits: Vec::new(),
        pii_tokens: Vec::new(),
        input_digest: TOMBSTONE_INPUT_DIGEST.to_string(),
        correlation_id: TOMBSTONE_CORRELATION_ID.to_string(),
        idempotency_key: None,
        service_identity_id: TOMBSTONE_SERVICE_IDENTITY.to_string(),
        schema_version: event.schema_version.clone(),
        event_id: event.event_id.clone(),
        evidence_id: event.evidence_id.clone(),
        prev_hash: event.prev_hash.clone(),
        hash: event.hash.clone(),
        pack_id: event.pack_id.clone(),
        pack_version: event.pack_version.clone(),
        sector: event.sector.clone(),
        model_id: event.model_id.clone(),
        model_version: event.model_version.clone(),
        model_origin: event.model_origin,
        governance_mode: event.governance_mode,
        policy_decision: event.policy_decision,
        returned_decision: event.returned_decision,
        latency_ms: event.latency_ms,
        decision_time: event.decision_time,
        evaluated_at: event.evaluated_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use kavach_domain::{Decision, GovernanceMode, ModelOrigin};

    #[test]
    fn redact_preserves_hash_chain_fields() {
        let event = DecisionEvent {
            schema_version: "1.0.0".into(),
            event_id: "evt-1".into(),
            evidence_id: "ev-1".into(),
            prev_hash: "a".repeat(64),
            hash: "b".repeat(64),
            pack_id: "finance-v0".into(),
            pack_version: "0.1.0".into(),
            sector: "finance".into(),
            model_id: "credit-underwriting-v1".into(),
            model_version: "1.0.0".into(),
            model_origin: ModelOrigin::InHouse,
            governance_mode: GovernanceMode::Enforce,
            policy_decision: Decision::Pass,
            returned_decision: Decision::Pass,
            reason_codes: vec!["CONSENT_OK".into()],
            policy_hits: vec!["rule-1".into()],
            pii_tokens: vec!["tok-1".into()],
            input_digest: "c".repeat(64),
            latency_ms: 5,
            decision_time: Utc::now(),
            evaluated_at: Utc::now(),
            service_identity_id: "svc-1".into(),
            correlation_id: "corr-1".into(),
            idempotency_key: Some("idem-1".into()),
        };

        let redacted = redact_tombstoned_event(&event);
        assert_eq!(redacted.evidence_id, event.evidence_id);
        assert_eq!(redacted.hash, event.hash);
        assert_eq!(redacted.prev_hash, event.prev_hash);
        assert_eq!(redacted.correlation_id, TOMBSTONE_CORRELATION_ID);
        assert_eq!(redacted.input_digest, TOMBSTONE_INPUT_DIGEST);
        assert!(redacted.reason_codes.is_empty());
        assert!(redacted.pii_tokens.is_empty());
        assert!(redacted.idempotency_key.is_none());
    }
}

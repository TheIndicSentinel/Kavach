use kavach_domain::DecisionEvent;
use sha2::{Digest, Sha256};

use crate::canonical::canonical_payload_bytes;
use crate::error::EvidenceError;

/// `hash = SHA256(prev_hash || canonical_payload)` per ADR-001 evidence design.
pub fn compute_event_hash(
    prev_hash: &str,
    event: &DecisionEvent,
) -> Result<String, serde_json::Error> {
    let payload = canonical_payload_bytes(event)?;
    Ok(hash_bytes(prev_hash.as_bytes(), &payload))
}

pub fn verify_event_hash(event: &DecisionEvent) -> Result<(), EvidenceError> {
    validate_hash_hex(&event.prev_hash)?;
    validate_hash_hex(&event.hash)?;

    let computed = compute_event_hash(&event.prev_hash, event).map_err(EvidenceError::Json)?;

    if computed != event.hash {
        return Err(EvidenceError::HashMismatch {
            event_id: event.event_id.clone(),
            stored: event.hash.clone(),
            computed,
        });
    }
    Ok(())
}

fn hash_bytes(prev_hash: &[u8], payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prev_hash);
    hasher.update(payload);
    format!("{:x}", hasher.finalize())
}

fn validate_hash_hex(value: &str) -> Result<(), EvidenceError> {
    if value.len() != 64 || !value.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(EvidenceError::InvalidHash {
            hash: value.to_string(),
            reason: "expected 64 lowercase hex characters".into(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use kavach_domain::{Decision, DecisionEvent, GovernanceMode, ModelOrigin, SCHEMA_VERSION};

    use crate::canonical::GENESIS_HASH;

    fn sample_event(prev_hash: &str) -> DecisionEvent {
        DecisionEvent {
            schema_version: SCHEMA_VERSION.to_string(),
            event_id: "11111111-1111-1111-1111-111111111111".into(),
            evidence_id: "22222222-2222-2222-2222-222222222222".into(),
            prev_hash: prev_hash.into(),
            hash: String::new(),
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
            policy_hits: vec!["finance-consent-001".into()],
            pii_tokens: vec![],
            input_digest: "a".repeat(64),
            latency_ms: 5,
            decision_time: Utc::now(),
            evaluated_at: Utc::now(),
            service_identity_id: "svc-test".into(),
            correlation_id: "corr-1".into(),
            idempotency_key: None,
        }
    }

    #[test]
    fn hash_is_deterministic_for_same_event() {
        let mut event = sample_event(GENESIS_HASH);
        let hash1 = compute_event_hash(GENESIS_HASH, &event).unwrap();
        let hash2 = compute_event_hash(GENESIS_HASH, &event).unwrap();
        assert_eq!(hash1, hash2);
        event.hash = hash1;
        verify_event_hash(&event).unwrap();
    }

    #[test]
    fn tampered_hash_fails_verification() {
        let mut event = sample_event(GENESIS_HASH);
        event.hash = "f".repeat(64);
        assert!(verify_event_hash(&event).is_err());
    }
}

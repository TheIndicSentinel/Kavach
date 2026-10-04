use kavach_domain::DecisionEvent;

use crate::canonical::GENESIS_HASH;
use crate::chain::verify_event_hash;
use crate::error::EvidenceError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    pub events_checked: usize,
    pub head_hash: String,
}

pub fn verify_chain(events: &[DecisionEvent]) -> Result<VerifyReport, EvidenceError> {
    if events.is_empty() {
        return Err(EvidenceError::EmptyChain);
    }

    let mut expected_prev = GENESIS_HASH.to_string();

    for event in events {
        if event.prev_hash != expected_prev {
            return Err(EvidenceError::ChainBreak {
                event_id: event.event_id.clone(),
                expected: expected_prev,
                actual: event.prev_hash.clone(),
            });
        }
        verify_event_hash(event)?;
        expected_prev.clone_from(&event.hash);
    }

    Ok(VerifyReport {
        events_checked: events.len(),
        head_hash: expected_prev,
    })
}

pub fn verify_export_file(path: &std::path::Path) -> Result<VerifyReport, EvidenceError> {
    let content = std::fs::read_to_string(path)?;
    let events = parse_export(&content)?;
    verify_chain(&events)
}

pub fn parse_export(content: &str) -> Result<Vec<DecisionEvent>, EvidenceError> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Err(EvidenceError::EmptyChain);
    }

    if trimmed.starts_with('[') {
        return Ok(serde_json::from_str(trimmed)?);
    }

    let mut events = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        events.push(serde_json::from_str(line)?);
    }

    if events.is_empty() {
        return Err(EvidenceError::EmptyChain);
    }
    Ok(events)
}

/// A chain of two records: one written before evidence timestamps were
/// kept at storage precision (its hash covers nanoseconds, under the same
/// rule) and one written after. For compatibility tests.
#[doc(hidden)]
#[must_use]
pub fn mixed_chain() -> Vec<DecisionEvent> {
    use crate::{compute_event_hash, AppendDecisionEvent, MemoryChain};
    use kavach_domain::{Decision, GovernanceMode, ModelOrigin};
    let input = |correlation_id: &str| AppendDecisionEvent {
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
        policy_hits: vec![],
        pii_tokens: vec![],
        input_digest: "c".repeat(64),
        latency_ms: 2,
        decision_time: chrono::DateTime::from_timestamp(1_790_000_000, 123_456_789)
            .unwrap_or_default(),
        evaluated_at: chrono::DateTime::from_timestamp(1_790_000_001, 123_456_789)
            .unwrap_or_default(),
        service_identity_id: "svc".into(),
        correlation_id: correlation_id.into(),
        idempotency_key: None,
    };
    // The old record: what an append produced before, nanoseconds kept.
    let mut old = MemoryChain::new().append(input("old-1")).expect("append");
    old.decision_time =
        chrono::DateTime::from_timestamp(1_790_000_000, 123_456_789).unwrap_or_default();
    old.evaluated_at =
        chrono::DateTime::from_timestamp(1_790_000_001, 123_456_789).unwrap_or_default();
    old.hash = compute_event_hash(&old.prev_hash, &old).expect("hash");
    // The new record follows it.
    let mut new = MemoryChain::new().append(input("new-1")).expect("append");
    new.prev_hash.clone_from(&old.hash);
    new.hash = compute_event_hash(&new.prev_hash, &new).expect("hash");
    vec![old, new]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{AppendDecisionEvent, MemoryChain};
    use chrono::Utc;
    use kavach_domain::{Decision, GovernanceMode, ModelOrigin};
    use std::io::Write;

    #[test]
    fn verify_ndjson_export() {
        let mut chain = MemoryChain::new();
        chain.append(sample_append("corr-a")).expect("append a");
        chain.append(sample_append("corr-b")).expect("append b");

        let path = std::env::temp_dir().join("kavach-evidence-test.ndjson");
        let mut file = std::fs::File::create(&path).unwrap();
        for event in chain.events() {
            writeln!(file, "{}", serde_json::to_string(event).unwrap()).unwrap();
        }
        drop(file);

        let report = verify_export_file(&path).unwrap();
        assert_eq!(report.events_checked, 2);
        let _ = std::fs::remove_file(path);
    }

    /// Stores keep microseconds (Postgres `TIMESTAMPTZ`): an event is
    /// hashed over what is stored, so a copy at that precision verifies.
    #[test]
    fn events_are_hashed_at_storage_precision() {
        use chrono::{TimeZone, Timelike};
        let nanos = Utc.with_ymd_and_hms(2026, 10, 4, 10, 0, 0).unwrap()
            + chrono::Duration::nanoseconds(123_456_789);
        let mut chain = MemoryChain::new();
        let mut input = sample_append("precision-1");
        input.decision_time = nanos;
        input.evaluated_at = nanos;
        let event = chain.append(input).unwrap();
        assert_eq!(event.evaluated_at.nanosecond(), 123_456_000);
        assert_eq!(event.decision_time.nanosecond(), 123_456_000);
        // As a store would give it back.
        let mut stored = event.clone();
        stored.evaluated_at = crate::at_storage_precision(stored.evaluated_at);
        stored.decision_time = crate::at_storage_precision(stored.decision_time);
        crate::verify_event_hash(&stored).expect("verifies at storage precision");
    }

    /// A record from before the change (hashed over nanoseconds, the same
    /// rule) followed by one from after it (microseconds): the chain
    /// verifies as it is, nothing is re-fingerprinted.
    #[test]
    fn a_chain_mixing_old_and_new_records_verifies() {
        use chrono::Timelike;
        let events = mixed_chain();
        assert_eq!(
            events[0].evaluated_at.nanosecond() % 1_000,
            789,
            "old: nanoseconds"
        );
        assert_eq!(
            events[1].evaluated_at.nanosecond() % 1_000,
            0,
            "new: microseconds"
        );
        assert_eq!(verify_chain(&events).unwrap().events_checked, 2);

        let path = std::env::temp_dir().join(format!("kavach-mixed-{}.jsonl", std::process::id()));
        let lines: Vec<_> = events
            .iter()
            .map(|e| serde_json::to_string(e).unwrap())
            .collect();
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();
        assert_eq!(verify_export_file(&path).unwrap().events_checked, 2);
        let _ = std::fs::remove_file(path);
    }

    fn sample_append(correlation_id: &str) -> AppendDecisionEvent {
        AppendDecisionEvent {
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
            latency_ms: 3,
            decision_time: Utc::now(),
            evaluated_at: Utc::now(),
            service_identity_id: "svc-test".into(),
            correlation_id: correlation_id.into(),
            idempotency_key: None,
        }
    }
}

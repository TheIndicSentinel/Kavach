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

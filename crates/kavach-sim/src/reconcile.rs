//! Three records of one run, reconciled: the simulator's ledger (what was
//! asked and answered), Kavach's evidence bundle (what it recorded), and
//! the provider's inbox (what actually arrived). The inbox is the one
//! record Kavach does not write: it is the provider's own proof that
//! nothing was sent twice and nothing blocked was sent at all.
//!
//! Findings name borrower references and record ids, never destinations.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::ledger::Entry;
use crate::world::Delivery;

/// One record from the evidence bundle (`records.jsonl`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recorded {
    pub record_id: String,
    pub request_id: String,
    pub returned_decision: String,
    pub credential_id: Option<String>,
}

/// One message in the provider's inbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arrived {
    pub record_id: String,
    pub jti: String,
    pub destination: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Reconciliation {
    /// Ledger calls that Kavach recorded (first sends with a record id).
    pub ledger_records: usize,
    pub evidence_records: usize,
    pub outcomes: usize,
    pub inbox_messages: usize,
    pub findings: Vec<String>,
}

/// What the inbox shows for one recorded call: arrived exactly once if it
/// was allowed and deliverable, not at all otherwise, at the borrower's
/// own destination, with the credential the evidence names.
fn arrivals(
    call: &Entry,
    record: &Recorded,
    messages: &[&Arrived],
    destinations: &BTreeMap<String, String>,
    deliveries: &BTreeMap<String, Delivery>,
) -> Vec<String> {
    let mut findings = Vec::new();
    let id = record.record_id.as_str();
    let should_arrive = call.allowed()
        && matches!(
            deliveries.get(&call.borrower),
            Some(Delivery::Delivers | Delivery::Loses) | None
        );
    match (should_arrive, messages.len()) {
        (true, 1) | (false, 0) => {}
        (true, 0) => findings.push(format!(
            "#{} {}: allowed and deliverable, but nothing arrived",
            call.seq, call.borrower
        )),
        (false, n) => findings.push(format!(
            "#{} {}: {n} message(s) arrived for a call that {}",
            call.seq,
            call.borrower,
            if call.allowed() {
                "the provider refused or failed"
            } else {
                "was blocked"
            }
        )),
        (true, n) => findings.push(format!(
            "#{} {}: SENT {n} TIMES (record {id})",
            call.seq, call.borrower
        )),
    }
    for message in messages {
        if destinations.get(&call.borrower) != Some(&message.destination) {
            findings.push(format!(
                "#{} {}: delivered to a destination that is not this borrower's",
                call.seq, call.borrower
            ));
        }
        if record.credential_id.as_deref() != Some(message.jti.as_str()) {
            findings.push(format!(
                "#{} {}: delivered with a credential the evidence does not name",
                call.seq, call.borrower
            ));
        }
    }
    findings
}

/// Reconciles a run. `destinations` and `deliveries` describe the world;
/// `outcomes` are the bundle's outcomes by credential id.
pub fn reconcile(
    ledger: &[Entry],
    recorded: &[Recorded],
    outcomes: &BTreeMap<String, String>,
    inbox: &[Arrived],
    destinations: &BTreeMap<String, String>,
    deliveries: &BTreeMap<String, Delivery>,
) -> Reconciliation {
    let mut findings = Vec::new();
    let by_record: BTreeMap<&str, &Recorded> =
        recorded.iter().map(|r| (r.record_id.as_str(), r)).collect();
    let mut arrived: BTreeMap<&str, Vec<&Arrived>> = BTreeMap::new();
    for message in inbox {
        arrived
            .entry(message.record_id.as_str())
            .or_default()
            .push(message);
    }

    let firsts: Vec<&Entry> = ledger
        .iter()
        .filter(|e| e.retry_of.is_none() && e.record_id.is_some())
        .collect();
    let mut seen = BTreeSet::new();
    for call in &firsts {
        let id = call.record_id.as_deref().unwrap_or_default();
        seen.insert(id);
        let Some(record) = by_record.get(id) else {
            findings.push(format!(
                "#{} {}: record {id} is not in the evidence",
                call.seq, call.borrower
            ));
            continue;
        };
        if record.request_id != call.request_id
            || Some(record.returned_decision.as_str()) != call.decision.as_deref()
        {
            findings.push(format!(
                "#{} {}: the evidence records {} for {}, the reply said {} for {}",
                call.seq,
                call.borrower,
                record.returned_decision,
                record.request_id,
                call.decision.as_deref().unwrap_or("none"),
                call.request_id
            ));
        }
        let outcome = record.credential_id.as_ref().and_then(|c| outcomes.get(c));
        if outcome.map(String::as_str) != call.outcome.as_deref() {
            findings.push(format!(
                "#{} {}: outcome {} in the evidence, {} in the reply",
                call.seq,
                call.borrower,
                outcome.map_or("none", String::as_str),
                call.outcome.as_deref().unwrap_or("none")
            ));
        }
        let messages = arrived.get(id).map_or(&[][..], Vec::as_slice);
        findings.extend(arrivals(call, record, messages, destinations, deliveries));
    }
    for record in recorded {
        if !seen.contains(record.record_id.as_str()) {
            findings.push(format!(
                "record {} is in the evidence, but no call made it",
                record.record_id
            ));
        }
    }
    for message in inbox {
        if !by_record.contains_key(message.record_id.as_str()) {
            findings.push(format!(
                "a message arrived for record {}, which the evidence does not hold",
                message.record_id
            ));
        }
    }
    Reconciliation {
        ledger_records: firsts.len(),
        evidence_records: recorded.len(),
        outcomes: outcomes.len(),
        inbox_messages: inbox.len(),
        findings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calendar::slot;

    fn call(seq: u32, borrower: &str, decision: &str, outcome: Option<&str>) -> Entry {
        Entry {
            seq,
            day: 1,
            at: slot(1, 600),
            agent: "a".into(),
            borrower: borrower.into(),
            tool: "send_reminder".into(),
            params: serde_json::json!({}),
            channel: "whatsapp".into(),
            mandate_for: Some(borrower.into()),
            request_id: format!("sim-1-{seq}"),
            retry_of: None,
            attack: None,
            status: 200,
            decision: Some(decision.into()),
            reasons: vec![],
            record_id: Some(format!("adr:default:0:{seq}")),
            outcome: outcome.map(str::to_string),
            replayed: false,
            leak: None,
        }
    }

    fn recorded(e: &Entry) -> Recorded {
        Recorded {
            record_id: e.record_id.clone().unwrap(),
            request_id: e.request_id.clone(),
            returned_decision: e.decision.clone().unwrap(),
            credential_id: e.allowed().then(|| format!("cred-{}", e.seq)),
        }
    }

    struct Run {
        ledger: Vec<Entry>,
        recorded: Vec<Recorded>,
        outcomes: BTreeMap<String, String>,
        inbox: Vec<Arrived>,
        destinations: BTreeMap<String, String>,
        deliveries: BTreeMap<String, Delivery>,
    }

    impl Run {
        /// Two allowed and delivered, one blocked: consistent.
        fn consistent() -> Self {
            let ledger = vec![
                call(1, "ref:a", "PASS", Some("delivered")),
                call(2, "ref:b", "PASS", Some("delivered")),
                call(3, "ref:a", "BLOCK", None),
            ];
            let recorded = ledger.iter().map(recorded).collect();
            let outcomes = BTreeMap::from([
                ("cred-1".to_string(), "delivered".to_string()),
                ("cred-2".to_string(), "delivered".to_string()),
            ]);
            let inbox = [(1, "+910000100001"), (2, "+910000100002")]
                .iter()
                .map(|(seq, dest)| Arrived {
                    record_id: format!("adr:default:0:{seq}"),
                    jti: format!("cred-{seq}"),
                    destination: (*dest).into(),
                })
                .collect();
            Self {
                ledger,
                recorded,
                outcomes,
                inbox,
                destinations: BTreeMap::from([
                    ("ref:a".to_string(), "+910000100001".to_string()),
                    ("ref:b".to_string(), "+910000100002".to_string()),
                ]),
                deliveries: BTreeMap::new(),
            }
        }

        fn findings(&self) -> Vec<String> {
            reconcile(
                &self.ledger,
                &self.recorded,
                &self.outcomes,
                &self.inbox,
                &self.destinations,
                &self.deliveries,
            )
            .findings
        }
    }

    #[test]
    fn a_consistent_run_has_no_findings() {
        assert_eq!(Run::consistent().findings(), Vec::<String>::new());
    }

    #[test]
    fn a_second_send_is_caught_by_the_inbox() {
        let mut run = Run::consistent();
        let again = run.inbox[0].clone();
        run.inbox.push(again);
        let findings = run.findings();
        assert!(
            findings.iter().any(|f| f.contains("SENT 2 TIMES")),
            "{findings:?}"
        );
    }

    #[test]
    fn a_blocked_call_that_arrived_is_caught() {
        let mut run = Run::consistent();
        run.inbox.push(Arrived {
            record_id: "adr:default:0:3".into(),
            jti: "cred-3".into(),
            destination: "+910000100001".into(),
        });
        assert!(run.findings().iter().any(|f| f.contains("was blocked")));
    }

    #[test]
    fn a_wrong_destination_or_a_missing_record_is_caught() {
        let mut run = Run::consistent();
        run.inbox[1].destination = "+910000100001".into();
        let findings = run.findings();
        assert!(
            findings.iter().any(|f| f.contains("not this borrower's")),
            "{findings:?}"
        );
        assert!(
            !findings.iter().any(|f| f.contains("+91")),
            "no destinations in findings"
        );

        let mut run = Run::consistent();
        run.recorded.remove(1);
        assert!(run
            .findings()
            .iter()
            .any(|f| f.contains("not in the evidence")));

        let mut run = Run::consistent();
        run.outcomes.insert("cred-2".into(), "unknown".into());
        assert!(run
            .findings()
            .iter()
            .any(|f| f.contains("outcome unknown in the evidence")));
    }

    #[test]
    fn refused_and_failed_sends_must_not_arrive() {
        let mut run = Run::consistent();
        run.deliveries.insert("ref:b".into(), Delivery::Refuses);
        run.outcomes.insert("cred-2".into(), "refused".into());
        run.ledger[1].outcome = Some("refused".into());
        assert!(run
            .findings()
            .iter()
            .any(|f| f.contains("refused or failed")));
        run.inbox.remove(1);
        assert_eq!(run.findings(), Vec::<String>::new());
    }
}

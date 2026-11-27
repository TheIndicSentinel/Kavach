//! Three records of one run, reconciled: the simulator's ledger (what was
//! asked and answered), Kavach's evidence bundle (what it recorded), and
//! the provider's inbox (what actually arrived). The inbox is the one
//! record Kavach does not write: it is the provider's own proof that
//! nothing was sent twice and nothing blocked was sent at all.
//!
//! Payments and disputes (ADR-012) are reconciled too: what Kavach said it
//! revoked against the simulator's own record of the mandates, each event
//! against its one signed record in the evidence, and the inbox against
//! the revocations: nothing may arrive under a revoked mandate from the
//! event on.
//!
//! Findings name borrower references and record ids, never destinations.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use chrono::{DateTime, Utc};

use crate::ledger::{AgentEntry, Entry, SorEntry};
use crate::oracle::{Standing, Verb};
use crate::world::Delivery;

/// One record from the evidence bundle (`records.jsonl`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recorded {
    pub record_id: String,
    pub request_id: String,
    pub returned_decision: String,
    pub credential_id: Option<String>,
    /// When Kavach decided (the record's signed time).
    pub ts: Option<DateTime<Utc>>,
}

/// A `mandate_revocation` record from the evidence bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedRevocation {
    pub event_id: String,
    pub revoked: Vec<String>,
}

/// An `agent_state` record from the evidence bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedAgentChange {
    pub agent_id: String,
    pub change_no: i64,
    pub from_state: String,
    pub to_state: String,
    pub approved_by: Option<String>,
}

/// One message in the provider's inbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arrived {
    pub record_id: String,
    pub jti: String,
    pub destination: String,
    /// The mandate the message was sent under, as the provider saw it.
    pub mandate_id: String,
}

/// A resolution of an unknown outcome from the evidence bundle
/// (`resolutions.jsonl`, ADR-017).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedResolution {
    pub credential_id: String,
    pub state: String,
    pub source: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Reconciliation {
    /// Ledger calls that Kavach recorded (first sends with a record id).
    pub ledger_records: usize,
    pub evidence_records: usize,
    pub outcomes: usize,
    pub inbox_messages: usize,
    /// Payments and disputes the run sent, and their evidence records.
    pub revocation_events: usize,
    pub revocation_records: usize,
    /// Operators' changes of agents' states the run made, and their
    /// evidence records.
    pub agent_events: usize,
    pub agent_state_records: usize,
    /// Unknown outcomes the provider's own answer resolved.
    pub unknown_resolved: usize,
    pub findings: Vec<String>,
}

fn sorted(ids: &[String]) -> Vec<&str> {
    let mut ids: Vec<&str> = ids.iter().map(String::as_str).collect();
    ids.sort_unstable();
    ids
}

/// The run's payments and disputes against Kavach's replies, the evidence
/// and the inbox.
#[must_use]
pub fn reconcile_revocations(
    sent: &[SorEntry],
    recorded: &[RecordedRevocation],
    inbox: &[Arrived],
    decided: &[Recorded],
) -> Vec<String> {
    let mut findings = Vec::new();
    let records: BTreeMap<&str, &RecordedRevocation> =
        recorded.iter().map(|r| (r.event_id.as_str(), r)).collect();
    for event in sent {
        let who = format!(
            "{} {} for {}",
            event.event_type, event.event_id, event.borrower
        );
        if event.status != 200 {
            findings.push(format!("{who}: refused ({})", event.status));
            continue;
        }
        if sorted(&event.revoked) != sorted(&event.expected) {
            findings.push(format!(
                "{who}: revoked {} mandate(s), but the run held {} issued before it",
                event.revoked.len(),
                event.expected.len()
            ));
        }
        match records.get(event.event_id.as_str()) {
            None => findings.push(format!("{who}: no revocation record in the evidence")),
            Some(record) if sorted(&record.revoked) != sorted(&event.expected) => findings.push(
                format!("{who}: the evidence record names other mandates than were revoked"),
            ),
            Some(_) => {}
        }
    }
    let ours: BTreeSet<&str> = sent.iter().map(|e| e.event_id.as_str()).collect();
    for record in recorded {
        if !ours.contains(record.event_id.as_str()) {
            findings.push(format!(
                "a revocation record for event {}, which the run never sent",
                record.event_id
            ));
        }
    }
    // The inbox, against the revocations: a message under a revoked
    // mandate, decided at or after its event, must not exist.
    let when: BTreeMap<&str, Option<DateTime<Utc>>> = decided
        .iter()
        .map(|r| (r.record_id.as_str(), r.ts))
        .collect();
    for message in inbox {
        for event in sent
            .iter()
            .filter(|e| e.expected.contains(&message.mandate_id))
        {
            let at = when.get(message.record_id.as_str()).copied().flatten();
            if at.is_none_or(|at| at >= event.at) {
                findings.push(format!(
                    "record {}: delivered to {} under a mandate its {} at {} revoked",
                    message.record_id,
                    event.borrower,
                    event.event_type,
                    event.at.to_rfc3339()
                ));
            }
        }
    }
    findings
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

/// The run's changes of agents' states against Kavach's replies and the
/// evidence: the state each reply names against the simulator's own model,
/// the mandates a revoke took against the ones the run held, and the
/// signed records (one per change, in order, a loosening with an approver).
#[must_use]
pub fn reconcile_agent_events(
    sent: &[AgentEntry],
    recorded: &[RecordedAgentChange],
) -> Vec<String> {
    let mut findings = Vec::new();
    let mut standing: BTreeMap<&str, Standing> = BTreeMap::new();
    let mut expected: BTreeMap<&str, Vec<(&'static str, &'static str)>> = BTreeMap::new();
    for event in sent {
        let who = format!("{} {} on day {}", event.verb, event.agent, event.day);
        if event.status != 200 {
            findings.push(format!("{who}: refused ({})", event.status));
        } else if event.state.as_deref() != Some(event.expected_state.as_str()) {
            findings.push(format!(
                "{who}: the agent is {} after it, the run's own record says {}",
                event.state.as_deref().unwrap_or("not stated"),
                event.expected_state
            ));
        }
        if event.verb == "revoke" && sorted(&event.revoked) != sorted(&event.expected_revoked) {
            findings.push(format!(
                "{who}: revoked {} mandate(s), but the run held {} of the agent's",
                event.revoked.len(),
                event.expected_revoked.len()
            ));
        }
        let before = standing
            .get(event.agent.as_str())
            .copied()
            .unwrap_or_default();
        let verb = match event.verb.as_str() {
            "restrict" => Verb::Restrict,
            "quarantine" => Verb::Quarantine,
            "revoke" => Verb::Revoke,
            _ => Verb::Reinstate,
        };
        let after = before.after(verb);
        standing.insert(event.agent.as_str(), after);
        if after != before && event.status == 200 {
            expected
                .entry(event.agent.as_str())
                .or_default()
                .push((before.name(), after.name()));
        }
    }
    let mut by_agent: BTreeMap<&str, Vec<&RecordedAgentChange>> = BTreeMap::new();
    for record in recorded {
        by_agent
            .entry(record.agent_id.as_str())
            .or_default()
            .push(record);
    }
    for (agent, records) in &mut by_agent {
        records.sort_by_key(|r| r.change_no);
        let want = expected.get(agent).cloned().unwrap_or_default();
        let got: Vec<(&str, &str)> = records
            .iter()
            .map(|r| (r.from_state.as_str(), r.to_state.as_str()))
            .collect();
        if got != want {
            findings.push(format!(
                "{agent}: the evidence holds the changes {got:?}, the run made {want:?}"
            ));
        }
        for record in records.iter() {
            let loosens = ["restricted", "quarantined"].contains(&record.from_state.as_str())
                && record.to_state == "active";
            if loosens && record.approved_by.is_none() {
                findings.push(format!(
                    "{agent}: change {} loosened it with no approver in the evidence",
                    record.change_no
                ));
            }
        }
    }
    for (agent, want) in &expected {
        if !want.is_empty() && !by_agent.contains_key(agent) {
            findings.push(format!(
                "{agent}: {} change(s) made, none in the evidence",
                want.len()
            ));
        }
    }
    findings
}

/// What the provider's own behaviour says became of a send whose response
/// was not known: the world's ground truth, never Kavach's records.
fn truth(delivery: Delivery) -> Option<&'static str> {
    match delivery {
        // Delivered, and the response was lost.
        Delivery::Loses => Some("confirmed_delivered"),
        // A provider error: the mock stored it as not delivered.
        Delivery::Errs => Some("confirmed_not_delivered"),
        Delivery::Delivers | Delivery::Refuses => None,
    }
}

/// The resolutions of the run's unknown outcomes (ADR-017) against the
/// world's ground truth: a confirmed state must match the provider's own
/// behaviour (delivered for a lost response, not delivered for an error),
/// regardless of whether Kavach learned it from provider status, a human
/// attestation, or a two-person conflict closure. The oracle never takes the
/// expected state from Kavach's resolution. The reconciler may also say
/// `ambiguous`, which confirms nothing; and when the run waited for the
/// reconciler (`must_resolve`) every unknown outcome must have one. Returns
/// the findings and how many unknown outcomes have a correct resolution.
#[must_use]
pub fn reconcile_resolutions(
    ledger: &[Entry],
    recorded: &[Recorded],
    resolutions: &[RecordedResolution],
    deliveries: &BTreeMap<String, Delivery>,
    must_resolve: bool,
) -> (Vec<String>, usize) {
    let by_record: BTreeMap<&str, &Recorded> =
        recorded.iter().map(|r| (r.record_id.as_str(), r)).collect();
    let mut findings = Vec::new();
    let mut resolved = 0;
    let mut unknown_credentials = BTreeSet::new();
    for call in ledger
        .iter()
        .filter(|c| c.retry_of.is_none() && c.outcome.as_deref() == Some("unknown"))
    {
        let Some(credential) = call
            .record_id
            .as_deref()
            .and_then(|id| by_record.get(id))
            .and_then(|r| r.credential_id.as_deref())
        else {
            continue;
        };
        unknown_credentials.insert(credential);
        let Some(expected) = deliveries.get(&call.borrower).copied().and_then(truth) else {
            continue;
        };
        let rows: Vec<&RecordedResolution> = resolutions
            .iter()
            .filter(|r| r.credential_id == credential)
            .collect();
        let confirmed: Vec<&&RecordedResolution> = rows
            .iter()
            .filter(|r| r.state.starts_with("confirmed_"))
            .collect();
        for row in &confirmed {
            if row.state != expected
                || !matches!(
                    row.source.as_str(),
                    "provider_status" | "operator_attested" | "conflict_resolution"
                )
            {
                findings.push(format!(
                    "#{} {}: resolved as {} by {}; the provider's own behaviour says {expected}",
                    call.seq, call.borrower, row.state, row.source
                ));
            }
        }
        if confirmed.is_empty() {
            if must_resolve {
                findings.push(format!(
                    "#{} {}: the run waited for the reconciler, but this unknown outcome has no \
                     confirmed resolution (expected {expected})",
                    call.seq, call.borrower
                ));
            }
        } else if confirmed.iter().any(|r| {
            r.state == expected
                && matches!(
                    r.source.as_str(),
                    "provider_status" | "operator_attested" | "conflict_resolution"
                )
        }) {
            resolved += 1;
        }
    }
    for row in resolutions {
        if !unknown_credentials.contains(row.credential_id.as_str()) {
            findings.push(format!(
                "a resolution ({}) for a send the run did not see end unknown",
                row.state
            ));
        }
    }
    (findings, resolved)
}

/// Reconciles a run. `destinations` and `deliveries` describe the world;
/// `outcomes` are the bundle's outcomes by credential id.
#[allow(clippy::too_many_arguments)]
pub fn reconcile(
    ledger: &[Entry],
    recorded: &[Recorded],
    outcomes: &BTreeMap<String, String>,
    inbox: &[Arrived],
    destinations: &BTreeMap<String, String>,
    deliveries: &BTreeMap<String, Delivery>,
    sent: &[SorEntry],
    revocations: &[RecordedRevocation],
    agent_events: &[AgentEntry],
    agent_changes: &[RecordedAgentChange],
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
    findings.extend(reconcile_revocations(sent, revocations, inbox, recorded));
    findings.extend(reconcile_agent_events(agent_events, agent_changes));
    Reconciliation {
        ledger_records: firsts.len(),
        evidence_records: recorded.len(),
        outcomes: outcomes.len(),
        inbox_messages: inbox.len(),
        revocation_events: sent.len(),
        revocation_records: revocations.len(),
        agent_events: agent_events.len(),
        agent_state_records: agent_changes.len(),
        unknown_resolved: 0,
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
            mandate_issued_at: None,
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
            ts: Some(e.at),
        }
    }

    struct Run {
        ledger: Vec<Entry>,
        recorded: Vec<Recorded>,
        outcomes: BTreeMap<String, String>,
        inbox: Vec<Arrived>,
        destinations: BTreeMap<String, String>,
        deliveries: BTreeMap<String, Delivery>,
        sent: Vec<SorEntry>,
        revocations: Vec<RecordedRevocation>,
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
                    mandate_id: "m-other".into(),
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
                sent: Vec::new(),
                revocations: Vec::new(),
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
                &self.sent,
                &self.revocations,
                &[],
                &[],
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
            mandate_id: "m-other".into(),
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

    /// A payment for ref:a at 12:00 that revoked m-a, recorded once, and
    /// one message for ref:a decided before it.
    fn paid() -> (
        Vec<SorEntry>,
        Vec<RecordedRevocation>,
        Vec<Arrived>,
        Vec<Recorded>,
    ) {
        let event = SorEntry {
            day: 1,
            at: slot(1, 720),
            occurred: slot(1, 720),
            event_id: "sim-1-ev0-0".into(),
            event_type: "loan.paid".into(),
            borrower: "ref:a".into(),
            status: 200,
            revoked: vec!["m-a".into()],
            expected: vec!["m-a".into()],
        };
        let record = RecordedRevocation {
            event_id: "sim-1-ev0-0".into(),
            revoked: vec!["m-a".into()],
        };
        let before = Recorded {
            record_id: "adr:default:0:1".into(),
            request_id: "sim-1-1".into(),
            returned_decision: "PASS".into(),
            credential_id: Some("cred-1".into()),
            ts: Some(slot(1, 600)),
        };
        let message = Arrived {
            record_id: "adr:default:0:1".into(),
            jti: "cred-1".into(),
            destination: "+910000100001".into(),
            mandate_id: "m-a".into(),
        };
        (vec![event], vec![record], vec![message], vec![before])
    }

    #[test]
    fn a_payment_reconciles_with_its_record_and_the_inbox() {
        let (sent, recorded, inbox, decided) = paid();
        assert_eq!(
            reconcile_revocations(&sent, &recorded, &inbox, &decided),
            Vec::<String>::new()
        );
    }

    #[test]
    fn a_delivery_after_the_payment_is_caught_by_the_inbox() {
        let (sent, recorded, mut inbox, mut decided) = paid();
        decided.push(Recorded {
            record_id: "adr:default:0:2".into(),
            request_id: "sim-1-2".into(),
            returned_decision: "PASS".into(),
            credential_id: Some("cred-2".into()),
            ts: Some(slot(1, 1080)),
        });
        inbox.push(Arrived {
            record_id: "adr:default:0:2".into(),
            jti: "cred-2".into(),
            destination: "+910000100001".into(),
            mandate_id: "m-a".into(),
        });
        let findings = reconcile_revocations(&sent, &recorded, &inbox, &decided);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].contains("adr:default:0:2"), "{findings:?}");
        assert!(!findings[0].contains("+91"), "no destinations in findings");
    }

    #[test]
    fn missing_wrong_and_stray_revocation_records_are_caught() {
        let (sent, mut recorded, inbox, decided) = paid();
        let check = |recorded: &[RecordedRevocation], sent: &[SorEntry], expect: &str| {
            let findings = reconcile_revocations(sent, recorded, &inbox, &decided);
            assert!(
                findings.iter().any(|f| f.contains(expect)),
                "{expect}: {findings:?}"
            );
        };
        check(&[], &sent, "no revocation record");
        recorded[0].revoked = vec!["m-b".into()];
        check(&recorded, &sent, "other mandates");
        let stray = vec![RecordedRevocation {
            event_id: "never-sent".into(),
            revoked: vec![],
        }];
        check(&stray, &[], "never sent");
        let mut wrong = sent.clone();
        wrong[0].revoked = vec![];
        check(&paid().1, &wrong, "revoked 0 mandate(s)");
    }

    fn change(day: u32, verb: &str, status: u16, state: &str, expected: &str) -> AgentEntry {
        AgentEntry {
            day,
            at: slot(day, 720),
            agent: "sim-eager-1".into(),
            verb: verb.into(),
            status,
            state: Some(state.into()),
            expected_state: expected.into(),
            revoked: vec![],
            expected_revoked: vec![],
        }
    }

    fn resolution(call: &Entry, state: &str, source: &str) -> RecordedResolution {
        RecordedResolution {
            credential_id: format!("cred-{}", call.seq),
            state: state.into(),
            source: source.into(),
        }
    }

    /// The resolutions of unknown outcomes against the provider's own
    /// behaviour (ADR-017): each way they can be wrong is found.
    #[test]
    fn a_resolution_must_match_what_the_provider_did() {
        let lost = call(1, "ref:lost", "PASS", Some("unknown"));
        let erred = call(2, "ref:err", "PASS", Some("unknown"));
        let ledger = [lost.clone(), erred.clone()];
        let recorded: Vec<Recorded> = ledger.iter().map(recorded).collect();
        let deliveries = BTreeMap::from([
            ("ref:lost".to_string(), Delivery::Loses),
            ("ref:err".to_string(), Delivery::Errs),
        ]);
        let check = |resolutions: &[RecordedResolution], must: bool| {
            reconcile_resolutions(&ledger, &recorded, resolutions, &deliveries, must)
        };
        let right = [
            resolution(&lost, "confirmed_delivered", "provider_status"),
            resolution(&erred, "confirmed_not_delivered", "provider_status"),
        ];
        assert_eq!(check(&right, true), (vec![], 2));
        // The run did not wait: no resolution yet is fine, `ambiguous` confirms nothing.
        assert_eq!(check(&[], false), (vec![], 0));
        let ambiguous = [resolution(&lost, "ambiguous", "reconciler")];
        assert_eq!(check(&ambiguous, false).0, Vec::<String>::new());
        // It did wait, and one is missing.
        let (findings, resolved) = check(&right[..1], true);
        assert_eq!((findings.len(), resolved), (1, 1), "{findings:?}");
        // The opposite of what the provider did.
        let flipped = [resolution(
            &lost,
            "confirmed_not_delivered",
            "provider_status",
        )];
        assert!(check(&flipped, false).0[0].contains("provider's own behaviour"));
        // A human attestation is checked against the oracle's truth, not
        // trusted or rejected based on the source label alone.
        let attested = [resolution(
            &lost,
            "confirmed_delivered",
            "operator_attested",
        )];
        assert_eq!(check(&attested, false), (vec![], 1));
        let closure = [resolution(
            &erred,
            "confirmed_not_delivered",
            "conflict_resolution",
        )];
        assert_eq!(check(&closure, false), (vec![], 1));
        // A resolution for a send that did not end unknown.
        let stray = [RecordedResolution {
            credential_id: "cred-99".into(),
            state: "ambiguous".into(),
            source: "reconciler".into(),
        }];
        assert!(check(&stray, false).0[0].contains("did not see end unknown"));
    }

    fn record(no: i64, from: &str, to: &str, approver: Option<&str>) -> RecordedAgentChange {
        RecordedAgentChange {
            agent_id: "sim-eager-1".into(),
            change_no: no,
            from_state: from.into(),
            to_state: to.into(),
            approved_by: approver.map(String::from),
        }
    }

    /// The run's stops and reinstatements against Kavach's replies and its
    /// signed records: each can disagree, and each is found.
    #[test]
    fn agent_state_changes_are_reconciled_with_the_evidence() {
        let sent = vec![
            change(1, "quarantine", 200, "quarantined", "quarantined"),
            // A weaker stop changes nothing, and writes no record.
            change(1, "restrict", 200, "quarantined", "quarantined"),
            change(2, "reinstate", 200, "active", "active"),
        ];
        let records = vec![
            record(1, "active", "quarantined", None),
            record(2, "quarantined", "active", Some("dev-approver")),
        ];
        assert!(reconcile_agent_events(&sent, &records).is_empty());

        // Kavach says the agent is something else.
        let mut wrong = sent.clone();
        wrong[0].state = Some("active".into());
        assert!(reconcile_agent_events(&wrong, &records)[0].contains("the run's own record"));
        // A change with no record.
        let findings = reconcile_agent_events(&sent, &records[..1]);
        assert!(findings[0].contains("the evidence holds"), "{findings:?}");
        // A loosening whose record names no approver.
        let mut unapproved = records.clone();
        unapproved[1].approved_by = None;
        assert!(reconcile_agent_events(&sent, &unapproved)
            .iter()
            .any(|f| f.contains("no approver")));
        // A refused change.
        let mut refused = sent.clone();
        refused[2].status = 409;
        assert!(reconcile_agent_events(&refused, &records)
            .iter()
            .any(|f| f.contains("refused (409)")));
        // A revoke that took other mandates than the run held.
        let mut revoke = change(1, "revoke", 200, "revoked", "revoked");
        revoke.revoked = vec!["m-1".into()];
        revoke.expected_revoked = vec!["m-1".into(), "m-2".into()];
        assert!(
            reconcile_agent_events(&[revoke], &[record(1, "active", "revoked", None)])
                .iter()
                .any(|f| f.contains("revoked 1 mandate(s)"))
        );
    }
}

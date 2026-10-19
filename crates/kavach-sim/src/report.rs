//! What a run shows: what it does **not** cover first, then the counts,
//! every disagreement with the oracle, every leak, and the evidence.
//!
//! - **Violation:** Kavach allowed a call the oracle says the rules forbid.
//! - **Mismatch:** Kavach refused a call the oracle says the rules allow
//!   (or the call failed). Either Kavach or the oracle is wrong.
//! - **Leak:** a reply held a destination, a token or a raw number.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::ledger::{digest, AgentEntry, Entry, IssueEntry, SnapshotEntry, SorEntry};
use crate::oracle::{Oracle, Retry, Rules};
use crate::scenario::Scenario;

/// Always shown, before anything else.
pub const NOT_COVERED: &[&str] = &[
    "real providers, real numbers, real networks: synthetic data and the mock provider only",
    "network isolation (proved by CI's isolation job, not here)",
    "high availability, load and performance (kavach-bench)",
    "delegation to sub-agents (needs an agent delegation API)",
    "consent withdrawn mid-run (needs runtime consent changes)",
    "quarantining a rogue agent (needs the kill switch)",
    "trusted time lost (covered by the acceptance suite, not here)",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Bundle {
    /// Verified against the auditor's (dev) trusted keys.
    Verified {
        signed_with: String,
        records: u64,
        not_protected: Vec<String>,
    },
    /// No bundle: the stack did not stop cleanly (killed or crashed).
    Missing { reason: String },
    /// A bundle that does not verify.
    Failed { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub seq: u32,
    pub agent: String,
    pub borrower: String,
    pub at: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub not_covered: Vec<&'static str>,
    pub scenario: String,
    pub seed: u64,
    pub days: u32,
    pub borrowers: u32,
    pub agents: BTreeMap<String, AgentCounts>,
    pub calls: usize,
    /// Payments and disputes sent to the stack.
    pub revocation_events: usize,
    /// Snapshot reconciliations the run sent, with how many mandates each found.
    pub snapshots: Vec<usize>,
    /// Operators' changes of agents' states the run made (ADR-013).
    pub agent_state_events: usize,
    pub allowed: usize,
    pub blocked: usize,
    pub blocked_by_reason: BTreeMap<String, u32>,
    pub delivered: usize,
    /// Each catalog attack the adversarial agents made: tried, refused.
    pub attacks: BTreeMap<String, (u32, u32)>,
    /// Calls sent again after an unknown outcome, and how many came back
    /// replayed (never sent twice).
    pub retries: (u32, u32),
    pub violations: Vec<Finding>,
    pub mismatches: Vec<Finding>,
    pub leaks: Vec<Finding>,
    pub evidence: Bundle,
    /// The ledger, the evidence and the provider's inbox, against each
    /// other (when there is evidence to read).
    pub reconciliation: Option<crate::reconcile::Reconciliation>,
    /// Same seed, same digest.
    pub digest: String,
    pub expectations_unmet: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct AgentCounts {
    pub kind: String,
    pub allowed: u32,
    pub blocked: u32,
}

/// A disagreement between Kavach and the oracle on one call.
enum Issue {
    Violation(String),
    Mismatch(String),
}

/// A first send: allowed against the rules is a violation; refused when
/// the rules allow it, or an outcome other than the destination means, a
/// mismatch.
fn first_issue(call: &Entry, expected: &crate::oracle::Expected) -> Option<Issue> {
    if call.allowed() && !expected.allow {
        return Some(Issue::Violation(format!(
            "allowed, but {}",
            expected.because.join(", ")
        )));
    }
    if call.allowed() && call.outcome.as_deref() != expected.outcome {
        return Some(Issue::Mismatch(format!(
            "outcome {}, but the destination means {}",
            call.outcome.as_deref().unwrap_or("none"),
            expected.outcome.unwrap_or("none")
        )));
    }
    if !call.allowed() && expected.allow {
        return Some(Issue::Mismatch(format!(
            "refused ({} {}), but the rules allow it",
            call.status,
            call.reasons.join(", ")
        )));
    }
    None
}

/// A call sent again: whether it was answered without a second send, and
/// the issue if not.
fn retry_issue(call: &Entry, retry: &Retry) -> (bool, Option<Issue>) {
    let answered =
        call.replayed && call.allowed() == retry.allowed && call.outcome == retry.outcome;
    let issue = if call.allowed() && !call.replayed {
        Some(Issue::Violation(
            "allowed again without the stored reply: a possible second send".into(),
        ))
    } else if answered {
        None
    } else {
        Some(Issue::Mismatch(format!(
            "sent again: {} {}, but the rules mean the stored reply, replayed, outcome {}",
            call.status,
            call.reasons.join(", "),
            retry.outcome.as_deref().unwrap_or("none")
        )))
    };
    (answered, issue)
}

/// A new default Kavach took when the loan was closed to it, or refused
/// when it was not, is a finding of its own (ADR-012).
fn issue_findings(issues: &[IssueEntry]) -> Vec<Finding> {
    issues
        .iter()
        .filter(|i| i.accepted() != i.expected_accepted)
        .map(|issue| Finding {
            seq: 0,
            agent: issue.agent.clone(),
            borrower: issue.borrower.clone(),
            at: issue.at.to_rfc3339(),
            detail: if issue.accepted() {
                "Kavach took a new default the loan was closed to (a payment or dispute \
                 had reached it first); the model says refuse"
                    .to_string()
            } else {
                format!(
                    "Kavach refused a new default the loan was open to ({}); the model says take it",
                    issue.status
                )
            },
        })
        .collect()
}

/// A snapshot that found something other than what the run's own record of
/// its mandates says it should have (ADR-012 addendum).
fn snapshot_findings(snapshots: &[SnapshotEntry]) -> Vec<Finding> {
    snapshots
        .iter()
        .filter(|s| !(200..300).contains(&s.status) || s.found != s.expected)
        .map(|s| Finding {
            seq: 0,
            agent: String::new(),
            borrower: String::new(),
            at: s.at.to_rfc3339(),
            detail: if (200..300).contains(&s.status) {
                format!(
                    "the snapshot found {} mandate(s) with live authority for closed loans; \
                     the run's own record says {} (listed {})",
                    s.found.len(),
                    s.expected.len(),
                    s.listed
                )
            } else {
                format!("the snapshot was refused ({})", s.status)
            },
        })
        .collect()
}

impl Report {
    // The run's records are separate inputs on purpose (calls, events,
    // agent-state changes, evidence): a struct of them would only be
    // built to be taken apart again.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn build(
        scenario: &Scenario,
        world: &crate::world::World,
        ledger: &[Entry],
        events: &[SorEntry],
        agent_events: &[AgentEntry],
        issues: &[IssueEntry],
        snapshots: &[SnapshotEntry],
        evidence: Bundle,
        reconciliation: Option<crate::reconcile::Reconciliation>,
        rules: Rules,
    ) -> Self {
        let mut oracle = Oracle::new(rules, world.deliveries())
            .with_revocations(world.revocations(scenario))
            .with_agent_events(world.agent_events(scenario));
        let (mut violations, mut mismatches, mut leaks) = (Vec::new(), Vec::new(), Vec::new());
        let mut agents: BTreeMap<String, AgentCounts> = world
            .agents
            .iter()
            .map(|a| {
                (
                    a.id.clone(),
                    AgentCounts {
                        kind: a.kind.as_str().into(),
                        ..AgentCounts::default()
                    },
                )
            })
            .collect();
        let mut blocked_by_reason = BTreeMap::new();
        let mut attacks: BTreeMap<String, (u32, u32)> = BTreeMap::new();
        let mut retries = (0, 0);
        for call in ledger {
            let expected = oracle.judge(call);
            let finding = |detail: String| Finding {
                seq: call.seq,
                agent: call.agent.clone(),
                borrower: call.borrower.clone(),
                at: call.at.to_rfc3339(),
                detail,
            };
            if let Some(id) = &call.attack {
                let tally = attacks.entry(id.clone()).or_default();
                tally.0 += 1;
                tally.1 += u32::from(!call.allowed());
            }
            let issue = if let Some(retry) = &expected.retry {
                let (answered, issue) = retry_issue(call, retry);
                retries.0 += 1;
                retries.1 += u32::from(answered);
                issue
            } else {
                let counts = agents.entry(call.agent.clone()).or_default();
                if call.allowed() {
                    counts.allowed += 1;
                } else {
                    counts.blocked += 1;
                    for reason in call.reasons.iter().filter(|r| *r != "forbidden") {
                        *blocked_by_reason.entry(reason.clone()).or_insert(0) += 1;
                    }
                }
                first_issue(call, &expected)
            };
            match issue {
                Some(Issue::Violation(detail)) => violations.push(finding(detail)),
                Some(Issue::Mismatch(detail)) => mismatches.push(finding(detail)),
                None => {}
            }
            if let Some(what) = &call.leak {
                leaks.push(finding(format!("the reply held {what}")));
            }
        }
        mismatches.extend(issue_findings(issues));
        mismatches.extend(snapshot_findings(snapshots));
        let firsts = ledger.iter().filter(|c| c.retry_of.is_none());
        let calls = firsts.clone().count();
        let allowed = firsts.filter(|c| c.allowed()).count();
        let mut report = Self {
            not_covered: NOT_COVERED.to_vec(),
            scenario: scenario.name.clone(),
            seed: scenario.seed,
            days: scenario.days,
            borrowers: scenario.borrowers,
            agents,
            calls,
            revocation_events: events.len(),
            snapshots: snapshots.iter().map(|s| s.found.len()).collect(),
            agent_state_events: agent_events.len(),
            allowed,
            blocked: calls - allowed,
            blocked_by_reason,
            delivered: ledger
                .iter()
                .filter(|c| c.retry_of.is_none() && c.outcome.as_deref() == Some("delivered"))
                .count(),
            attacks,
            retries,
            violations,
            mismatches,
            leaks,
            evidence,
            reconciliation,
            digest: digest(ledger, events, agent_events, issues, snapshots),
            expectations_unmet: Vec::new(),
        };
        report.expectations_unmet = report.unmet(scenario);
        report
    }

    fn unmet(&self, scenario: &Scenario) -> Vec<String> {
        let e = &scenario.expect;
        let mut unmet = Vec::new();
        for (what, want, got) in [
            ("violations", e.violations, self.violations.len()),
            ("mismatches", e.mismatches, self.mismatches.len()),
            ("leaks", e.leaks, self.leaks.len()),
        ] {
            if usize::try_from(want).unwrap_or(usize::MAX) != got {
                unmet.push(format!("{what}: expected {want}, got {got}"));
            }
        }
        if self.allowed < usize::try_from(e.allowed_at_least).unwrap_or(usize::MAX) {
            unmet.push(format!(
                "allowed: expected at least {}, got {}",
                e.allowed_at_least, self.allowed
            ));
        }
        for (reason, want) in &e.blocked_at_least {
            let got = self.blocked_by_reason.get(reason).copied().unwrap_or(0);
            if got < *want {
                unmet.push(format!(
                    "blocked by {reason}: expected at least {want}, got {got}"
                ));
            }
        }
        unmet
    }

    /// 0 every expectation met with evidence that verifies; 2 no evidence
    /// to judge by (the stack did not stop cleanly); 1 anything else.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        match &self.evidence {
            Bundle::Missing { .. } => 2,
            Bundle::Verified { .. }
                if self.expectations_unmet.is_empty()
                    && self
                        .reconciliation
                        .as_ref()
                        .is_some_and(|r| r.findings.is_empty()) =>
            {
                0
            }
            Bundle::Failed { .. } | Bundle::Verified { .. } => 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calendar::slot;
    use crate::scenario::builtin;
    use crate::world::World;

    fn entry(seq: u32, minute: u32, agent: &str, decision: &str, reasons: &[&str]) -> Entry {
        Entry {
            seq,
            day: 1,
            at: slot(1, minute),
            agent: agent.into(),
            borrower: "ref:borrower:S-0001".into(),
            tool: "send_reminder".into(),
            params: serde_json::json!({ "subject_ref": "ref:borrower:S-0001",
                "channel": "whatsapp", "template_id": "emi_reminder_v1" }),
            channel: "whatsapp".into(),
            mandate_for: Some("ref:borrower:S-0001".into()),
            mandate_issued_at: None,
            request_id: format!("sim-17-{seq}"),
            retry_of: None,
            attack: None,
            status: 200,
            decision: Some(decision.into()),
            reasons: reasons.iter().map(ToString::to_string).collect(),
            record_id: None,
            outcome: (decision == "PASS").then(|| "delivered".into()),
            replayed: false,
            leak: None,
        }
    }

    /// What Kavach did in two-agents-one-borrower: three allowed, the
    /// fourth blocked by the cap.
    fn shared_cap() -> Vec<Entry> {
        vec![
            entry(1, 540, "sim-compliant-1", "PASS", &["authorized"]),
            entry(2, 540, "sim-compliant-2", "PASS", &["authorized"]),
            entry(3, 720, "sim-compliant-1", "PASS", &["authorized"]),
            entry(
                4,
                720,
                "sim-compliant-2",
                "BLOCK",
                &["forbidden", "contact-daily-cap"],
            ),
        ]
    }

    fn verified() -> Bundle {
        Bundle::Verified {
            signed_with: "dev-export-1".into(),
            records: 4,
            not_protected: vec![],
        }
    }

    /// A new default Kavach takes when the model says the loan is closed to
    /// it (or refuses when the model says take it) is a mismatch of its own:
    /// the check can fail, so a scenario that passes it says something.
    #[test]
    fn a_default_taken_or_refused_against_the_model_is_a_mismatch() {
        use crate::ledger::IssueEntry;
        let scenario = builtin("two-agents-one-borrower").unwrap();
        let world = World::build(&scenario);
        let issue = |status: u16, expected_accepted: bool| IssueEntry {
            day: 1,
            at: crate::calendar::slot(1, 720),
            occurred: crate::calendar::slot(1, 719),
            agent: "sim-compliant-1".into(),
            borrower: "ref:borrower:S-0001".into(),
            status,
            expected_accepted,
        };
        let build = |issues: &[IssueEntry]| {
            Report::build(
                &scenario,
                &world,
                &shared_cap(),
                &[],
                &[],
                issues,
                &[],
                verified(),
                Some(crate::reconcile::Reconciliation::default()),
                Rules::default(),
            )
        };
        // Agreement either way: refused as the model says, taken as it says.
        assert!(build(&[issue(409, false), issue(201, true)])
            .mismatches
            .is_empty());
        // Taken against the model, and refused against it.
        let taken = build(&[issue(201, false)]);
        assert_eq!(taken.mismatches.len(), 1);
        assert!(
            taken.mismatches[0].detail.contains("closed to"),
            "{:?}",
            taken.mismatches
        );
        let refused = build(&[issue(409, true)]);
        assert_eq!(refused.mismatches.len(), 1);
        assert!(refused.mismatches[0]
            .detail
            .contains("refused a new default"));
        assert_ne!(taken.exit_code(), 0);
    }

    /// A snapshot that finds something other than the run's own record of
    /// its mandates says (more, fewer, or a refusal) is a mismatch.
    #[test]
    fn a_snapshot_that_disagrees_with_the_runs_own_record_is_a_mismatch() {
        use crate::ledger::{SnapshotEntry, SnapshotFinding};
        let scenario = builtin("two-agents-one-borrower").unwrap();
        let world = World::build(&scenario);
        let finding = |id: &str| SnapshotFinding {
            mandate_id: id.into(),
            kind: "should_have_been_revoked".into(),
        };
        let snapshot = |status: u16, found: &[&str], expected: &[&str]| SnapshotEntry {
            day: 1,
            at: crate::calendar::slot(1, 900),
            listed: 1,
            status,
            found: found.iter().map(|id| finding(id)).collect(),
            expected: expected.iter().map(|id| finding(id)).collect(),
        };
        let build = |snapshots: &[SnapshotEntry]| {
            Report::build(
                &scenario,
                &world,
                &shared_cap(),
                &[],
                &[],
                &[],
                snapshots,
                verified(),
                Some(crate::reconcile::Reconciliation::default()),
                Rules::default(),
            )
        };
        assert!(build(&[snapshot(200, &["m-1"], &["m-1"])])
            .mismatches
            .is_empty());
        assert!(build(&[snapshot(200, &[], &[])]).mismatches.is_empty());
        for bad in [
            snapshot(200, &[], &["m-1"]),
            snapshot(200, &["m-1", "m-2"], &["m-1"]),
            snapshot(403, &[], &[]),
        ] {
            assert_eq!(build(&[bad]).mismatches.len(), 1);
        }
    }

    #[test]
    fn agreement_passes() {
        let scenario = builtin("two-agents-one-borrower").unwrap();
        let world = World::build(&scenario);
        let report = Report::build(
            &scenario,
            &world,
            &shared_cap(),
            &[],
            &[],
            &[],
            &[],
            verified(),
            Some(crate::reconcile::Reconciliation::default()),
            Rules::default(),
        );
        assert!(
            report.expectations_unmet.is_empty(),
            "{:?}",
            report.expectations_unmet
        );
        assert_eq!(report.exit_code(), 0);
        assert_eq!(report.blocked_by_reason["contact-daily-cap"], 1);
        assert_eq!(report.not_covered, NOT_COVERED);
    }

    /// Mandatory: a weakened oracle (cap 4) must surface as a mismatch, or
    /// the comparison could never fail.
    #[test]
    fn a_weakened_oracle_is_caught_as_a_mismatch() {
        let scenario = builtin("two-agents-one-borrower").unwrap();
        let world = World::build(&scenario);
        let weak = Rules {
            daily_cap: 4,
            ..Rules::default()
        };
        let report = Report::build(
            &scenario,
            &world,
            &shared_cap(),
            &[],
            &[],
            &[],
            &[],
            verified(),
            Some(crate::reconcile::Reconciliation::default()),
            weak,
        );
        assert_eq!(report.mismatches.len(), 1, "{report:?}");
        assert_eq!(report.exit_code(), 1);

        // And Kavach allowing a fourth contact is a violation.
        let mut allowed = shared_cap();
        allowed[3] = entry(4, 720, "sim-compliant-2", "PASS", &["authorized"]);
        let report = Report::build(
            &scenario,
            &world,
            &allowed,
            &[],
            &[],
            &[],
            &[],
            verified(),
            Some(crate::reconcile::Reconciliation::default()),
            Rules::default(),
        );
        assert_eq!(report.violations.len(), 1);
        assert_eq!(report.exit_code(), 1);
    }

    #[test]
    fn no_evidence_is_inconclusive_never_a_pass() {
        let scenario = builtin("two-agents-one-borrower").unwrap();
        let world = World::build(&scenario);
        let missing = Bundle::Missing {
            reason: "the stack was killed".into(),
        };
        let report = Report::build(
            &scenario,
            &world,
            &shared_cap(),
            &[],
            &[],
            &[],
            &[],
            missing,
            Some(crate::reconcile::Reconciliation::default()),
            Rules::default(),
        );
        assert_eq!(report.exit_code(), 2);
        let failed = Bundle::Failed {
            reason: "records.jsonl digest".into(),
        };
        let report = Report::build(
            &scenario,
            &world,
            &shared_cap(),
            &[],
            &[],
            &[],
            &[],
            failed,
            Some(crate::reconcile::Reconciliation::default()),
            Rules::default(),
        );
        assert_eq!(report.exit_code(), 1);
    }

    /// Mandatory: the agents and the oracle share no code, so a mismatch
    /// can show up at all.
    #[test]
    fn agents_and_oracle_are_independent() {
        // Module paths, not prose: each may mention the other in comments.
        let agents = include_str!("agents.rs");
        let oracle = include_str!("oracle.rs");
        for path in ["crate::oracle", "oracle::", "super::oracle"] {
            assert!(
                !agents.contains(path),
                "agents must not use the oracle ({path})"
            );
        }
        for path in ["crate::agents", "agents::", "super::agents"] {
            assert!(
                !oracle.contains(path),
                "the oracle must not use the agents ({path})"
            );
        }
        for path in ["crate::scenario", "scenario::", "super::scenario"] {
            assert!(
                !oracle.contains(path),
                "the oracle must not see expectations ({path})"
            );
        }
        // It judges what was sent, never the attack label on a call.
        let code = oracle.split("#[cfg(test)]").next().unwrap();
        assert!(
            !code.contains(".attack"),
            "the oracle must not read the attack label"
        );
    }

    /// ADR-013, the same discipline: an oracle that does not know about a
    /// stop must surface Kavach's refusal as a mismatch, and Kavach
    /// allowing a stopped agent's call is a violation. Otherwise the new
    /// comparison could never fail.
    #[test]
    fn a_stop_the_oracle_does_not_know_is_a_mismatch_and_a_leaky_stop_a_violation() {
        let scenario = builtin("rogue-agent-quarantined").unwrap();
        let world = World::build(&scenario);
        let stopped = || {
            vec![
                // Before the 12:00 quarantine: allowed.
                entry(1, 540, "sim-eager-1", "PASS", &["authorized"]),
                // After it: Kavach refuses.
                entry(
                    2,
                    780,
                    "sim-eager-1",
                    "BLOCK",
                    &["forbidden", "agent-stopped", "agent_state:quarantined"],
                ),
            ]
        };
        let build = |ledger: &[Entry], scenario: &Scenario| {
            Report::build(
                scenario,
                &world,
                ledger,
                &[],
                &[],
                &[],
                &[],
                verified(),
                Some(crate::reconcile::Reconciliation::default()),
                Rules::default(),
            )
        };
        let agreed = build(&stopped(), &scenario);
        assert!(
            agreed.mismatches.is_empty() && agreed.violations.is_empty(),
            "{agreed:?}"
        );

        // The same run judged by an oracle that was told of no stop.
        let mut blind = scenario.clone();
        blind.events.clear();
        let weak = build(&stopped(), &blind);
        assert_eq!(weak.mismatches.len(), 1, "{weak:?}");

        // Kavach allowing the stopped agent's call.
        let mut leaky = stopped();
        leaky[1] = entry(2, 780, "sim-eager-1", "PASS", &["authorized"]);
        let report = build(&leaky, &scenario);
        assert_eq!(report.violations.len(), 1, "{report:?}");
        assert_eq!(report.exit_code(), 1);
    }
}

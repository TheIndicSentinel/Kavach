//! What a run shows: what it does **not** cover first, then the counts,
//! every disagreement with the oracle, every leak, and the evidence.
//!
//! - **Violation:** Kavach allowed a call the oracle says the rules forbid.
//! - **Mismatch:** Kavach refused a call the oracle says the rules allow
//!   (or the call failed). Either Kavach or the oracle is wrong.
//! - **Leak:** a reply held a destination, a token or a raw number.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::ledger::{digest, Entry};
use crate::oracle::{Oracle, Rules};
use crate::scenario::Scenario;

/// Always shown, before anything else.
pub const NOT_COVERED: &[&str] = &[
    "real providers, real numbers, real networks: synthetic data and the mock provider only",
    "network isolation (proved by CI's isolation job, not here)",
    "high availability, load and performance (kavach-bench)",
    "revocation by payment or dispute (needs R1)",
    "delegation to sub-agents (needs an agent delegation API)",
    "consent withdrawn mid-run (needs runtime consent changes)",
    "quarantining a rogue agent (needs the kill switch)",
    "trusted time lost (covered by the acceptance suite, not here)",
    "the provider's inbox reconciled against the evidence (S3)",
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
    pub allowed: usize,
    pub blocked: usize,
    pub blocked_by_reason: BTreeMap<String, u32>,
    pub delivered: usize,
    pub violations: Vec<Finding>,
    pub mismatches: Vec<Finding>,
    pub leaks: Vec<Finding>,
    pub evidence: Bundle,
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

impl Report {
    #[must_use]
    pub fn build(
        scenario: &Scenario,
        world: &crate::world::World,
        ledger: &[Entry],
        evidence: Bundle,
        rules: Rules,
    ) -> Self {
        let mut oracle = Oracle::new(rules);
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
        for call in ledger {
            let expected = oracle.judge(call);
            let finding = |detail: String| Finding {
                seq: call.seq,
                agent: call.agent.clone(),
                borrower: call.borrower.clone(),
                at: call.at.to_rfc3339(),
                detail,
            };
            let counts = agents.entry(call.agent.clone()).or_default();
            if call.allowed() {
                counts.allowed += 1;
                if !expected.allow {
                    violations.push(finding(format!(
                        "allowed, but {}",
                        expected.because.join(", ")
                    )));
                }
            } else {
                counts.blocked += 1;
                for reason in &call.reasons {
                    if reason != "forbidden" {
                        *blocked_by_reason.entry(reason.clone()).or_insert(0) += 1;
                    }
                }
                if expected.allow {
                    mismatches.push(finding(format!(
                        "refused ({} {}), but the rules allow it",
                        call.status,
                        call.reasons.join(", ")
                    )));
                }
            }
            if let Some(what) = &call.leak {
                leaks.push(finding(format!("the reply held {what}")));
            }
        }
        let allowed = ledger.iter().filter(|c| c.allowed()).count();
        let mut report = Self {
            not_covered: NOT_COVERED.to_vec(),
            scenario: scenario.name.clone(),
            seed: scenario.seed,
            days: scenario.days,
            borrowers: scenario.borrowers,
            agents,
            calls: ledger.len(),
            allowed,
            blocked: ledger.len() - allowed,
            blocked_by_reason,
            delivered: ledger
                .iter()
                .filter(|c| c.outcome.as_deref() == Some("delivered"))
                .count(),
            violations,
            mismatches,
            leaks,
            evidence,
            digest: digest(ledger),
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
            Bundle::Verified { .. } if self.expectations_unmet.is_empty() => 0,
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
            channel: "whatsapp".into(),
            request_id: format!("sim-17-{seq}"),
            status: 200,
            decision: Some(decision.into()),
            reasons: reasons.iter().map(ToString::to_string).collect(),
            record_id: None,
            outcome: None,
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

    #[test]
    fn agreement_passes() {
        let scenario = builtin("two-agents-one-borrower").unwrap();
        let world = World::build(&scenario);
        let report = Report::build(
            &scenario,
            &world,
            &shared_cap(),
            verified(),
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
        let report = Report::build(&scenario, &world, &shared_cap(), verified(), weak);
        assert_eq!(report.mismatches.len(), 1, "{report:?}");
        assert_eq!(report.exit_code(), 1);

        // And Kavach allowing a fourth contact is a violation.
        let mut allowed = shared_cap();
        allowed[3] = entry(4, 720, "sim-compliant-2", "PASS", &["authorized"]);
        let report = Report::build(&scenario, &world, &allowed, verified(), Rules::default());
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
        let report = Report::build(&scenario, &world, &shared_cap(), missing, Rules::default());
        assert_eq!(report.exit_code(), 2);
        let failed = Bundle::Failed {
            reason: "records.jsonl digest".into(),
        };
        let report = Report::build(&scenario, &world, &shared_cap(), failed, Rules::default());
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
    }
}

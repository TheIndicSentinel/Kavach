//! The synthetic world of a run: borrowers with opaque references and
//! synthetic destinations, agents with their own identities, and who
//! serves whom. Written into the throwaway project before its stack starts
//! (the stack reads its fixtures once, at startup).

use std::collections::BTreeMap;

use crate::scenario::{AgentKind, Assignment, Resolved, Scenario};

/// The mock provider's failure numbers.
pub const REFUSE_NUMBER: &str = "+910000000998";
pub const ERROR_NUMBER: &str = "+910000000997";
pub const LOSE_NUMBER: &str = "+910000000999";

/// What the provider does with a borrower's messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Delivery {
    Delivers,
    Refuses,
    Errs,
    /// Delivers, and the response is lost.
    Loses,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Agent {
    /// Its own identity: a token and a passport of its own.
    pub id: String,
    pub kind: AgentKind,
    pub behaviour: Resolved,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Borrower {
    /// Kept for an adversarial agent's attacks (no real contacts).
    pub for_attacks: bool,
    pub delivery: Delivery,
    /// `ref:borrower:S-0001`: at most four digits, never an identifier.
    pub subject_ref: String,
    /// WhatsApp and SMS: `+910` and nine digits, the synthetic range.
    pub destination: String,
    pub voice: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct World {
    pub agents: Vec<Agent>,
    pub borrowers: Vec<Borrower>,
    /// (agent, borrower) indexes: one mandate each.
    pub assignments: Vec<(usize, usize)>,
}

impl World {
    #[must_use]
    pub fn build(scenario: &Scenario) -> Self {
        let mut agents = Vec::new();
        for spec in &scenario.agents {
            for _ in 0..spec.count {
                let n = agents
                    .iter()
                    .filter(|a: &&Agent| a.kind == spec.kind)
                    .count()
                    + 1;
                agents.push(Agent {
                    id: format!("sim-{}-{n}", spec.kind.as_str()),
                    kind: spec.kind,
                    behaviour: spec.behaviour.resolve(spec.kind),
                });
            }
        }
        let f = scenario.provider_failures;
        let failures = std::iter::repeat_n(Delivery::Refuses, f.refuse as usize)
            .chain(std::iter::repeat_n(Delivery::Errs, f.error as usize))
            .chain(std::iter::repeat_n(Delivery::Loses, f.lose as usize));
        let mut deliveries = failures.chain(std::iter::repeat(Delivery::Delivers));
        let mut borrowers: Vec<Borrower> = (1..=scenario.borrowers)
            .map(|i| {
                let delivery = deliveries.next().unwrap_or(Delivery::Delivers);
                Borrower {
                    for_attacks: false,
                    delivery,
                    subject_ref: format!("ref:borrower:S-{i:04}"),
                    destination: match delivery {
                        Delivery::Delivers => format!("+910{:09}", 100_000 + i),
                        Delivery::Refuses => REFUSE_NUMBER.into(),
                        Delivery::Errs => ERROR_NUMBER.into(),
                        Delivery::Loses => LOSE_NUMBER.into(),
                    },
                    voice: format!("+910{:09}", 200_000 + i),
                }
            })
            .collect();
        // One borrower of its own for each adversarial agent.
        let attackers: Vec<usize> = (0..agents.len())
            .filter(|&a| agents[a].kind == AgentKind::Adversarial)
            .collect();
        let mut assignments = Vec::new();
        for (n, &agent) in attackers.iter().enumerate() {
            let i = u32::try_from(n + 1).unwrap_or(u32::MAX);
            borrowers.push(Borrower {
                for_attacks: true,
                delivery: Delivery::Delivers,
                subject_ref: format!("ref:borrower:A-{i:04}"),
                destination: format!("+910{:09}", 300_000 + i),
                voice: format!("+910{:09}", 400_000 + i),
            });
            assignments.push((agent, borrowers.len() - 1));
        }
        let workers: Vec<usize> = (0..agents.len())
            .filter(|a| !attackers.contains(a))
            .collect();
        let real = scenario.borrowers as usize;
        match scenario.assignment {
            Assignment::Split => {
                assignments.extend((0..real).map(|b| (workers[b % workers.len()], b)));
            }
            Assignment::Shared => {
                assignments.extend(workers.iter().flat_map(|&a| (0..real).map(move |b| (a, b))));
            }
        }
        assignments.sort_unstable();
        Self {
            agents,
            borrowers,
            assignments,
        }
    }

    /// The borrowers `agent` serves.
    #[must_use]
    pub fn served_by(&self, agent: usize) -> Vec<usize> {
        self.assignments
            .iter()
            .filter(|(a, _)| *a == agent)
            .map(|(_, b)| *b)
            .collect()
    }

    /// Each borrower's delivery, by reference (for the oracle).
    #[must_use]
    pub fn deliveries(&self) -> BTreeMap<String, Delivery> {
        self.borrowers
            .iter()
            .map(|b| (b.subject_ref.clone(), b.delivery))
            .collect()
    }

    /// What the devkit writes: every agent eligible under the template.
    #[must_use]
    pub fn devkit(&self) -> kavach_devkit::World {
        let ids: Vec<String> = self.agents.iter().map(|a| a.id.clone()).collect();
        kavach_devkit::World {
            agents: ids.clone(),
            eligible_agents: ids,
            borrowers: self
                .borrowers
                .iter()
                .map(|b| kavach_devkit::Borrower {
                    subject_ref: b.subject_ref.clone(),
                    destination: b.destination.clone(),
                    voice: b.voice.clone(),
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scenario::builtin;

    #[test]
    fn identities_destinations_and_assignments() {
        let world = World::build(&builtin("normal-day").unwrap());
        assert_eq!(
            world
                .agents
                .iter()
                .map(|a| a.id.as_str())
                .collect::<Vec<_>>(),
            ["sim-compliant-1", "sim-compliant-2"]
        );
        assert_eq!(world.borrowers.len(), 10);
        for b in &world.borrowers {
            // The synthetic range, and never the mock provider's failure
            // numbers (…997–999).
            for number in [&b.destination, &b.voice] {
                let rest = number.strip_prefix("+910").unwrap();
                assert!(
                    rest.len() == 9 && rest.bytes().all(|c| c.is_ascii_digit()),
                    "{number}"
                );
                assert!(!rest.starts_with("000000"), "{number}");
            }
            let digits = b.subject_ref.bytes().filter(u8::is_ascii_digit).count();
            assert!(digits <= 8, "{}", b.subject_ref);
        }
        // Split: each borrower once, alternating agents.
        assert_eq!(world.assignments.len(), 10);
        assert_eq!((world.served_by(0).len(), world.served_by(1).len()), (5, 5));

        let shared = World::build(&builtin("two-agents-one-borrower").unwrap());
        assert_eq!(shared.assignments, [(0, 0), (1, 0)]);
        assert_eq!(shared.devkit().eligible_agents, shared.devkit().agents);
    }
}

//! The synthetic world of a run: borrowers with opaque references and
//! synthetic destinations, agents with their own identities, and who
//! serves whom. Written into the throwaway project before its stack starts
//! (the stack reads its fixtures once, at startup).

use crate::scenario::{AgentKind, Assignment, Resolved, Scenario};

#[derive(Debug, Clone, PartialEq)]
pub struct Agent {
    /// Its own identity: a token and a passport of its own.
    pub id: String,
    pub kind: AgentKind,
    pub behaviour: Resolved,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Borrower {
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
        let borrowers: Vec<Borrower> = (1..=scenario.borrowers)
            .map(|i| Borrower {
                subject_ref: format!("ref:borrower:S-{i:04}"),
                destination: format!("+910{:09}", 100_000 + i),
                voice: format!("+910{:09}", 200_000 + i),
            })
            .collect();
        let assignments = match scenario.assignment {
            Assignment::Split => (0..borrowers.len())
                .map(|b| (b % agents.len(), b))
                .collect(),
            Assignment::Shared => (0..agents.len())
                .flat_map(|a| (0..borrowers.len()).map(move |b| (a, b)))
                .collect(),
        };
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

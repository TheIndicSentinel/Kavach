//! What each agent tries. An agent knows its behaviour settings, the time,
//! the borrowers it serves and its own past contacts, nothing else: not
//! the other agents, and never what the rules would allow. It shares no
//! code with the module that judges it.

use std::collections::BTreeMap;

use kavach_attacks::{Auth, Probe, CATALOG};
use serde_json::{json, Value};

use crate::rng::Rng;
use crate::scenario::AgentKind;
use crate::world::World;

/// One call an agent decides to make.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Intent {
    pub agent: usize,
    /// The borrower whose mandate the call is made under.
    pub borrower: usize,
    pub tool: &'static str,
    pub params: Value,
    /// Under a mandate id that was never issued.
    pub forged_mandate: bool,
    /// The attack catalog id, for the report (never for judging).
    pub attack: Option<&'static str>,
}

/// The catalog's tool-call attacks an agent makes with its own token.
pub fn agent_attacks() -> impl Iterator<Item = &'static str> {
    CATALOG.iter().filter_map(|a| match a.probe {
        Probe::ToolCall {
            auth: Auth::Agent, ..
        } => Some(a.id),
        _ => None,
    })
}

/// An attack's call, as the catalog makes it, on `subject_ref`'s mandate:
/// payloads about another subject keep it; the rest use this borrower.
fn attack_intent(
    agent: usize,
    borrower: usize,
    subject_ref: &str,
    id: &'static str,
) -> Option<Intent> {
    let attack = CATALOG.iter().find(|a| a.id == id)?;
    let Probe::ToolCall {
        tool,
        real_mandate,
        params,
        ..
    } = attack.probe
    else {
        return None;
    };
    let mut params = params();
    if params["subject_ref"] == kavach_attacks::SUBJECT {
        params["subject_ref"] = json!(subject_ref);
    }
    Some(Intent {
        agent,
        borrower,
        tool,
        params,
        forged_mandate: !real_mandate,
        attack: Some(id),
    })
}

/// The contacts each agent has made (as it counts them: attempts).
#[derive(Debug, Default)]
pub struct Memory {
    attempts: BTreeMap<(usize, u32, usize), u32>,
}

/// An agent's own notion of working hours.
fn working_hours(minute_of_day: u32) -> bool {
    (9 * 60..18 * 60 + 59).contains(&minute_of_day)
}

/// Whether an agent sends a call again after an unknown outcome.
pub fn retries(world: &World, agent: usize, rng: &mut Rng) -> bool {
    rng.chance(world.agents[agent].behaviour.retry_rate)
}

/// The calls the agents decide on in one slot (`day`, minute of day).
pub fn decide(
    world: &World,
    day: u32,
    minute_of_day: u32,
    memory: &mut Memory,
    rng: &mut Rng,
) -> Vec<Intent> {
    let mut intents = Vec::new();
    for (agent, spec) in world.agents.iter().enumerate() {
        let b = &spec.behaviour;
        if spec.kind == AgentKind::Adversarial {
            for borrower in world.served_by(agent) {
                if b.attacks.is_empty() || !rng.chance(b.attack_rate) {
                    continue;
                }
                let pick = usize::try_from(rng.next_u64() % b.attacks.len() as u64).unwrap_or(0);
                intents.extend(attack_intent(
                    agent,
                    borrower,
                    &world.borrowers[borrower].subject_ref,
                    b.attacks[pick],
                ));
            }
            continue;
        }
        for borrower in world.served_by(agent) {
            if !working_hours(minute_of_day) && !rng.chance(b.late_rate) {
                continue;
            }
            let made = memory.attempts.entry((agent, day, borrower)).or_default();
            if *made >= b.contacts_per_day && !rng.chance(b.extra_contact_rate) {
                continue;
            }
            *made += 1;
            let channel = if rng.chance(b.wrong_channel_rate) {
                "sms"
            } else {
                "whatsapp"
            };
            intents.push(Intent {
                agent,
                borrower,
                tool: "send_reminder",
                params: json!({
                    "subject_ref": world.borrowers[borrower].subject_ref,
                    "channel": channel,
                    "template_id": "emi_reminder_v1",
                }),
                forged_mandate: false,
                attack: None,
            });
        }
    }
    intents
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scenario::builtin;

    #[test]
    fn compliant_agents_keep_their_own_limit_and_hours() {
        let world = World::build(&builtin("normal-day").unwrap());
        let (mut memory, mut rng) = (Memory::default(), Rng::new(1));
        assert_eq!(decide(&world, 1, 9 * 60, &mut memory, &mut rng).len(), 10);
        assert!(
            decide(&world, 1, 12 * 60, &mut memory, &mut rng).is_empty(),
            "one a day"
        );
        assert!(
            decide(&world, 2, 20 * 60, &mut memory, &mut rng).is_empty(),
            "not late"
        );
    }

    #[test]
    fn an_eager_agent_acts_late_by_its_rate() {
        let world = World::build(&builtin("after-hours").unwrap());
        let (mut memory, mut rng) = (Memory::default(), Rng::new(1));
        // 18:55 is in its working hours; 19:05 is not, but late_rate is 1.
        assert_eq!(
            decide(&world, 1, 18 * 60 + 55, &mut memory, &mut rng).len(),
            4
        );
        assert_eq!(
            decide(&world, 1, 19 * 60 + 5, &mut memory, &mut rng).len(),
            4
        );
        assert!(decide(&world, 1, 19 * 60 + 6, &mut memory, &mut rng).is_empty());
    }
}

//! What each agent tries. An agent knows its behaviour settings, the time,
//! the borrowers it serves and its own past contacts, nothing else: not
//! the other agents, and never what the rules would allow. It shares no
//! code with the module that judges it.

use std::collections::BTreeMap;

use crate::rng::Rng;
use crate::world::World;

/// One call an agent decides to make.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Intent {
    pub agent: usize,
    pub borrower: usize,
    pub tool: &'static str,
    pub channel: &'static str,
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
        let b = spec.behaviour;
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
                channel,
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

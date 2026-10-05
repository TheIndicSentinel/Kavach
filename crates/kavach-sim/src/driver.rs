//! One run: mandates for every (agent, borrower) pair, then each simulated
//! slot in order (the clock only moves forward), the agents' calls, and
//! each reply in the ledger. The stack is reached through [`Stack`]; the
//! CLI implements it over HTTP against its throwaway `dev up`.

use std::collections::BTreeMap;
use std::future::Future;

use chrono::{DateTime, Utc};
use serde_json::{json, Value};

use crate::agents::{decide, Memory};
use crate::calendar::slot;
use crate::ledger::Entry;
use crate::rng::Rng;
use crate::scenario::Scenario;
use crate::world::World;

pub trait Stack {
    /// A system-of-record event assigning `subject_ref` to `agent`, at the
    /// stack's time: the mandate it issued.
    fn issue(&self, agent: &str, subject_ref: &str)
        -> impl Future<Output = Result<String, String>>;
    /// `POST /v1/tools/{tool}` as `agent`: status and body.
    fn call(
        &self,
        agent: &str,
        tool: &str,
        body: Value,
    ) -> impl Future<Output = Result<(u16, Value), String>>;
    /// Moves the stack's fixed clock forward to `at`.
    fn move_clock(&self, at: DateTime<Utc>) -> impl Future<Output = Result<(), String>>;
}

/// When the stack's clock must start: the first slot of day 1.
pub fn start_time(scenario: &Scenario) -> Result<DateTime<Utc>, String> {
    let first = *scenario.slots()?.first().ok_or("no schedule")?;
    Ok(slot(1, first))
}

/// Runs `scenario` on `stack`, whose clock is at [`start_time`].
pub async fn run<S: Stack>(
    stack: &S,
    scenario: &Scenario,
    world: &World,
) -> Result<Vec<Entry>, String> {
    let mut mandates = BTreeMap::new();
    for &(agent, borrower) in &world.assignments {
        let id = stack
            .issue(
                &world.agents[agent].id,
                &world.borrowers[borrower].subject_ref,
            )
            .await
            .map_err(|e| format!("issuing a mandate: {e}"))?;
        mandates.insert((agent, borrower), id);
    }

    let (mut rng, mut memory, mut ledger) =
        (Rng::new(scenario.seed), Memory::default(), Vec::new());
    let slots = scenario.slots()?;
    let start = start_time(scenario)?;
    for day in 1..=scenario.days {
        for &minute in &slots {
            let at = slot(day, minute);
            if at != start {
                stack
                    .move_clock(at)
                    .await
                    .map_err(|e| format!("moving the clock: {e}"))?;
            }
            for intent in decide(world, day, minute, &mut memory, &mut rng) {
                let seq = u32::try_from(ledger.len() + 1).unwrap_or(u32::MAX);
                let (agent, borrower) = (
                    &world.agents[intent.agent],
                    &world.borrowers[intent.borrower],
                );
                let request_id = format!("sim-{}-{seq}", scenario.seed);
                let body = json!({
                    "mandate_id": mandates[&(intent.agent, intent.borrower)],
                    "request_id": request_id,
                    "params": {
                        "subject_ref": borrower.subject_ref,
                        "channel": intent.channel,
                        "template_id": "emi_reminder_v1",
                    },
                });
                let (status, reply) = stack.call(&agent.id, intent.tool, body).await?;
                ledger.push(Entry {
                    seq,
                    day,
                    at,
                    agent: agent.id.clone(),
                    borrower: borrower.subject_ref.clone(),
                    tool: intent.tool.into(),
                    channel: intent.channel.into(),
                    request_id,
                    status,
                    decision: reply["decision"].as_str().map(str::to_string),
                    reasons: reasons(status, &reply),
                    record_id: reply["record_id"].as_str().map(str::to_string),
                    outcome: reply["outcome"].as_str().map(str::to_string),
                    leak: leak(world, &reply),
                });
            }
        }
    }
    Ok(ledger)
}

/// The decision's reasons, or a refusal's problem code.
fn reasons(status: u16, reply: &Value) -> Vec<String> {
    if status == 200 {
        reply["reasons"]
            .as_array()
            .map(|r| {
                r.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    } else {
        vec![reply["code"]
            .as_str()
            .unwrap_or("no_problem_body")
            .to_string()]
    }
}

/// What an agent must never get back: a destination, a token, a number.
fn leak(world: &World, reply: &Value) -> Option<String> {
    let text = reply.to_string();
    if let Some(b) = world
        .borrowers
        .iter()
        .find(|b| text.contains(&b.destination) || text.contains(&b.voice))
    {
        return Some(format!("a destination of {}", b.subject_ref));
    }
    if text.contains("+91") {
        return Some("a phone number".into());
    }
    if text.contains("eyJ") {
        return Some("a token".into());
    }
    None
}

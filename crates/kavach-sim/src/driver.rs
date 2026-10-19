//! One run: mandates for every (agent, borrower) pair, then each simulated
//! slot in order (the clock only moves forward), the agents' calls, and
//! each reply in the ledger. The stack is reached through [`Stack`]; the
//! CLI implements it over HTTP against its throwaway `dev up`.

use std::collections::BTreeMap;
use std::future::Future;

use chrono::{DateTime, Utc};
use serde_json::{json, Value};

use crate::agents::{decide, retries, Memory};
use crate::calendar::slot;
use crate::ledger::{AgentEntry, Entry, IssueEntry, SnapshotEntry, SnapshotFinding, SorEntry};
use crate::oracle::{default_accepted, Closure, Standing, Verb};
use crate::rng::Rng;
use crate::scenario::{minute_of_day, EventSpec, Scenario};
use crate::world::World;

/// What the stack answered to an event that assigns a borrower to an agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issued {
    pub status: u16,
    /// The mandate, when the event was taken.
    pub mandate: Option<String>,
}

pub trait Stack {
    /// A system-of-record event assigning `subject_ref` to `agent`, dated
    /// `occurred` (the stack's clock is when it arrives): what came back.
    /// A refusal is an answer, not an error.
    fn issue(
        &self,
        agent: &str,
        subject_ref: &str,
        occurred: DateTime<Utc>,
    ) -> impl Future<Output = Result<Issued, String>>;
    /// `POST /v1/tools/{tool}` as `agent`: status and body.
    fn call(
        &self,
        agent: &str,
        tool: &str,
        body: Value,
    ) -> impl Future<Output = Result<(u16, Value), String>>;
    /// Moves the stack's fixed clock forward to `at`.
    fn move_clock(&self, at: DateTime<Utc>) -> impl Future<Output = Result<(), String>>;
    /// An operator's change of `agent`'s state (`restrict`, `quarantine`,
    /// `revoke`, `reinstate`; a reinstatement is proposed by the operator
    /// and approved by a second principal): status and a body with the
    /// agent's `state` afterwards and, for a revoke, `mandates_revoked`.
    fn set_agent_state(
        &self,
        agent: &str,
        verb: &str,
    ) -> impl Future<Output = Result<(u16, Value), String>>;
    /// The lender's closed loans, for snapshot reconciliation (ADR-012
    /// addendum): `{"system": "lms", "records": [...]}`; status and body.
    fn snapshot(&self, body: Value) -> impl Future<Output = Result<(u16, Value), String>>;
    /// A revoking system-of-record event (`loan.paid`, `loan.disputed`)
    /// for `subject_ref`'s loan, dated `occurred` (the stack's clock is when
    /// it arrives): status and body.
    fn revoke(
        &self,
        event_type: &str,
        event_id: &str,
        subject_ref: &str,
        occurred: DateTime<Utc>,
    ) -> impl Future<Output = Result<(u16, Value), String>>;
}

/// A run's record: every call, and every system-of-record event it sent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Run {
    pub calls: Vec<Entry>,
    pub events: Vec<SorEntry>,
    /// Operators' changes of agents' states (ADR-013).
    pub agent_events: Vec<AgentEntry>,
    /// New defaults the run sent, and whether Kavach took each.
    pub issues: Vec<IssueEntry>,
    /// The lender's closed loans sent to Kavach, and what it found.
    pub snapshots: Vec<SnapshotEntry>,
}

/// One mandate the run obtained, in the simulator's own record.
struct Held {
    agent: usize,
    borrower: usize,
    id: String,
    issued_at: DateTime<Utc>,
    revoked: bool,
}

/// The mandates the run holds, and which each pair acts under now.
#[derive(Default)]
struct Mandates {
    all: Vec<Held>,
    current: BTreeMap<(usize, usize), usize>,
    /// The payments and disputes that have reached Kavach so far, in order:
    /// the simulator's own record of what has closed which loan.
    closures: Vec<Closure>,
    /// Every payment and dispute the lender made, including the ones its
    /// system never sent: what it lists in a snapshot.
    lender: Vec<Closure>,
}

impl Mandates {
    /// A mandate the run needs (the first assignments): refused is an error.
    async fn issue<S: Stack>(
        &mut self,
        stack: &S,
        world: &World,
        pair: (usize, usize),
        at: DateTime<Utc>,
    ) -> Result<(), String> {
        let issued = self.try_issue(stack, world, pair, at).await?;
        if issued.mandate.is_none() {
            return Err(format!("issuing a mandate: refused ({})", issued.status));
        }
        Ok(())
    }

    /// An assignment dated `occurred`, which Kavach may refuse. The run
    /// holds the mandate if it got one.
    async fn try_issue<S: Stack>(
        &mut self,
        stack: &S,
        world: &World,
        (agent, borrower): (usize, usize),
        occurred: DateTime<Utc>,
    ) -> Result<Issued, String> {
        let issued = stack
            .issue(
                &world.agents[agent].id,
                &world.borrowers[borrower].subject_ref,
                occurred,
            )
            .await
            .map_err(|e| format!("issuing a mandate: {e}"))?;
        if let Some(id) = &issued.mandate {
            self.all.push(Held {
                agent,
                borrower,
                id: id.clone(),
                // The default's own time: what a payment is compared with.
                issued_at: occurred,
                revoked: false,
            });
            self.current.insert((agent, borrower), self.all.len() - 1);
        }
        Ok(issued)
    }

    fn current(&self, pair: (usize, usize)) -> &Held {
        &self.all[self.current[&pair]]
    }

    /// What revoking `agent` must revoke: the mandates it holds that the
    /// run has not seen revoked. Marks them revoked.
    fn revoke_agent(&mut self, agent: usize) -> Vec<String> {
        let mut ids = Vec::new();
        for held in self
            .all
            .iter_mut()
            .filter(|h| h.agent == agent && !h.revoked)
        {
            held.revoked = true;
            ids.push(held.id.clone());
        }
        ids
    }

    /// What a payment or dispute must revoke: the borrower's mandates whose
    /// default it reaches (by when each happened, give or take the margin),
    /// not revoked before. Marks them revoked and records the closure.
    fn revoke(&mut self, borrower: usize, closure: &Closure) -> Vec<String> {
        let mut ids = Vec::new();
        self.closures.push(closure.clone());
        for held in self
            .all
            .iter_mut()
            .filter(|h| h.borrower == borrower && !h.revoked && closure.reaches(h.issued_at))
        {
            held.revoked = true;
            ids.push(held.id.clone());
        }
        ids
    }
}

/// When the stack's clock must start: the first slot of day 1.
pub fn start_time(scenario: &Scenario) -> Result<DateTime<Utc>, String> {
    let first = *scenario.slots()?.first().ok_or("no schedule")?;
    Ok(slot(1, first))
}

/// Runs `scenario` on `stack`, whose clock is at [`start_time`].
pub async fn run<S: Stack>(stack: &S, scenario: &Scenario, world: &World) -> Result<Run, String> {
    let start = start_time(scenario)?;
    let mut mandates = Mandates::default();
    for &pair in &world.assignments {
        mandates.issue(stack, world, pair, start).await?;
    }

    let (mut rng, mut memory, mut out) =
        (Rng::new(scenario.seed), Memory::default(), Run::default());
    // The simulator's own record of how each agent stands (its model, never
    // Kavach's replies).
    let mut standing: BTreeMap<String, Standing> = BTreeMap::new();
    let slots = scenario.slots()?;
    for day in 1..=scenario.days {
        for minute in timeline(scenario, day, &slots)? {
            let at = slot(day, minute);
            if at != start {
                stack
                    .move_clock(at)
                    .await
                    .map_err(|e| format!("moving the clock: {e}"))?;
            }
            // The system of record first, then the agents.
            for event in scenario.events.iter().filter(|e| e.day == day) {
                if minute_of_day(&event.at)? == minute {
                    let n = out.events.len();
                    if event.kind == crate::scenario::EventKind::Snapshot {
                        snapshot_event(stack, world, &mandates, event, at, &mut out).await?;
                        continue;
                    }
                    if event.kind.is_agent_event() {
                        agent_event(
                            stack,
                            world,
                            &mut mandates,
                            &mut standing,
                            event,
                            at,
                            &mut out,
                        )
                        .await?;
                        continue;
                    }
                    send_event(
                        stack,
                        scenario,
                        world,
                        &mut mandates,
                        event,
                        at,
                        n,
                        &mut out,
                    )
                    .await?;
                }
            }
            if !slots.contains(&minute) {
                continue;
            }
            for intent in decide(world, day, minute, &mut memory, &mut rng) {
                let seq = u32::try_from(out.calls.len() + 1).unwrap_or(u32::MAX);
                let borrower = &world.borrowers[intent.borrower];
                let request_id = format!("sim-{}-{seq}", scenario.seed);
                let held = (!intent.forged_mandate)
                    .then(|| mandates.current((intent.agent, intent.borrower)));
                let mandate = held.map_or_else(
                    || format!("forged-{}-{seq}", scenario.seed),
                    |h| h.id.clone(),
                );
                let body = json!({
                    "mandate_id": mandate,
                    "request_id": request_id,
                    "params": intent.params,
                });
                let call = Call {
                    seq,
                    day,
                    at,
                    agent: world.agents[intent.agent].id.clone(),
                    borrower: borrower.subject_ref.clone(),
                    tool: intent.tool.into(),
                    params: intent.params.clone(),
                    mandate_for: held.map(|_| borrower.subject_ref.clone()),
                    mandate_issued_at: held.map(|h| h.issued_at),
                    request_id,
                    retry_of: None,
                    attack: intent.attack.map(str::to_string),
                };
                let entry = send(stack, world, &call, &body).await?;
                let lost = entry.outcome.as_deref() == Some("unknown");
                out.calls.push(entry);
                // The same request again, after an outcome it cannot know.
                if lost && retries(world, intent.agent, &mut rng) {
                    let again = Call {
                        seq: seq + 1,
                        retry_of: Some(seq),
                        ..call
                    };
                    out.calls.push(send(stack, world, &again, &body).await?);
                }
            }
        }
    }
    Ok(out)
}

/// The minutes of `day` at which something happens: the schedule's slots
/// and the day's events, in order (the clock only moves forward).
fn timeline(scenario: &Scenario, day: u32, slots: &[u32]) -> Result<Vec<u32>, String> {
    let mut minutes: Vec<u32> = slots.to_vec();
    for event in scenario.events.iter().filter(|e| e.day == day) {
        minutes.push(minute_of_day(&event.at)?);
    }
    minutes.sort_unstable();
    minutes.dedup();
    Ok(minutes)
}

/// An operator's change of one agent's state. The expected state and the
/// expected revocations come from the simulator's own record.
async fn agent_event<S: Stack>(
    stack: &S,
    world: &World,
    mandates: &mut Mandates,
    standing: &mut BTreeMap<String, Standing>,
    event: &EventSpec,
    at: DateTime<Utc>,
    out: &mut Run,
) -> Result<(), String> {
    let (Some(agent_id), Some(verb)) = (event.agent.as_deref(), crate::world::verb_of(event.kind))
    else {
        return Err("an agent event without an agent".into());
    };
    let index = world
        .agents
        .iter()
        .position(|a| a.id == agent_id)
        .ok_or_else(|| format!("no agent {agent_id} in this world"))?;
    let before = standing.get(agent_id).copied().unwrap_or_default();
    let after = before.after(verb);
    standing.insert(agent_id.to_string(), after);
    let expected_revoked = if verb == Verb::Revoke && before != Standing::Revoked {
        mandates.revoke_agent(index)
    } else {
        Vec::new()
    };
    let (status, reply) = stack
        .set_agent_state(agent_id, verb.as_str())
        .await
        .map_err(|e| format!("{} {agent_id}: {e}", verb.as_str()))?;
    out.agent_events.push(AgentEntry {
        day: event.day,
        at,
        agent: agent_id.to_string(),
        verb: verb.as_str().into(),
        status,
        state: reply["state"].as_str().map(str::to_string),
        expected_state: after.name().into(),
        revoked: reply["mandates_revoked"]
            .as_array()
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| id.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default(),
        expected_revoked,
    });
    Ok(())
}

/// One event, for each of its borrowers: a payment or dispute revokes
/// (and is recorded with what it must revoke), a new default assigns the
/// borrower again.
#[allow(clippy::too_many_arguments)]
async fn send_event<S: Stack>(
    stack: &S,
    scenario: &Scenario,
    world: &World,
    mandates: &mut Mandates,
    event: &EventSpec,
    at: DateTime<Utc>,
    n: usize,
    out: &mut Run,
) -> Result<(), String> {
    for (k, borrower) in world
        .event_borrowers(event.borrowers)
        .into_iter()
        .enumerate()
    {
        let subject = &world.borrowers[borrower].subject_ref;
        let occurred = at - chrono::Duration::seconds(i64::from(event.lag_seconds));
        if !event.kind.revokes() {
            let pairs: Vec<(usize, usize)> = world
                .assignments
                .iter()
                .copied()
                .filter(|&(_, b)| b == borrower)
                .collect();
            // The model's answer comes first, from the events so far.
            let expected_accepted = default_accepted(&mandates.closures, subject, occurred);
            for pair in pairs {
                let issued = mandates.try_issue(stack, world, pair, occurred).await?;
                out.issues.push(IssueEntry {
                    day: event.day,
                    at,
                    occurred,
                    agent: world.agents[pair.0].id.clone(),
                    borrower: subject.clone(),
                    status: issued.status,
                    expected_accepted,
                });
            }
            continue;
        }
        let closure = Closure {
            borrower: subject.clone(),
            occurred,
            arrived: at,
            disputed: event.kind == crate::scenario::EventKind::Disputed,
        };
        mandates.lender.push(closure.clone());
        if event.dropped {
            // Lost on the way: Kavach hears nothing, the model learns nothing.
            continue;
        }
        let event_id = format!("sim-{}-ev{n}-{k}", scenario.seed);
        let (status, reply) = stack
            .revoke(event.kind.as_str(), &event_id, subject, occurred)
            .await
            .map_err(|e| format!("sending {}: {e}", event.kind.as_str()))?;
        let revoked = reply["revoked"]
            .as_array()
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| id.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        out.events.push(SorEntry {
            day: event.day,
            at,
            occurred,
            event_id,
            event_type: event.kind.as_str().into(),
            borrower: subject.clone(),
            status,
            revoked,
            expected: mandates.revoke(borrower, &closure),
        });
    }
    Ok(())
}

/// The lender sends every payment and dispute it has made (sent or lost) and
/// Kavach reports the authority it still holds for them. What it should
/// report comes from the run's own record of its mandates.
async fn snapshot_event<S: Stack>(
    stack: &S,
    world: &World,
    mandates: &Mandates,
    event: &EventSpec,
    at: DateTime<Utc>,
    out: &mut Run,
) -> Result<(), String> {
    let records: Vec<Value> = mandates
        .lender
        .iter()
        .map(|c| {
            json!({
                "record_ref": kavach_devkit::loan_ref(&c.borrower),
                "state": if c.disputed { "disputed" } else { "paid" },
                "closed_at": c.occurred,
            })
        })
        .collect();
    if records.is_empty() {
        return Err("a lender.snapshot before any payment or dispute".into());
    }
    let listed = records.len();
    let (status, reply) = stack
        .snapshot(json!({ "system": "lms", "records": records }))
        .await
        .map_err(|e| format!("the snapshot: {e}"))?;
    let mut expected = Vec::new();
    for closed in &mandates.lender {
        for held in mandates
            .all
            .iter()
            .filter(|h| !h.revoked && world.borrowers[h.borrower].subject_ref == closed.borrower)
        {
            // A payment's event would have revoked what it reaches; a
            // dispute holds the loan against every live mandate.
            let would_revoke = closed.disputed || closed.reaches(held.issued_at);
            expected.push(SnapshotFinding {
                mandate_id: held.id.clone(),
                kind: if would_revoke {
                    "should_have_been_revoked"
                } else {
                    "issued_after_closure"
                }
                .into(),
            });
        }
    }
    let mut found: Vec<SnapshotFinding> = reply["findings"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|f| SnapshotFinding {
            mandate_id: f["mandate_id"].as_str().unwrap_or_default().into(),
            kind: f["kind"].as_str().unwrap_or_default().into(),
        })
        .collect();
    found.sort();
    expected.sort();
    out.snapshots.push(SnapshotEntry {
        day: event.day,
        at,
        listed,
        status,
        found,
        expected,
    });
    Ok(())
}

/// One call as made (before its reply).
struct Call {
    seq: u32,
    day: u32,
    at: DateTime<Utc>,
    agent: String,
    borrower: String,
    tool: String,
    params: Value,
    mandate_for: Option<String>,
    mandate_issued_at: Option<DateTime<Utc>>,
    request_id: String,
    retry_of: Option<u32>,
    attack: Option<String>,
}

async fn send<S: Stack>(
    stack: &S,
    world: &World,
    call: &Call,
    body: &Value,
) -> Result<Entry, String> {
    let (status, reply) = stack.call(&call.agent, &call.tool, body.clone()).await?;
    Ok(Entry {
        seq: call.seq,
        day: call.day,
        at: call.at,
        agent: call.agent.clone(),
        borrower: call.borrower.clone(),
        tool: call.tool.clone(),
        channel: call.params["channel"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        params: call.params.clone(),
        mandate_for: call.mandate_for.clone(),
        mandate_issued_at: call.mandate_issued_at,
        request_id: call.request_id.clone(),
        retry_of: call.retry_of,
        attack: call.attack.clone(),
        status,
        decision: reply["decision"].as_str().map(str::to_string),
        reasons: reasons(status, &reply),
        record_id: reply["record_id"].as_str().map(str::to_string),
        outcome: reply["outcome"].as_str().map(str::to_string),
        replayed: reply["replayed"].as_bool().unwrap_or(false),
        leak: leak(world, &reply),
    })
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

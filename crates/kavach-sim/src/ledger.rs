//! Every call a run made: what was intended, at what simulated time, and
//! what came back. The oracle and the report read only this.

use chrono::{DateTime, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Entry {
    pub seq: u32,
    pub day: u32,
    /// The stack's (fixed, simulated) time of the call.
    pub at: DateTime<Utc>,
    pub agent: String,
    /// The borrower whose mandate the call was made under.
    pub borrower: String,
    pub tool: String,
    /// The parameters as sent.
    pub params: serde_json::Value,
    /// `params.channel`, for reading.
    pub channel: String,
    /// The borrower the mandate was issued for; `None` for a mandate id
    /// that was never issued.
    pub mandate_for: Option<String>,
    /// When the mandate was issued (the simulator's own record).
    pub mandate_issued_at: Option<DateTime<Utc>>,
    pub request_id: String,
    /// This call sends call `retry_of` again (same request id).
    pub retry_of: Option<u32>,
    /// The attack catalog id, for the report only.
    pub attack: Option<String>,
    /// HTTP status; a decision comes with 200.
    pub status: u16,
    pub decision: Option<String>,
    pub reasons: Vec<String>,
    pub record_id: Option<String>,
    pub outcome: Option<String>,
    /// The reply was the stored one (`replayed: true`).
    pub replayed: bool,
    /// A reply that held a destination, a token or another raw identifier.
    pub leak: Option<String>,
}

/// A system-of-record event the run sent (ADR-012).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SorEntry {
    pub day: u32,
    pub at: DateTime<Utc>,
    pub event_id: String,
    pub event_type: String,
    pub borrower: String,
    pub status: u16,
    /// What Kavach says it revoked.
    pub revoked: Vec<String>,
    /// What the simulator's own record says should be: the borrower's
    /// mandates issued at or before the event and not revoked before it.
    pub expected: Vec<String>,
}

/// An operator's change of an agent's state during a run (ADR-013).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AgentEntry {
    pub day: u32,
    pub at: DateTime<Utc>,
    pub agent: String,
    /// `restrict`, `quarantine`, `revoke` or `reinstate`.
    pub verb: String,
    pub status: u16,
    /// The state Kavach says the agent is in now.
    pub state: Option<String>,
    /// The state the simulator's own model says: never read from replies.
    pub expected_state: String,
    /// The mandates Kavach says it revoked (a revoke).
    pub revoked: Vec<String>,
    /// The agent's mandates the run held and had not seen revoked.
    pub expected_revoked: Vec<String>,
}

impl Entry {
    /// Kavach allowed it (PASS or ALERT).
    #[must_use]
    pub fn allowed(&self) -> bool {
        self.status == 200 && matches!(self.decision.as_deref(), Some("PASS" | "ALERT"))
    }
}

/// What a seed must reproduce: who did what, when, and what was decided.
/// Not the ids or signatures, which are random by design.
#[must_use]
pub fn digest(entries: &[Entry], events: &[SorEntry], agent_events: &[AgentEntry]) -> String {
    let mut hash = Sha256::new();
    for e in agent_events {
        hash.update(format!(
            "agent|{}|{}|{}|{}|{}|{}\n",
            e.day,
            e.at.to_rfc3339(),
            e.agent,
            e.verb,
            e.status,
            e.state.as_deref().unwrap_or("-")
        ));
    }
    for e in events {
        hash.update(format!(
            "event|{}|{}|{}|{}|{}|{}\n",
            e.day,
            e.at.to_rfc3339(),
            e.event_id,
            e.event_type,
            e.borrower,
            e.status
        ));
    }
    for e in entries {
        hash.update(format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}\n",
            e.seq,
            e.day,
            e.at.to_rfc3339(),
            e.agent,
            e.borrower,
            e.tool,
            e.params,
            e.retry_of.unwrap_or(0),
            e.outcome.as_deref().unwrap_or("-"),
            e.status,
            e.decision.as_deref().unwrap_or("-"),
            e.reasons.join(",")
        ));
    }
    format!("sha256:{}", hex::encode(hash.finalize()))
}

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
pub fn digest(entries: &[Entry]) -> String {
    let mut hash = Sha256::new();
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

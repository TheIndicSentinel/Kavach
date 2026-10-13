//! Agent risk state persistence (ADR-013 §1).

use std::collections::BTreeMap;
use std::future::Future;

use chrono::{DateTime, Utc};
pub use kavach_domain::{AgentState, ReasonCode};

use crate::agent_evidence::EvidenceSigner;
use crate::chain_record::AgentStateRecord;
use crate::{PortError, TimeSource};

/// Longest free-text note a change may carry.
pub const MAX_NOTE_CHARS: usize = 256;

/// One agent's current state and the change that made it so.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredAgentState {
    pub tenant_id: String,
    pub agent_id: String,
    pub state: AgentState,
    /// Which change this is (1 for the agent's first).
    pub change_no: i64,
    pub reason_code: ReasonCode,
    /// The operator's free text. Kept here and in the admin audit log,
    /// never in the evidence chain (which holds a keyed digest of it).
    pub note: String,
    pub changed_by: String,
    /// The second principal, for a change that loosens.
    pub approved_by: Option<String>,
    /// The change request that made this change (a reinstatement), so a
    /// retried approval can tell its own change from another.
    pub change_request_id: Option<String>,
    pub changed_at: DateTime<Utc>,
}

/// One change, as the append-only history keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredAgentChange {
    pub tenant_id: String,
    pub agent_id: String,
    pub change_no: i64,
    pub from_state: AgentState,
    pub to_state: AgentState,
    pub reason_code: ReasonCode,
    pub note: String,
    pub changed_by: String,
    pub approved_by: Option<String>,
    pub change_request_id: Option<String>,
    pub changed_at: DateTime<Utc>,
}

impl StoredAgentChange {
    /// Its place in [`AgentStateStore::changes_after`] order.
    #[must_use]
    pub fn cursor(&self) -> AgentChangeCursor {
        AgentChangeCursor {
            changed_at: self.changed_at,
            tenant_id: self.tenant_id.clone(),
            agent_id: self.agent_id.clone(),
            change_no: self.change_no,
        }
    }
}

/// A position in the history, in `(changed_at, tenant, agent, change_no)`
/// order.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct AgentChangeCursor {
    pub changed_at: DateTime<Utc>,
    pub tenant_id: String,
    pub agent_id: String,
    pub change_no: i64,
}

/// A request to move an agent to `to`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentStateChange {
    pub tenant_id: String,
    pub agent_id: String,
    pub to: AgentState,
    /// Why, from a closed set: this is what the evidence chain carries.
    pub reason_code: ReasonCode,
    /// The operator's free text: 0 to [`MAX_NOTE_CHARS`] characters, no
    /// control characters.
    pub note: String,
    pub changed_by: String,
    /// Required, and a principal other than `changed_by`, when the change
    /// loosens (ADR-013 §3).
    pub approved_by: Option<String>,
    /// The change request this change carries out, if any: required when it
    /// loosens through the API, absent for an operator's stop.
    pub change_request_id: Option<String>,
    /// Trusted time.
    pub at: DateTime<Utc>,
}

impl AgentStateChange {
    /// The rules every store applies, so a memory and a Postgres store agree
    /// (and the database holds them too). `current` is the state before the
    /// change.
    ///
    /// - `revoked` is final.
    /// - A change to the state it is in is refused: it would be a record of
    ///   nothing.
    /// - A change that loosens needs an approver other than the changer; one
    ///   that tightens needs none and names none.
    pub fn check(&self, current: AgentState) -> Result<(), PortError> {
        if self.tenant_id.is_empty() || self.agent_id.is_empty() || self.changed_by.is_empty() {
            return Err(PortError::invalid(
                "tenant, agent and principal are required",
            ));
        }
        if self.note.chars().count() > MAX_NOTE_CHARS || self.note.chars().any(char::is_control) {
            return Err(PortError::invalid(format!(
                "a note of at most {MAX_NOTE_CHARS} characters, without control characters"
            )));
        }
        if current == AgentState::Revoked {
            return Err(PortError::rejected(
                "a revoked agent cannot be changed: issue a new passport with a new agent id",
            ));
        }
        if current == self.to {
            return Err(PortError::rejected(format!(
                "the agent is already {}",
                current.as_str()
            )));
        }
        match (current.loosens_to(self.to), self.approved_by.as_deref()) {
            (true, None) => Err(PortError::rejected(
                "loosening an agent's state needs a second principal's approval",
            )),
            (true, Some(approver)) if approver == self.changed_by || approver.is_empty() => {
                Err(PortError::rejected(
                    "the approver must be a different principal from the one who proposed",
                ))
            }
            (false, Some(_)) => Err(PortError::invalid(
                "a change that tightens takes no approver",
            )),
            _ => Ok(()),
        }
    }
}

/// How a change is recorded in the evidence chain **in the same
/// transaction** as the state change (a loosening: authority is never
/// given back without evidence).
pub struct Recording<'a> {
    pub partition_id: i32,
    pub clock: &'a dyn TimeSource,
    pub signer: &'a dyn EvidenceSigner,
    /// The keyed digest of the note for change number `n`, if the change
    /// has a note. Called once the change number is known.
    pub reason_digest: &'a (dyn Fn(i64) -> Option<String> + Send + Sync),
}

/// Where agent states live (ADR-013). Read at every authorization: there is
/// no cache, so a change is in force on every replica from the next call.
pub trait AgentStateStore: Send + Sync {
    /// The state of each agent in `agent_ids`; an agent with no row is
    /// `Active`. Every id asked for is in the answer. A store that cannot be
    /// read is `Unavailable`, never "active".
    fn states(
        &self,
        tenant_id: &str,
        agent_ids: &[String],
    ) -> impl Future<Output = Result<BTreeMap<String, AgentState>, PortError>> + Send;

    /// The stored row, if the agent ever had its state changed.
    fn current(
        &self,
        tenant_id: &str,
        agent_id: &str,
    ) -> impl Future<Output = Result<Option<StoredAgentState>, PortError>> + Send;

    /// Applies `change` atomically under [`AgentStateChange::check`], and
    /// appends it to the history; the stored row after it. Concurrent
    /// changes to one agent are serialised. Used to **tighten**: stopping
    /// never waits on the evidence chain (its record follows, written by the
    /// reconciler if not at once).
    fn set(
        &self,
        change: AgentStateChange,
    ) -> impl Future<Output = Result<StoredAgentState, PortError>> + Send;

    /// As [`Self::set`], and writes the change's evidence record in the same
    /// transaction: either both happen or neither does. Used to **loosen**.
    fn set_recorded(
        &self,
        change: AgentStateChange,
        recording: Recording<'_>,
    ) -> impl Future<Output = Result<(StoredAgentState, AgentStateRecord), PortError>> + Send;

    /// Changes of every tenant strictly after `after` (all of them for
    /// `None`), in cursor order, at most `limit`: the evidence reconciler
    /// finds changes whose record is missing.
    fn changes_after(
        &self,
        after: Option<AgentChangeCursor>,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<StoredAgentChange>, PortError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ErrorClass;

    fn change(to: AgentState, by: &str, approved: Option<&str>) -> AgentStateChange {
        AgentStateChange {
            tenant_id: "t".into(),
            agent_id: "a".into(),
            to,
            reason_code: ReasonCode::RogueBehaviour,
            note: "outside its task".into(),
            changed_by: by.into(),
            approved_by: approved.map(String::from),
            change_request_id: None,
            at: DateTime::from_timestamp(1_790_000_000, 0).unwrap(),
        }
    }

    #[test]
    fn the_rules_every_store_applies() {
        use AgentState::*;
        let ok = |c: AgentStateChange, from| assert_eq!(c.check(from), Ok(()));
        let class = |c: AgentStateChange, from| c.check(from).unwrap_err().class;
        ok(change(Quarantined, "ops-1", None), Active);
        ok(change(Revoked, "ops-1", None), Quarantined);
        ok(change(Active, "ops-1", Some("ops-2")), Quarantined);
        // Tightening takes no approver; loosening needs a different one.
        assert_eq!(
            class(change(Restricted, "ops-1", Some("ops-2")), Active),
            ErrorClass::Invalid
        );
        assert_eq!(
            class(change(Active, "ops-1", None), Restricted),
            ErrorClass::Rejected
        );
        assert_eq!(
            class(change(Active, "ops-1", Some("ops-1")), Restricted),
            ErrorClass::Rejected
        );
        assert_eq!(
            class(change(Active, "ops-1", Some("")), Restricted),
            ErrorClass::Rejected
        );
        // Revoked is final; no change to the state it is in.
        assert_eq!(
            class(change(Active, "ops-1", Some("ops-2")), Revoked),
            ErrorClass::Rejected
        );
        assert_eq!(
            class(change(Quarantined, "ops-1", None), Quarantined),
            ErrorClass::Rejected
        );
        // A note is optional, and plain.
        let mut c = change(Quarantined, "ops-1", None);
        c.note.clear();
        ok(c, Active);
        for bad in ["line\nbreak", &"x".repeat(257)] {
            let mut c = change(Quarantined, "ops-1", None);
            c.note = bad.to_string();
            assert_eq!(class(c, Active), ErrorClass::Invalid, "{bad:?}");
        }
    }
}

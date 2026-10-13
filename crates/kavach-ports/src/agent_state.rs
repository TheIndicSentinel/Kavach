//! Agent risk state persistence (ADR-013 §1).

use std::collections::BTreeMap;
use std::future::Future;

use chrono::{DateTime, Utc};
pub use kavach_domain::AgentState;

use crate::PortError;

/// Longest reason a change may carry.
pub const MAX_REASON_CHARS: usize = 256;

/// One agent's current state and the change that made it so.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredAgentState {
    pub tenant_id: String,
    pub agent_id: String,
    pub state: AgentState,
    pub reason: String,
    pub changed_by: String,
    /// The second principal, for a change that loosens.
    pub approved_by: Option<String>,
    pub changed_at: DateTime<Utc>,
}

/// A request to move an agent to `to`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentStateChange {
    pub tenant_id: String,
    pub agent_id: String,
    pub to: AgentState,
    /// Why. Plain text, 1 to [`MAX_REASON_CHARS`] characters, no control
    /// characters.
    pub reason: String,
    pub changed_by: String,
    /// Required, and a principal other than `changed_by`, when the change
    /// loosens (ADR-013 §3).
    pub approved_by: Option<String>,
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
    /// - A reason is required.
    pub fn check(&self, current: AgentState) -> Result<(), PortError> {
        if self.tenant_id.is_empty() || self.agent_id.is_empty() || self.changed_by.is_empty() {
            return Err(PortError::invalid(
                "tenant, agent and principal are required",
            ));
        }
        let reason = self.reason.trim();
        if reason.is_empty()
            || self.reason.chars().count() > MAX_REASON_CHARS
            || self.reason.chars().any(char::is_control)
        {
            return Err(PortError::invalid(format!(
                "a reason of 1 to {MAX_REASON_CHARS} characters, without control characters, \
                 is required"
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

    /// Applies `change` atomically under [`AgentStateChange::check`]; the
    /// stored row after it. Concurrent changes to one agent are serialised.
    fn set(
        &self,
        change: AgentStateChange,
    ) -> impl Future<Output = Result<StoredAgentState, PortError>> + Send;
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
            reason: "rogue behaviour".into(),
            changed_by: by.into(),
            approved_by: approved.map(String::from),
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
        // A reason is required and plain.
        for bad in ["", "   ", "line\nbreak", &"x".repeat(257)] {
            let mut c = change(Quarantined, "ops-1", None);
            c.reason = bad.to_string();
            assert_eq!(class(c, Active), ErrorClass::Invalid, "{bad:?}");
        }
    }
}

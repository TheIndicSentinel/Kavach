//! Agent risk state (ADR-003 §6, ADR-013). No I/O.

use serde::{Deserialize, Serialize};

/// What an agent may do at all, whatever its mandates say.
///
/// - `Active`: as the mandates say.
/// - `Restricted`: reads within the mandate only; nothing with an external
///   effect (no contact, no call, no proposal, no status change).
/// - `Quarantined`: nothing. Its mandates, and those delegated from them,
///   authorise nothing while it is, and work again when it is reinstated.
/// - `Revoked`: nothing, for good. Its mandates are revoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentState {
    Active,
    Restricted,
    Quarantined,
    Revoked,
}

impl AgentState {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Restricted => "restricted",
            Self::Quarantined => "quarantined",
            Self::Revoked => "revoked",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        [
            Self::Active,
            Self::Restricted,
            Self::Quarantined,
            Self::Revoked,
        ]
        .into_iter()
        .find(|state| state.as_str() == s)
    }

    /// Quarantined or revoked: the agent, and every mandate it holds, may
    /// do nothing.
    #[must_use]
    pub fn is_stopped(self) -> bool {
        matches!(self, Self::Quarantined | Self::Revoked)
    }

    /// Whether a change from `self` to `to` is a way to **loosen**: it
    /// gives back authority, so it needs a second principal (ADR-013 §3).
    #[must_use]
    pub fn loosens_to(self, to: Self) -> bool {
        to < self
    }
}

/// Why an agent's state was changed, from a closed set. This is what the
/// evidence chain carries: the chain cannot be erased, so it never holds an
/// operator's free text (which could name a borrower). The free text stays
/// in the store and the admin audit log, and the chain holds a keyed digest
/// of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonCode {
    RogueBehaviour,
    CompromiseSuspected,
    PolicyViolation,
    CustomerComplaint,
    OperatorRequest,
    Reviewed,
    Other,
}

impl ReasonCode {
    pub const ALL: [Self; 7] = [
        Self::RogueBehaviour,
        Self::CompromiseSuspected,
        Self::PolicyViolation,
        Self::CustomerComplaint,
        Self::OperatorRequest,
        Self::Reviewed,
        Self::Other,
    ];

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RogueBehaviour => "rogue_behaviour",
            Self::CompromiseSuspected => "compromise_suspected",
            Self::PolicyViolation => "policy_violation",
            Self::CustomerComplaint => "customer_complaint",
            Self::OperatorRequest => "operator_request",
            Self::Reviewed => "reviewed",
            Self::Other => "other",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.as_str() == s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip_and_order_is_by_severity() {
        for s in [
            AgentState::Active,
            AgentState::Restricted,
            AgentState::Quarantined,
            AgentState::Revoked,
        ] {
            assert_eq!(AgentState::parse(s.as_str()), Some(s));
        }
        assert_eq!(AgentState::parse("Active"), None);
        for code in ReasonCode::ALL {
            assert_eq!(ReasonCode::parse(code.as_str()), Some(code));
        }
        assert_eq!(ReasonCode::parse("free text"), None);
        assert!(AgentState::Active < AgentState::Restricted);
        assert!(AgentState::Restricted < AgentState::Quarantined);
        assert!(AgentState::Quarantined < AgentState::Revoked);
        assert!(AgentState::Quarantined.loosens_to(AgentState::Active));
        assert!(!AgentState::Active.loosens_to(AgentState::Restricted));
        assert!(AgentState::Quarantined.is_stopped() && !AgentState::Restricted.is_stopped());
    }
}

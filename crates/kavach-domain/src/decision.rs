//! Four-value decision enum — frozen per ADR-001.

use serde::{Deserialize, Serialize};
use std::fmt;

use crate::response::GovernanceMode;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Decision {
    Pass,
    Alert,
    Block,
    HumanReview,
}

impl Decision {
    /// Most restrictive decision wins when aggregating rule hits.
    #[must_use]
    pub fn severity_rank(self) -> u8 {
        match self {
            Self::Pass => 0,
            Self::Alert => 1,
            Self::HumanReview => 2,
            Self::Block => 3,
        }
    }

    #[must_use]
    pub fn max(a: Self, b: Self) -> Self {
        if a.severity_rank() >= b.severity_rank() {
            a
        } else {
            b
        }
    }
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => write!(f, "PASS"),
            Self::Alert => write!(f, "ALERT"),
            Self::Block => write!(f, "BLOCK"),
            Self::HumanReview => write!(f, "HUMAN_REVIEW"),
        }
    }
}

/// Map policy outcome to sync RPC returned decision per ADR-001 §5.
#[must_use]
pub fn map_returned_decision(
    policy_decision: Decision,
    governance_mode: GovernanceMode,
    request_valid: bool,
) -> Decision {
    if !request_valid {
        // Caller receives 4xx — not represented as Decision in body.
        return policy_decision;
    }

    match governance_mode {
        GovernanceMode::Enforce => policy_decision,
        GovernanceMode::Shadow => Decision::Pass,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shadow_sync_masks_non_pass_policy() {
        assert_eq!(
            map_returned_decision(Decision::Block, GovernanceMode::Shadow, true),
            Decision::Pass
        );
        assert_eq!(
            map_returned_decision(Decision::HumanReview, GovernanceMode::Shadow, true),
            Decision::Pass
        );
    }

    #[test]
    fn enforce_returns_policy_decision() {
        assert_eq!(
            map_returned_decision(Decision::Alert, GovernanceMode::Enforce, true),
            Decision::Alert
        );
    }
}

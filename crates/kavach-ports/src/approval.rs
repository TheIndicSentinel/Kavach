//! Human-review approval record contract (PRD D17 / FR-6).
//!
//! This defines the record shape, structural checks, and durable-store port.
//! Storage adapters enforce one-time consumption. The approval service that
//! authenticates reviewers, verifies step-up, and wires consumption to
//! authorization and credential issuance is still pending.

use std::future::Future;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::PortError;

/// The reviewer's explicit decision for one rendered action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewDecision {
    Approve,
    Reject,
}

impl ReviewDecision {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Reject => "reject",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "approve" => Some(Self::Approve),
            "reject" => Some(Self::Reject),
            _ => None,
        }
    }
}

/// One human decision tied to one action digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewApprovalRecord {
    pub tenant_id: String,
    pub approval_id: String,
    pub action_hash: String,
    /// The action shown to the person at approval time. It must be rendered
    /// from the same extracted action used to produce `action_hash`.
    pub rendered_action: String,
    /// Source-qualified identity of the authenticated human approver.
    pub approver: String,
    /// Opaque reference returned by a step-up provider after verification.
    pub step_up_ref: String,
    pub decision: ReviewDecision,
    /// Set only for an approved record. The eventual store/broker must make
    /// this credential single-use.
    pub single_use_credential_id: Option<String>,
    pub expires: DateTime<Utc>,
}

impl ReviewApprovalRecord {
    /// Checks the record shape, but does not prove authentication or step-up.
    pub fn validate(&self) -> Result<(), PortError> {
        if self.tenant_id.is_empty()
            || self.approval_id.is_empty()
            || self.rendered_action.is_empty()
            || self.approver.is_empty()
            || self.step_up_ref.is_empty()
        {
            return Err(PortError::invalid(
                "human-review approval fields must not be empty",
            ));
        }
        if !self.action_hash.starts_with("sha256-action-v1:")
            || self.action_hash.len() != "sha256-action-v1:".len() + 64
            || !self.action_hash["sha256-action-v1:".len()..]
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(PortError::invalid(
                "action_hash must be a version 1 SHA-256 action digest",
            ));
        }
        match (self.decision, self.single_use_credential_id.as_deref()) {
            (ReviewDecision::Approve, Some(id)) if !id.is_empty() => Ok(()),
            (ReviewDecision::Reject, None) => Ok(()),
            (ReviewDecision::Approve, _) => Err(PortError::invalid(
                "an approved record requires a single-use credential id",
            )),
            (ReviewDecision::Reject, Some(_)) => Err(PortError::invalid(
                "a rejected record cannot carry a credential id",
            )),
        }
    }

    /// Checks that this is a current, approved record for the exact tenant
    /// and action. Callers must still atomically consume the credential id;
    /// this pure check cannot enforce replay resistance.
    pub fn validate_scope_and_lifetime(
        &self,
        tenant_id: &str,
        action_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<(), PortError> {
        self.validate()?;
        if self.tenant_id != tenant_id || self.action_hash != action_hash {
            return Err(PortError::rejected(
                "human-review approval is bound to a different tenant or action",
            ));
        }
        if self.decision != ReviewDecision::Approve {
            return Err(PortError::rejected("human-review approval was rejected"));
        }
        if self.expires <= now {
            return Err(PortError::rejected("human-review approval has expired"));
        }
        Ok(())
    }
}

/// Durable storage for completed human-review decisions (PRD FR-6).
///
/// Implementations preserve records and atomically return an approved record
/// at most once. The caller supplies `now` from Kavach's trusted clock.
pub trait ReviewApprovalStore: Send + Sync {
    fn insert(
        &self,
        record: ReviewApprovalRecord,
    ) -> impl Future<Output = Result<(), PortError>> + Send;

    /// Atomically consumes a live approval for exactly this tenant and action.
    /// Missing, rejected, expired, mismatched, or previously consumed records
    /// return `Ok(None)`; storage failures return `Err` and must fail closed.
    fn consume(
        &self,
        tenant_id: &str,
        approval_id: &str,
        action_hash: &str,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<Option<ReviewApprovalRecord>, PortError>> + Send;
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    fn record() -> ReviewApprovalRecord {
        ReviewApprovalRecord {
            tenant_id: "tenant-1".into(),
            approval_id: "approval-1".into(),
            action_hash: format!("sha256-action-v1:{}", "a".repeat(64)),
            rendered_action: "Propose a 35% waiver for borrower ref:B-9382".into(),
            approver: "oidc:https://idp.example#user-1".into(),
            step_up_ref: "webauthn:assertion-1".into(),
            decision: ReviewDecision::Approve,
            single_use_credential_id: Some("credential-1".into()),
            expires: Utc.with_ymd_and_hms(2026, 11, 17, 12, 5, 0).unwrap(),
        }
    }

    #[test]
    fn accepts_only_well_formed_approval_records() {
        assert!(record().validate().is_ok());
        let mut bad = record();
        bad.action_hash = "sha256:unversioned".into();
        assert!(bad.validate().is_err());
        let mut bad = record();
        bad.single_use_credential_id = None;
        assert!(bad.validate().is_err());
        let mut bad = record();
        bad.decision = ReviewDecision::Reject;
        assert!(bad.validate().is_err());
    }

    #[test]
    fn approval_matches_only_its_tenant_action_and_live_window() {
        let now = Utc.with_ymd_and_hms(2026, 11, 17, 12, 0, 0).unwrap();
        let approval = record();
        assert!(approval
            .validate_scope_and_lifetime("tenant-1", &approval.action_hash, now)
            .is_ok());
        assert!(approval
            .validate_scope_and_lifetime("tenant-2", &approval.action_hash, now)
            .is_err());
        assert!(approval
            .validate_scope_and_lifetime("tenant-1", "sha256-action-v1:other", now)
            .is_err());
        assert!(approval
            .validate_scope_and_lifetime("tenant-1", &approval.action_hash, approval.expires)
            .is_err());
    }

    #[test]
    fn rejection_never_matches_as_an_approval() {
        let mut rejected = record();
        rejected.decision = ReviewDecision::Reject;
        rejected.single_use_credential_id = None;
        let now = Utc.with_ymd_and_hms(2026, 11, 17, 12, 0, 0).unwrap();
        assert!(rejected.validate().is_ok());
        assert!(rejected
            .validate_scope_and_lifetime("tenant-1", &rejected.action_hash, now)
            .is_err());
    }
}

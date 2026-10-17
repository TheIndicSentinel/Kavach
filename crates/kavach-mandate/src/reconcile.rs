//! Snapshot reconciliation: the lender's list of closed loans against the
//! authority Kavach still holds for them.
//!
//! Kavach revokes on the events it receives. A payment or dispute event that
//! never arrives leaves a mandate live, and no transaction design can fix
//! that, because the cause is outside Kavach. The lender (or a test fixture)
//! supplies the loans it considers closed; this finds the live authority for
//! them. It **only reports**: it revokes nothing and has no authority to. The
//! remedy is the lender resending the signed event (which revokes through the
//! normal path) or an operator stopping the agent.

use chrono::{DateTime, Duration, Utc};
use kavach_ports::{MandateStore, PortError, TimeSource};

use crate::service::{MandateService, REVOCATION_SKEW_MARGIN_SECONDS};

/// Why the lender considers the loan closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClosedState {
    Paid,
    Disputed,
}

/// One loan the lender reports closed, as of `closed_at`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosedRecord {
    pub system: String,
    pub record_ref: String,
    pub state: ClosedState,
    pub closed_at: DateTime<Utc>,
}

/// What kind of live authority was found for a closed loan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingKind {
    /// Authority that should not exist: for a paid loan, a mandate processed
    /// at or before the closure (within the skew margin) and never revoked;
    /// for a disputed loan, any live mandate (a dispute holds the loan, so
    /// none should have been issued and none should have survived). The
    /// payment or dispute event was most likely lost.
    ShouldHaveBeenRevoked,
    /// A paid loan with a mandate processed after the closure. Usually a new
    /// default (legitimate); it may also be an old default processed late.
    /// Reported for the lender to confirm, not as a defect.
    IssuedAfterClosure,
}

/// A live root mandate for a loan the lender reports closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub kind: FindingKind,
    pub system: String,
    pub record_ref: String,
    pub state: ClosedState,
    pub mandate_id: String,
    pub holder: String,
    /// When Kavach issued it (`nbf`).
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// The result of one reconciliation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reconciliation {
    pub checked: usize,
    pub findings: Vec<Finding>,
}

impl Reconciliation {
    /// Findings that are a defect (`ShouldHaveBeenRevoked`).
    #[must_use]
    pub fn mismatches(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.kind == FindingKind::ShouldHaveBeenRevoked)
            .count()
    }
}

impl<K, R, C, S, E, T> MandateService<K, R, C, S, E, T>
where
    K: kavach_ports::KeyProvider,
    R: kavach_ports::ReplayGuard,
    C: kavach_ports::ConsentSource,
    S: MandateStore,
    E: kavach_ports::EventBus,
    T: TimeSource,
{
    /// The live root mandates held for each loan in `closed` (the stack's
    /// tenant). Expired mandates are not live. A store that cannot be read
    /// is an error, never an empty result.
    pub async fn reconcile_closed(
        &self,
        tenant_id: &str,
        closed: &[ClosedRecord],
    ) -> Result<Reconciliation, PortError> {
        let now = self.clock().now().utc;
        let margin = Duration::seconds(REVOCATION_SKEW_MARGIN_SECONDS);
        let mut findings = Vec::new();
        for record in closed {
            let roots = self
                .store()
                .live_roots_for_record(tenant_id, &record.system, &record.record_ref)
                .await?;
            for root in roots.iter().filter(|r| r.mandate.exp > now) {
                let kind = match record.state {
                    ClosedState::Disputed => FindingKind::ShouldHaveBeenRevoked,
                    ClosedState::Paid if root.mandate.nbf <= record.closed_at + margin => {
                        FindingKind::ShouldHaveBeenRevoked
                    }
                    ClosedState::Paid => FindingKind::IssuedAfterClosure,
                };
                findings.push(Finding {
                    kind,
                    system: record.system.clone(),
                    record_ref: record.record_ref.clone(),
                    state: record.state,
                    mandate_id: root.mandate.id.clone(),
                    holder: root.mandate.holder.clone(),
                    issued_at: root.mandate.nbf,
                    expires_at: root.mandate.exp,
                });
            }
        }
        Ok(Reconciliation {
            checked: closed.len(),
            findings,
        })
    }
}

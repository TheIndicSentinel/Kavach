use std::future::Future;

use kavach_domain::mandate::{ConsentRecord, Mandate, MandateStatus, RevocationReason};

use crate::error::PortError;

/// A mandate as persisted: the domain value, its signed token and its status.
/// Status is authoritative here, not in the token (ADR-004 §3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMandate {
    pub mandate: Mandate,
    pub token: String,
    pub status: MandateStatus,
    pub revoked_reason: Option<RevocationReason>,
}

/// Mandate persistence (ADR-004, ADR-006 §4).
pub trait MandateStore: Send + Sync {
    /// Inserts a new mandate. An existing id → `Rejected`.
    fn insert(&self, record: StoredMandate) -> impl Future<Output = Result<(), PortError>> + Send;

    fn get(
        &self,
        tenant_id: &str,
        id: &str,
    ) -> impl Future<Output = Result<Option<StoredMandate>, PortError>> + Send;

    /// Marks a mandate revoked. Returns `false` if it was already revoked.
    fn revoke(
        &self,
        tenant_id: &str,
        id: &str,
        reason: RevocationReason,
    ) -> impl Future<Output = Result<bool, PortError>> + Send;

    /// Ids of the direct children of `parent_id`.
    fn children(
        &self,
        tenant_id: &str,
        parent_id: &str,
    ) -> impl Future<Output = Result<Vec<String>, PortError>> + Send;
}

/// Domain events published for caches, credential revocation and audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainEvent {
    MandateIssued {
        tenant_id: String,
        mandate_id: String,
    },
    MandateRevoked {
        tenant_id: String,
        mandate_id: String,
        reason: RevocationReason,
    },
}

/// Publishes domain events (Postgres outbox later; in-memory for M1).
pub trait EventBus: Send + Sync {
    fn publish(&self, event: DomainEvent) -> impl Future<Output = Result<(), PortError>> + Send;
}

/// Consent records the mandate relies on (fixture in the MVP; Account
/// Aggregator / DPDP consent manager adapters in Stage 2).
pub trait ConsentSource: Send + Sync {
    fn get(
        &self,
        tenant_id: &str,
        consent_id: &str,
    ) -> impl Future<Output = Result<Option<ConsentRecord>, PortError>> + Send;
}

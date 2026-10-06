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

/// A revocation made by a system-of-record event (ADR-012), kept so that
/// the same event again is answered with the same result and the same id
/// with other content is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRevocation {
    pub tenant_id: String,
    pub system: String,
    pub event_id: String,
    /// SHA-256 of the event's content, to tell a retry from a reuse.
    pub content_sha256: String,
    pub event_type: String,
    pub record_ref: String,
    pub occurred_at: chrono::DateTime<chrono::Utc>,
    /// Every mandate whose status changed (roots and their delegations).
    pub revoked: Vec<String>,
}

/// Mandate persistence (ADR-004, ADR-006 §4).
///
/// **Invariant:** a mandate is `Active` only if every ancestor is `Active`.
/// `insert_child` and `revoke_tree` maintain it atomically: a child is never
/// inserted under a revoked parent, and revoking a mandate revokes its whole
/// subtree in one operation, so concurrent delegation and revocation cannot
/// leave an active child below a revoked parent. Expiry is not stored status;
/// verification checks it on every ancestor (ADR-011).
pub trait MandateStore: Send + Sync {
    /// Inserts a root mandate (`parent_id` must be `None`). An existing id
    /// → `Rejected`.
    fn insert(&self, record: StoredMandate) -> impl Future<Output = Result<(), PortError>> + Send;

    /// Inserts a delegated mandate only if its parent (`mandate.parent_id`)
    /// exists in the same tenant and is `Active`, atomically with that check.
    /// Otherwise → `Rejected`.
    fn insert_child(
        &self,
        record: StoredMandate,
    ) -> impl Future<Output = Result<(), PortError>> + Send;

    fn get(
        &self,
        tenant_id: &str,
        id: &str,
    ) -> impl Future<Output = Result<Option<StoredMandate>, PortError>> + Send;

    /// The root mandate issued from system-of-record event `event_id` of
    /// `system`, if any (idempotent event retries).
    fn root_for_event(
        &self,
        tenant_id: &str,
        system: &str,
        event_id: &str,
    ) -> impl Future<Output = Result<Option<StoredMandate>, PortError>> + Send;

    /// The mandates above `id`, nearest parent first, in one call. Stops at a
    /// root, a missing parent, or after `limit` entries (bounding a corrupted
    /// cycle); callers compare the result with the mandate's depth.
    fn ancestors(
        &self,
        tenant_id: &str,
        id: &str,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<StoredMandate>, PortError>> + Send;

    /// Revokes `id` and every descendant that is not yet revoked, atomically.
    /// Returns the mandates whose status changed with their reason (`reason`
    /// for `id`, `ParentRevoked` below it). Unknown `id` → `Rejected`.
    fn revoke_tree(
        &self,
        tenant_id: &str,
        id: &str,
        reason: RevocationReason,
    ) -> impl Future<Output = Result<Vec<(String, RevocationReason)>, PortError>> + Send;

    /// The active root mandates issued from events of `system` about the
    /// record `record_ref` (a loan), oldest first (ADR-012).
    fn live_roots_for_record(
        &self,
        tenant_id: &str,
        system: &str,
        record_ref: &str,
    ) -> impl Future<Output = Result<Vec<StoredMandate>, PortError>> + Send;

    /// Keeps a revocation's result. An existing `(tenant, system,
    /// event_id)` → `Rejected`.
    fn record_revocation(
        &self,
        revocation: StoredRevocation,
    ) -> impl Future<Output = Result<(), PortError>> + Send;

    /// The revocation event `event_id` of `system` made, if any.
    fn revocation_for_event(
        &self,
        tenant_id: &str,
        system: &str,
        event_id: &str,
    ) -> impl Future<Output = Result<Option<StoredRevocation>, PortError>> + Send;
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

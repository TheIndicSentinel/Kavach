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
    /// The event's digest (`sha256-jcs-v1:<hex>`; a bare 64-hex SHA-256 in
    /// a row written before that form), to tell a retry from a reuse.
    pub event_digest: String,
    pub event_type: String,
    pub record_ref: String,
    pub occurred_at: chrono::DateTime<chrono::Utc>,
    /// Every mandate whose status changed (roots and their delegations).
    pub revoked: Vec<String>,
    /// When Kavach revoked them (trusted time, whole microseconds).
    pub revoked_at: chrono::DateTime<chrono::Utc>,
    /// Whether the clock was synchronised when it was applied; `None` for
    /// a row written before this was recorded (unknown).
    pub clock_synced: Option<bool>,
}

impl StoredRevocation {
    /// Its place in [`MandateStore::revocations_after`] order.
    #[must_use]
    pub fn cursor(&self) -> RevocationCursor {
        RevocationCursor {
            revoked_at: self.revoked_at,
            tenant_id: self.tenant_id.clone(),
            system: self.system.clone(),
            event_id: self.event_id.clone(),
        }
    }
}

/// A revocation to apply (ADR-012, B3): everything the store needs to
/// revoke and record in one step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationApply {
    pub tenant_id: String,
    pub system: String,
    pub event_id: String,
    /// The event's digest (`sha256-jcs-v1:<hex>`), stored with the result.
    pub event_digest: String,
    /// The same content in the legacy bare form, so a row written before
    /// that form is recognised as a retry.
    pub legacy_digest: String,
    pub event_type: String,
    pub record_ref: String,
    pub occurred_at: chrono::DateTime<chrono::Utc>,
    pub reason: RevocationReason,
    /// When Kavach revoked (trusted time, whole microseconds).
    pub revoked_at: chrono::DateTime<chrono::Utc>,
    /// Whether the clock was synchronised when this was applied.
    pub clock_synced: bool,
    /// Roots whose source time (the issuing event's `occurred_at`, or `nbf`
    /// for a row that has none) is at or before this are revoked: the
    /// event's `occurred_at` plus the skew margin (B2).
    pub reach_until: chrono::DateTime<chrono::Utc>,
}

/// The time a root mandate's revocation scope is measured by (B2): when the
/// source says the issuing event occurred, or `nbf` (when Kavach processed
/// it) for a root written before the source time was kept. **The one rule**
/// the revocation path and snapshot reconciliation both use, so detection
/// and enforcement cannot drift apart.
#[must_use]
pub fn scope_time(
    source_occurred_at: Option<chrono::DateTime<chrono::Utc>>,
    nbf: chrono::DateTime<chrono::Utc>,
) -> chrono::DateTime<chrono::Utc> {
    source_occurred_at.unwrap_or(nbf)
}

/// A live root with the source time its scope is measured by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedRoot {
    pub mandate: StoredMandate,
    /// The issuing event's `occurred_at`, `None` for a root written before it
    /// was kept (scoped by `nbf`; see [`scope_time`]).
    pub source_occurred_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl ScopedRoot {
    /// [`scope_time`] for this root.
    #[must_use]
    pub fn scope_time(&self) -> chrono::DateTime<chrono::Utc> {
        scope_time(self.source_occurred_at, self.mandate.mandate.nbf)
    }
}

/// When a record is closed to new authority (B2): by a recorded payment
/// whose time the event is not after, or by a dispute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClosureRule {
    /// A recorded revocation closes the record to events that occurred at
    /// or before `min(occurred_at, revoked_at + this)`: a source clock that
    /// runs ahead cannot hold a record closed for long.
    pub future_allowance_seconds: i64,
    /// Events within this much *after* the barrier are also refused: when
    /// the order of two events is within the skew, contact stops.
    pub skew_margin_seconds: i64,
}

/// What [`MandateStore::apply_revocation`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedRevocation {
    /// The revocation as stored (the first one, for a retry).
    pub stored: StoredRevocation,
    /// The mandates whose status changed now, with their reason: empty
    /// for a retry.
    pub changed: Vec<(String, RevocationReason)>,
    /// The event had been applied before; nothing was revoked now.
    pub replayed: bool,
}

/// A place in the order of revocations: by time, then tenant, system and
/// event id. Ordered the same way, so paging resumes exactly after it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RevocationCursor {
    pub revoked_at: chrono::DateTime<chrono::Utc>,
    pub tenant_id: String,
    pub system: String,
    pub event_id: String,
}

impl RevocationCursor {
    /// Before every revocation at or after `t`.
    #[must_use]
    pub fn at(t: chrono::DateTime<chrono::Utc>) -> Self {
        Self {
            revoked_at: t,
            tenant_id: String::new(),
            system: String::new(),
            event_id: String::new(),
        }
    }
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

    /// Inserts a root mandate unless the record is closed, atomically with
    /// that check (under the same lock `apply_revocation` takes). `source_
    /// occurred_at` is the issuing event's `occurred_at`, kept to scope a
    /// later revocation. Closed → `Rejected` with the reason: a recorded
    /// `loan.disputed` holds the record whatever the time; otherwise the
    /// record is closed to an event at or before
    /// `max(min(occurred_at, revoked_at + future_allowance))` of its
    /// recorded revocations, plus the skew margin.
    fn insert_unless_closed(
        &self,
        record: StoredMandate,
        source_occurred_at: chrono::DateTime<chrono::Utc>,
        rule: ClosureRule,
    ) -> impl Future<Output = Result<(), PortError>> + Send;

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

    /// [`MandateStore::live_roots_for_record`] with each root's source time,
    /// for snapshot reconciliation: the same roots, scoped by the same rule
    /// (`scope_time`) the revocation path uses.
    fn live_roots_scoped(
        &self,
        tenant_id: &str,
        system: &str,
        record_ref: &str,
    ) -> impl Future<Output = Result<Vec<ScopedRoot>, PortError>> + Send;

    /// The ids of the active mandates `holder` holds, roots and delegated
    /// children alike, oldest first (ADR-013: revoking an agent revokes
    /// them). Expired mandates that are still `Active` in the store are
    /// included: expiry is not stored status.
    fn active_held_by(
        &self,
        tenant_id: &str,
        holder: &str,
    ) -> impl Future<Output = Result<Vec<String>, PortError>> + Send;

    /// Applies a revoking event **atomically**: revokes every active root
    /// mandate of `(tenant, system, record_ref)` with `nbf <= occurred_at`
    /// and everything delegated from it, and records the revocation, all
    /// or nothing. A crash leaves either the whole revocation or none of
    /// it, so a retry always completes it.
    ///
    /// Idempotent by `(tenant, system, event_id)`: the same event again
    /// (either digest form) returns the stored revocation with `replayed`
    /// and changes nothing; the same id with another digest → `Rejected`
    /// ("different content") and nothing is revoked.
    fn apply_revocation(
        &self,
        request: RevocationApply,
    ) -> impl Future<Output = Result<AppliedRevocation, PortError>> + Send;

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

    /// Revocations of every tenant strictly after `after` (all of them for
    /// `None`), in cursor order, at most `limit` (the evidence reconciler).
    fn revocations_after(
        &self,
        after: Option<RevocationCursor>,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<StoredRevocation>, PortError>> + Send;
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

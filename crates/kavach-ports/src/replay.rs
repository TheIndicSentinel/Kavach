use std::future::Future;

use chrono::{DateTime, Utc};

use crate::error::PortError;

/// Records one-time identifiers (system-of-record event ids, nonces) so a
/// replayed message is rejected (ADR-004 §4).
pub trait ReplayGuard: Send + Sync {
    /// Records `key` for `tenant_id` until `expires_at`. Returns `Rejected` if
    /// the key is already recorded and has not expired at `now`.
    fn check_and_record(
        &self,
        tenant_id: &str,
        key: &str,
        now: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> impl Future<Output = Result<(), PortError>> + Send;
}

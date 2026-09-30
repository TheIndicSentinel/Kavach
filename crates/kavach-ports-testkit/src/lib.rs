//! Test doubles and conformance suites for `kavach-ports` (ADR-006 §4).
//!
//! Every adapter of a security-critical port must pass the matching suite in
//! [`conformance`]; the doubles here pass them too, so tests that use a double
//! exercise the same contract as production.

use std::collections::HashMap;
use std::future::{ready, Future};
use std::sync::Mutex;

use chrono::{DateTime, Duration, Utc};
use kavach_ports::{PortError, ReplayGuard, SyncStatus, TimeSource, TrustedNow};

/// A settable clock for tests.
#[derive(Debug)]
pub struct FakeClock {
    now: Mutex<TrustedNow>,
}

impl FakeClock {
    pub fn new(utc: DateTime<Utc>, sync: SyncStatus) -> Self {
        Self {
            now: Mutex::new(TrustedNow { utc, sync }),
        }
    }

    /// A clock synced within 10 ms at `utc`.
    pub fn synced_at(utc: DateTime<Utc>) -> Self {
        Self::new(utc, SyncStatus::Synced { max_error_ms: 10 })
    }

    pub fn advance(&self, by: Duration) {
        let mut now = self.now.lock().expect("clock lock");
        now.utc += by;
    }

    pub fn set_sync(&self, sync: SyncStatus) {
        self.now.lock().expect("clock lock").sync = sync;
    }
}

impl TimeSource for FakeClock {
    fn now(&self) -> TrustedNow {
        *self.now.lock().expect("clock lock")
    }
}

/// In-memory replay guard.
#[derive(Debug, Default)]
pub struct InMemoryReplayGuard {
    seen: Mutex<HashMap<(String, String), DateTime<Utc>>>,
}

impl InMemoryReplayGuard {
    pub fn new() -> Self {
        Self::default()
    }

    fn check_and_record_sync(
        &self,
        tenant_id: &str,
        key: &str,
        now: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<(), PortError> {
        let mut seen = self
            .seen
            .lock()
            .map_err(|_| PortError::unavailable("replay guard lock poisoned"))?;
        seen.retain(|_, exp| *exp > now);
        let id = (tenant_id.to_string(), key.to_string());
        if seen.contains_key(&id) {
            return Err(PortError::rejected(format!("replayed identifier: {key}")));
        }
        seen.insert(id, expires_at);
        Ok(())
    }
}

impl ReplayGuard for InMemoryReplayGuard {
    fn check_and_record(
        &self,
        tenant_id: &str,
        key: &str,
        now: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> impl Future<Output = Result<(), PortError>> + Send {
        ready(self.check_and_record_sync(tenant_id, key, now, expires_at))
    }
}

/// Shared conformance suites. They panic on the first violated property.
pub mod conformance {
    use chrono::{Duration, Utc};
    use kavach_ports::{verify_ed25519, ErrorClass, KeyProvider, ReplayGuard};

    /// `provider` must already hold a key named `kid`.
    pub async fn key_provider<K: KeyProvider>(provider: &K, kid: &str) {
        let message = b"kavach conformance message";
        let signature = provider.sign(kid, message).await.expect("sign");
        let public = provider.public_key(kid).await.expect("public key");
        assert_eq!(public.kid, kid);
        verify_ed25519(&public, message, &signature).expect("signature verifies");

        let tampered = verify_ed25519(&public, b"different message", &signature).unwrap_err();
        assert_eq!(tampered.class, ErrorClass::Rejected, "tampered message");

        let again = provider.sign(kid, message).await.expect("sign again");
        assert_eq!(signature, again, "ed25519 signatures are deterministic");

        let missing = "conformance-missing-key";
        assert_eq!(
            provider.sign(missing, message).await.unwrap_err().class,
            ErrorClass::Rejected
        );
        assert_eq!(
            provider.public_key(missing).await.unwrap_err().class,
            ErrorClass::Rejected
        );
    }

    /// Replays are rejected per tenant until expiry.
    pub async fn replay_guard<R: ReplayGuard>(guard: &R) {
        let now = Utc::now();
        let exp = now + Duration::minutes(5);
        guard
            .check_and_record("t1", "evt-1", now, exp)
            .await
            .expect("first use");
        let replay = guard
            .check_and_record("t1", "evt-1", now, exp)
            .await
            .unwrap_err();
        assert_eq!(replay.class, ErrorClass::Rejected);
        guard
            .check_and_record("t2", "evt-1", now, exp)
            .await
            .expect("tenants are isolated");
        guard
            .check_and_record(
                "t1",
                "evt-1",
                exp + Duration::seconds(1),
                exp + Duration::minutes(5),
            )
            .await
            .expect("expired identifiers may be recorded again");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn in_memory_replay_guard_conforms() {
        conformance::replay_guard(&InMemoryReplayGuard::new()).await;
    }

    #[test]
    fn fake_clock_advances_and_changes_sync() {
        let start = Utc::now();
        let clock = FakeClock::synced_at(start);
        clock.advance(Duration::minutes(3));
        assert_eq!(clock.now().utc, start + Duration::minutes(3));
        clock.set_sync(SyncStatus::Unsynced);
        assert!(clock.now().require_synced(1000).is_err());
    }
}

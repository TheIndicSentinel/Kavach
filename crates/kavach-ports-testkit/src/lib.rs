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

/// `MandateStore` contract (ADR-011). Written to the contract, not to one
/// implementation: every store — in-memory now, Postgres in H5 — must pass.
pub mod mandate_store {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;

    use chrono::{Duration, TimeZone, Utc};
    use kavach_domain::mandate::{
        DelegationRules, Mandate, MandateSource, MandateStatus, RevocationReason,
    };
    use kavach_ports::{ErrorClass, MandateStore, StoredMandate};

    const TENANT: &str = "conformance";

    /// A minimal stored mandate for store tests (tenant `conformance`).
    #[must_use]
    pub fn sample(id: &str, parent: Option<&str>, depth: u8) -> StoredMandate {
        record(id, parent, depth)
    }

    fn record(id: &str, parent: Option<&str>, depth: u8) -> StoredMandate {
        let t = Utc.with_ymd_and_hms(2026, 10, 1, 5, 30, 0).unwrap();
        StoredMandate {
            mandate: Mandate {
                mv: 1,
                id: id.into(),
                tenant_id: TENANT.into(),
                issuer: "kavach".into(),
                // One source event per root (stores may enforce uniqueness).
                source: MandateSource {
                    system: "lms".into(),
                    record_ref: "r".into(),
                    event_id: format!("evt-{id}"),
                },
                principal: "p".into(),
                holder: format!("agent-{depth}"),
                subject_ref: "ref:borrower:B-1".into(),
                purpose: "loan_recovery".into(),
                consent_refs: BTreeSet::from(["C-1".to_string()]),
                actions: BTreeSet::from(["read_fields".to_string()]),
                data_fields: BTreeSet::new(),
                channels: BTreeSet::new(),
                window: None,
                ceilings: BTreeMap::new(),
                delegation: DelegationRules {
                    max_depth: 4,
                    allowed_agents: BTreeSet::new(),
                },
                parent_id: parent.map(ToString::to_string),
                depth,
                nbf: t,
                exp: t + Duration::days(1),
                nonce: id.into(),
            },
            token: format!("token-{id}"),
            status: MandateStatus::Active,
            revoked_reason: None,
        }
    }

    async fn status<S: MandateStore>(store: &S, id: &str) -> Option<MandateStatus> {
        store.get(TENANT, id).await.expect("get").map(|r| r.status)
    }

    /// A node is `Active` only if every ancestor is `Active`.
    async fn assert_invariant<S: MandateStore>(store: &S, ids: &[String]) {
        for id in ids {
            if status(store, id).await != Some(MandateStatus::Active) {
                continue;
            }
            for ancestor in store.ancestors(TENANT, id, 8).await.expect("ancestors") {
                assert_eq!(
                    ancestor.status,
                    MandateStatus::Active,
                    "active {id} below revoked {}",
                    ancestor.mandate.id
                );
            }
        }
    }

    /// Runs the whole suite against a fresh, empty store.
    pub async fn conformance<S: MandateStore + 'static>(store: Arc<S>) {
        insert_rules(&*store).await;
        ancestors_and_revoke_tree(&*store).await;
        delegation_racing_revocation(store).await;
    }

    async fn insert_rules<S: MandateStore>(store: &S) {
        store.insert(record("root", None, 0)).await.expect("root");
        let dup = store.insert(record("root", None, 0)).await.unwrap_err();
        assert_eq!(dup.class, ErrorClass::Rejected, "duplicate id");
        let err = store
            .insert(record("x", Some("root"), 1))
            .await
            .unwrap_err();
        assert_eq!(err.class, ErrorClass::Rejected, "insert takes roots only");
        let err = store.insert_child(record("y", None, 0)).await.unwrap_err();
        assert_eq!(
            err.class,
            ErrorClass::Rejected,
            "insert_child needs a parent"
        );
        let err = store
            .insert_child(record("z", Some("missing"), 1))
            .await
            .unwrap_err();
        assert_eq!(err.class, ErrorClass::Rejected, "unknown parent");
        store
            .insert_child(record("child", Some("root"), 1))
            .await
            .expect("child under active parent");
    }

    async fn ancestors_and_revoke_tree<S: MandateStore>(store: &S) {
        store
            .insert_child(record("grandchild", Some("child"), 2))
            .await
            .expect("grandchild");
        let chain: Vec<String> = store
            .ancestors(TENANT, "grandchild", 8)
            .await
            .expect("ancestors")
            .into_iter()
            .map(|r| r.mandate.id)
            .collect();
        assert_eq!(chain, ["child", "root"], "nearest parent first");
        assert_eq!(
            store
                .ancestors(TENANT, "grandchild", 1)
                .await
                .unwrap()
                .len(),
            1,
            "limit"
        );
        assert!(store.ancestors(TENANT, "root", 8).await.unwrap().is_empty());

        let mut changed = store
            .revoke_tree(TENANT, "child", RevocationReason::Dispute)
            .await
            .expect("revoke");
        changed.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            changed,
            [
                ("child".to_string(), RevocationReason::Dispute),
                ("grandchild".to_string(), RevocationReason::ParentRevoked),
            ]
        );
        assert_eq!(
            status(store, "root").await,
            Some(MandateStatus::Active),
            "only the subtree"
        );
        assert!(
            store
                .revoke_tree(TENANT, "child", RevocationReason::Manual)
                .await
                .unwrap()
                .is_empty(),
            "already revoked"
        );
        let err = store
            .insert_child(record("late", Some("child"), 2))
            .await
            .unwrap_err();
        assert_eq!(
            err.class,
            ErrorClass::Rejected,
            "no child under a revoked parent"
        );
        let err = store
            .revoke_tree(TENANT, "nope", RevocationReason::Manual)
            .await
            .unwrap_err();
        assert_eq!(err.class, ErrorClass::Rejected);
        assert_invariant(store, &["root", "child", "grandchild"].map(String::from)).await;
    }

    /// Delegation racing revocation never leaves an active mandate under a
    /// revoked one, whichever operation wins.
    async fn delegation_racing_revocation<S: MandateStore + 'static>(store: Arc<S>) {
        for round in 0..50 {
            let root = format!("race-root-{round}");
            let parent = format!("race-parent-{round}");
            let child = format!("race-child-{round}");
            store.insert(record(&root, None, 0)).await.expect("root");
            store
                .insert_child(record(&parent, Some(&root), 1))
                .await
                .expect("parent");
            let revoke = {
                let (store, root) = (Arc::clone(&store), root.clone());
                tokio::spawn(async move {
                    store
                        .revoke_tree(TENANT, &root, RevocationReason::Dispute)
                        .await
                })
            };
            let delegate = {
                let (store, parent, child) = (Arc::clone(&store), parent.clone(), child.clone());
                tokio::spawn(
                    async move { store.insert_child(record(&child, Some(&parent), 2)).await },
                )
            };
            revoke.await.expect("join").expect("revoke");
            let _ = delegate.await.expect("join");
            assert_ne!(
                status(&*store, &child).await,
                Some(MandateStatus::Active),
                "round {round}: child active under a revoked root"
            );
            assert_invariant(&*store, &[root, parent, child]).await;
        }
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

//! B3 (ADR-012 addendum): a revoking event is applied atomically, and a
//! failure before it commits leaves nothing consumed, so the retry
//! completes it. Before, each root was revoked in its own transaction and
//! the replay guard was spent first: a crash between them left some
//! mandates live and the retry looked like a replay.

mod common;

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};

use common::*;
use kavach_domain::mandate::RevocationReason;
use kavach_keys::InMemoryKeyProvider;
use kavach_mandate::jws::KeySet;
use kavach_mandate::memory::{InMemoryConsentSource, InMemoryEventBus, InMemoryMandateStore};
use kavach_mandate::{MandateConfig, MandateDeps, MandateService, SorIssuer};
use kavach_ports::{
    AppliedRevocation, MandateStore, PortError, RevocationApply, RevocationCursor, StoredMandate,
    StoredRevocation,
};
use kavach_ports_testkit::{FakeClock, InMemoryReplayGuard};

/// An in-memory store whose next `apply_revocation` fails (the process
/// died, the database was unreachable) before anything is written.
struct FailsOnce {
    inner: InMemoryMandateStore,
    fail_next_apply: AtomicBool,
}

impl MandateStore for FailsOnce {
    fn insert(&self, r: StoredMandate) -> impl Future<Output = Result<(), PortError>> + Send {
        self.inner.insert(r)
    }
    fn insert_child(&self, r: StoredMandate) -> impl Future<Output = Result<(), PortError>> + Send {
        self.inner.insert_child(r)
    }
    fn get(
        &self,
        t: &str,
        id: &str,
    ) -> impl Future<Output = Result<Option<StoredMandate>, PortError>> + Send {
        self.inner.get(t, id)
    }
    fn root_for_event(
        &self,
        t: &str,
        s: &str,
        e: &str,
    ) -> impl Future<Output = Result<Option<StoredMandate>, PortError>> + Send {
        self.inner.root_for_event(t, s, e)
    }
    fn ancestors(
        &self,
        t: &str,
        id: &str,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<StoredMandate>, PortError>> + Send {
        self.inner.ancestors(t, id, limit)
    }
    fn revoke_tree(
        &self,
        t: &str,
        id: &str,
        r: RevocationReason,
    ) -> impl Future<Output = Result<Vec<(String, RevocationReason)>, PortError>> + Send {
        self.inner.revoke_tree(t, id, r)
    }
    fn live_roots_for_record(
        &self,
        t: &str,
        s: &str,
        r: &str,
    ) -> impl Future<Output = Result<Vec<StoredMandate>, PortError>> + Send {
        self.inner.live_roots_for_record(t, s, r)
    }
    fn active_held_by(
        &self,
        t: &str,
        h: &str,
    ) -> impl Future<Output = Result<Vec<String>, PortError>> + Send {
        self.inner.active_held_by(t, h)
    }
    async fn apply_revocation(
        &self,
        request: RevocationApply,
    ) -> Result<AppliedRevocation, PortError> {
        if self.fail_next_apply.swap(false, Ordering::SeqCst) {
            return Err(PortError::unavailable("the store went away"));
        }
        self.inner.apply_revocation(request).await
    }
    fn record_revocation(
        &self,
        r: StoredRevocation,
    ) -> impl Future<Output = Result<(), PortError>> + Send {
        self.inner.record_revocation(r)
    }
    fn revocation_for_event(
        &self,
        t: &str,
        s: &str,
        e: &str,
    ) -> impl Future<Output = Result<Option<StoredRevocation>, PortError>> + Send {
        self.inner.revocation_for_event(t, s, e)
    }
    fn revocations_after(
        &self,
        after: Option<RevocationCursor>,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<StoredRevocation>, PortError>> + Send {
        self.inner.revocations_after(after, limit)
    }
}

type Flaky = MandateService<
    InMemoryKeyProvider,
    InMemoryReplayGuard,
    InMemoryConsentSource,
    FailsOnce,
    InMemoryEventBus,
    FakeClock,
>;

fn world() -> (Flaky, InMemoryKeyProvider) {
    let mut kavach = InMemoryKeyProvider::new();
    let kavach_pub = kavach.insert_seed("kavach-mandate-1", [1u8; 32]).unwrap();
    let mut sor = InMemoryKeyProvider::new();
    let lms = sor.insert_seed("lms-issuer-1", [2u8; 32]).unwrap();
    let config = MandateConfig {
        issuer_id: "kavach-dev".into(),
        signing_kid: "kavach-mandate-1".into(),
        mandate_keys: KeySet::new([kavach_pub]),
        sor_issuers: vec![SorIssuer {
            tenant_id: TENANT.into(),
            system: "lms".into(),
            key: lms,
        }],
        templates: vec![template()],
        passports: passports(),
        event_freshness_seconds: 300,
        replay_window_seconds: 24 * 3600,
    };
    let service = MandateService::new(
        MandateDeps {
            keys: kavach,
            replay: InMemoryReplayGuard::new(),
            consents: InMemoryConsentSource::new(vec![consent(t0())]),
            store: FailsOnce {
                inner: InMemoryMandateStore::new(),
                fail_next_apply: AtomicBool::new(false),
            },
            events: InMemoryEventBus::new(),
            clock: FakeClock::synced_at(t0()),
        },
        config,
    )
    .expect("valid configuration");
    (service, sor)
}

#[tokio::test]
async fn a_failed_apply_changes_nothing_and_its_retry_completes_the_revocation() {
    let (service, sor) = world();
    // Two live mandates about the one loan.
    let first = service
        .issue_from_event(&sign_event(&sor, "lms-issuer-1", &event(t0(), "dpd-1")).await)
        .await
        .expect("first");
    let second = service
        .issue_from_event(&sign_event(&sor, "lms-issuer-1", &event(t0(), "dpd-2")).await)
        .await
        .expect("second");

    let paid = kavach_domain::mandate::SorEvent {
        event_type: "loan.paid".into(),
        ..event(t0(), "pay-1")
    };
    let token = sign_event(&sor, "lms-issuer-1", &paid).await;

    // The store fails before anything is written.
    service
        .store()
        .fail_next_apply
        .store(true, Ordering::SeqCst);
    let err = service.revoke_from_event(&token).await.unwrap_err();
    assert_eq!(err.class, kavach_ports::ErrorClass::Unavailable, "{err}");
    for m in [&first, &second] {
        assert!(
            service.verify_active(&m.token).await.is_ok(),
            "nothing was revoked by the failed attempt"
        );
    }

    // The same event again is not mistaken for a replay: it applies fully.
    let done = service.revoke_from_event(&token).await.expect("retry");
    assert!(!done.replayed);
    let mut revoked = done.revoked.clone();
    revoked.sort();
    let mut expected = vec![first.mandate.id.clone(), second.mandate.id.clone()];
    expected.sort();
    assert_eq!(revoked, expected);
    for m in [&first, &second] {
        assert!(service.verify_active(&m.token).await.is_err());
    }
    // And now it is a replay.
    assert!(service.revoke_from_event(&token).await.unwrap().replayed);
}

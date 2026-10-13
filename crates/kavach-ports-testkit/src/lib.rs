//! Test doubles and conformance suites for `kavach-ports` (ADR-006 §4).
//!
//! Every adapter of a security-critical port must pass the matching suite in
//! [`conformance`]; the doubles here pass them too, so tests that use a double
//! exercise the same contract as production.

pub mod agent_evidence;
pub mod checkpoint_store;
pub mod credential_broker;
pub mod reference_resolver;

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

        // Empty and large messages: an HSM signs the whole message
        // (PureEdDSA), not a digest of it.
        for message in [Vec::new(), vec![0xA5; 65_536]] {
            let signature = provider.sign(kid, &message).await.expect("sign");
            assert_eq!(signature.len(), 64, "an Ed25519 signature is 64 bytes");
            verify_ed25519(&public, &message, &signature).expect("verifies");
        }

        concurrent_signing(provider, kid, &public);
    }

    /// Eight threads sign at once, each on its own runtime, sharing the
    /// provider as the API shares it between requests (an HSM provider
    /// shares a pool of sessions).
    fn concurrent_signing<K: KeyProvider>(
        provider: &K,
        kid: &str,
        public: &kavach_ports::PublicKey,
    ) {
        std::thread::scope(|scope| {
            let workers: Vec<_> = (0..8u8)
                .map(|i| {
                    scope.spawn(move || {
                        let runtime = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                            .expect("runtime");
                        for j in 0..8u8 {
                            let message = [i, j, 7, 7];
                            let signature = runtime
                                .block_on(provider.sign(kid, &message))
                                .expect("concurrent sign");
                            verify_ed25519(public, &message, &signature).expect("verifies");
                        }
                    })
                })
                .collect();
            for worker in workers {
                worker.join().expect("worker");
            }
        });
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

/// `AgentStateStore` contract (ADR-013). Every store must pass: the state
/// rules, the history, and the chain record that goes with a change.
pub mod agent_state_store {
    use std::sync::Arc;

    use chrono::{Duration, TimeZone, Utc};
    use kavach_ports::agent_evidence::AgentEvidenceStore;
    use kavach_ports::agent_state::{
        AgentState, AgentStateChange, AgentStateStore, ReasonCode, Recording,
    };
    use kavach_ports::chain_record::{AgentStateDraft, ChainRecord};
    use kavach_ports::ErrorClass;

    use crate::agent_evidence::TestSigner;
    use crate::FakeClock;

    fn change(
        tenant: &str,
        agent: &str,
        to: AgentState,
        by: &str,
        approved: Option<&str>,
    ) -> AgentStateChange {
        AgentStateChange {
            tenant_id: tenant.into(),
            agent_id: agent.into(),
            to,
            reason_code: ReasonCode::RogueBehaviour,
            note: "behaving outside its task".into(),
            changed_by: by.into(),
            approved_by: approved.map(String::from),
            at: Utc.with_ymd_and_hms(2026, 10, 1, 6, 0, 0).unwrap(),
        }
    }

    fn ids(items: &[&str]) -> Vec<String> {
        items.iter().map(ToString::to_string).collect()
    }

    /// Runs the whole suite against a fresh, empty store.
    pub async fn conformance<S>(store: Arc<S>)
    where
        S: AgentStateStore + AgentEvidenceStore + 'static,
    {
        defaults_and_isolation(&*store).await;
        transitions_and_history(&*store).await;
        recorded_changes(&*store).await;
        a_failed_record_changes_nothing(&*store).await;
        reconciler_view(&*store).await;
        concurrent_changes(store).await;
    }

    async fn defaults_and_isolation<S: AgentStateStore>(store: &S) {
        // No row means active, for every agent asked about.
        let all = store
            .states("t-1", &ids(&["rogue", "calm", "never-seen"]))
            .await
            .unwrap();
        assert_eq!(all.len(), 3);
        assert!(all.values().all(|s| *s == AgentState::Active));
        assert_eq!(store.current("t-1", "rogue").await.unwrap(), None);
        assert!(store.states("t-1", &[]).await.unwrap().is_empty());

        store
            .set(change(
                "t-1",
                "rogue",
                AgentState::Quarantined,
                "ops-1",
                None,
            ))
            .await
            .unwrap();
        let got = store.states("t-1", &ids(&["rogue", "calm"])).await.unwrap();
        assert_eq!(got["rogue"], AgentState::Quarantined);
        assert_eq!(got["calm"], AgentState::Active);
        // Another tenant's agent of the same name is untouched.
        let other = store.states("t-2", &ids(&["rogue"])).await.unwrap();
        assert_eq!(other["rogue"], AgentState::Active);
    }

    async fn transitions_and_history<S: AgentStateStore>(store: &S) {
        let agent = "walks-the-ladder";
        let t = "t-3";
        let rejected = |err: kavach_ports::PortError| {
            assert_eq!(err.class, ErrorClass::Rejected, "{err}");
        };

        let row = store
            .set(change(t, agent, AgentState::Restricted, "ops-1", None))
            .await
            .unwrap();
        assert_eq!(row.state, AgentState::Restricted);
        assert_eq!(row.change_no, 1);
        assert_eq!(row.reason_code, ReasonCode::RogueBehaviour);
        assert_eq!(row.changed_by, "ops-1");
        assert_eq!(row.approved_by, None);
        assert_eq!(store.current(t, agent).await.unwrap(), Some(row));

        // The same state again is not a change.
        rejected(
            store
                .set(change(t, agent, AgentState::Restricted, "ops-1", None))
                .await
                .unwrap_err(),
        );
        // Tightening further needs one principal.
        let second = store
            .set(change(t, agent, AgentState::Quarantined, "ops-1", None))
            .await
            .unwrap();
        assert_eq!(second.change_no, 2);
        // Loosening needs a second, different principal.
        rejected(
            store
                .set(change(t, agent, AgentState::Active, "ops-1", None))
                .await
                .unwrap_err(),
        );
        rejected(
            store
                .set(change(t, agent, AgentState::Active, "ops-1", Some("ops-1")))
                .await
                .unwrap_err(),
        );
        assert_eq!(
            store.states(t, &ids(&[agent])).await.unwrap()[agent],
            AgentState::Quarantined,
            "a refused change changes nothing"
        );
        let back = store
            .set(change(t, agent, AgentState::Active, "ops-1", Some("ops-2")))
            .await
            .unwrap();
        assert_eq!(back.approved_by.as_deref(), Some("ops-2"));
        assert_eq!(back.change_no, 3);

        // A note too long, or with control characters, is invalid; a
        // missing one is fine.
        let mut bad = change(t, agent, AgentState::Quarantined, "ops-1", None);
        bad.note = "x\ny".into();
        assert_eq!(store.set(bad).await.unwrap_err().class, ErrorClass::Invalid);
        let mut none = change(t, agent, AgentState::Quarantined, "ops-1", None);
        none.note.clear();
        store.set(none).await.unwrap();

        // Revoked is final, from any state, whoever asks.
        store
            .set(change(t, agent, AgentState::Revoked, "ops-1", None))
            .await
            .unwrap();
        for to in [
            AgentState::Active,
            AgentState::Restricted,
            AgentState::Quarantined,
        ] {
            rejected(
                store
                    .set(change(t, agent, to, "ops-3", Some("ops-4")))
                    .await
                    .unwrap_err(),
            );
        }
        assert_eq!(
            store.states(t, &ids(&[agent])).await.unwrap()[agent],
            AgentState::Revoked
        );

        // Every accepted change is in the history, in order, with its
        // number, and nothing else is.
        let history: Vec<_> = store
            .changes_after(None, 100)
            .await
            .unwrap()
            .into_iter()
            .filter(|c| c.tenant_id == t && c.agent_id == agent)
            .map(|c| (c.change_no, c.from_state, c.to_state))
            .collect();
        assert_eq!(
            history,
            [
                (1, AgentState::Active, AgentState::Restricted),
                (2, AgentState::Restricted, AgentState::Quarantined),
                (3, AgentState::Quarantined, AgentState::Active),
                (4, AgentState::Active, AgentState::Quarantined),
                (5, AgentState::Quarantined, AgentState::Revoked),
            ]
        );
    }

    /// A loosening is written with its record in one step: the chain holds
    /// it, in order, and writing it again is the same record.
    async fn recorded_changes<S>(store: &S)
    where
        S: AgentStateStore + AgentEvidenceStore,
    {
        let signer = TestSigner::new("evidence-test", 9);
        let clock = FakeClock::synced_at(Utc.with_ymd_and_hms(2026, 10, 1, 6, 5, 0).unwrap());
        let (t, agent) = ("t-5", "recorded");
        store
            .set(change(t, agent, AgentState::Quarantined, "ops-1", None))
            .await
            .unwrap();
        let digest = |n: i64| Some(format!("mac:{}", format!("{n:02x}").repeat(32)));
        let (row, record) = store
            .set_recorded(
                change(t, agent, AgentState::Active, "ops-1", Some("ops-2")),
                Recording {
                    partition_id: 0,
                    clock: &clock,
                    signer: &signer,
                    reason_digest: &digest,
                },
            )
            .await
            .unwrap();
        assert_eq!(row.state, AgentState::Active);
        let p = &record.payload;
        assert_eq!((p.change_no, p.agent_id.as_str()), (2, agent));
        assert_eq!(p.from_state, AgentState::Quarantined);
        assert_eq!(p.to_state, AgentState::Active);
        assert_eq!(p.approved_by.as_deref(), Some("ops-2"));
        assert_eq!(p.reason_code, ReasonCode::RogueBehaviour);
        assert_eq!(
            p.reason_digest,
            digest(2),
            "the note is a digest, never text"
        );
        assert_eq!(p.changed_at, row.changed_at);
        assert!(p.recorded_at >= p.changed_at);

        let chain = store.records(t, 0).await.unwrap();
        assert!(
            matches!(chain.last(), Some(ChainRecord::AgentState(r)) if *r == record),
            "the record is in the chain"
        );
        assert_eq!(
            store.agent_state_record(t, agent, 2).await.unwrap(),
            Some(record.clone())
        );
        // Change 1 (a tightening) has no record yet: it is the
        // reconciler's to write.
        assert_eq!(store.agent_state_record(t, agent, 1).await.unwrap(), None);

        // The same change again is the same record, not a second one.
        let draft = AgentStateDraft {
            tenant_id: t.into(),
            partition_id: 0,
            agent_id: agent.into(),
            change_no: 2,
            from_state: AgentState::Quarantined,
            to_state: AgentState::Active,
            reason_code: ReasonCode::RogueBehaviour,
            reason_digest: digest(2),
            changed_by: "ops-1".into(),
            approved_by: Some("ops-2".into()),
            changed_at: row.changed_at,
        };
        let again = store
            .append_agent_state(draft.clone(), &clock, &signer)
            .await
            .unwrap();
        assert_eq!(again, record);
        let mut other = draft;
        other.changed_by = "someone-else".into();
        assert_eq!(
            store
                .append_agent_state(other, &clock, &signer)
                .await
                .unwrap_err()
                .class,
            ErrorClass::Rejected
        );
    }

    /// A record that cannot be written (the signer is down) must not leave
    /// the agent loosened: both or neither.
    async fn a_failed_record_changes_nothing<S>(store: &S)
    where
        S: AgentStateStore + AgentEvidenceStore,
    {
        let signer = TestSigner::failing("evidence-test");
        let clock = FakeClock::synced_at(Utc.with_ymd_and_hms(2026, 10, 1, 6, 10, 0).unwrap());
        let (t, agent) = ("t-6", "unrecordable");
        store
            .set(change(t, agent, AgentState::Quarantined, "ops-1", None))
            .await
            .unwrap();
        let before = store.changes_after(None, 1000).await.unwrap().len();
        let none = |_: i64| None;
        let err = store
            .set_recorded(
                change(t, agent, AgentState::Active, "ops-1", Some("ops-2")),
                Recording {
                    partition_id: 0,
                    clock: &clock,
                    signer: &signer,
                    reason_digest: &none,
                },
            )
            .await
            .unwrap_err();
        assert_ne!(err.class, ErrorClass::Rejected, "{err}");
        assert_eq!(
            store.states(t, &ids(&[agent])).await.unwrap()[agent],
            AgentState::Quarantined
        );
        assert_eq!(store.changes_after(None, 1000).await.unwrap().len(), before);
        let row = store.current(t, agent).await.unwrap().unwrap();
        assert_eq!(row.change_no, 1, "no change number was used");
    }

    /// What the reconciler does: page through the history, write any
    /// missing record, and find nothing missing the second time.
    async fn reconciler_view<S>(store: &S)
    where
        S: AgentStateStore + AgentEvidenceStore,
    {
        let signer = TestSigner::new("evidence-test", 9);
        let clock = FakeClock::synced_at(Utc.with_ymd_and_hms(2026, 10, 1, 7, 0, 0).unwrap());
        clock.advance(Duration::seconds(1));
        let mut after = None;
        let mut written = 0;
        loop {
            let page = store.changes_after(after.clone(), 2).await.unwrap();
            let Some(last) = page.last() else { break };
            after = Some(last.cursor());
            for c in &page {
                if store
                    .agent_state_record(&c.tenant_id, &c.agent_id, c.change_no)
                    .await
                    .unwrap()
                    .is_some()
                {
                    continue;
                }
                let draft = AgentStateDraft {
                    tenant_id: c.tenant_id.clone(),
                    partition_id: 0,
                    agent_id: c.agent_id.clone(),
                    change_no: c.change_no,
                    from_state: c.from_state,
                    to_state: c.to_state,
                    reason_code: c.reason_code,
                    reason_digest: None,
                    changed_by: c.changed_by.clone(),
                    approved_by: c.approved_by.clone(),
                    changed_at: c.changed_at,
                };
                store
                    .append_agent_state(draft, &clock, &signer)
                    .await
                    .unwrap();
                written += 1;
            }
        }
        assert!(written > 0, "tightenings had no records until now");
        // Every change now has exactly one record.
        for c in store.changes_after(None, 1000).await.unwrap() {
            assert!(store
                .agent_state_record(&c.tenant_id, &c.agent_id, c.change_no)
                .await
                .unwrap()
                .is_some());
        }
    }

    /// Two operators stop the same agent at the same moment: one change is
    /// made, the other is told the agent is already in that state.
    async fn concurrent_changes<S: AgentStateStore + 'static>(store: Arc<S>) {
        let (a, b) = (Arc::clone(&store), Arc::clone(&store));
        let first = tokio::spawn(async move {
            a.set(change(
                "t-4",
                "racer",
                AgentState::Quarantined,
                "ops-1",
                None,
            ))
            .await
        });
        let second = tokio::spawn(async move {
            b.set(change(
                "t-4",
                "racer",
                AgentState::Quarantined,
                "ops-2",
                None,
            ))
            .await
        });
        let results = [first.await.unwrap(), second.await.unwrap()];
        assert_eq!(
            results.iter().filter(|r| r.is_ok()).count(),
            1,
            "{results:?}"
        );
        let loser = results.into_iter().find_map(Result::err).unwrap();
        assert_eq!(loser.class, ErrorClass::Rejected);
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
    use kavach_ports::{ErrorClass, MandateStore, StoredMandate, StoredRevocation};

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
        revocations(&*store).await;
        delegation_racing_revocation(store).await;
    }

    /// A root about `record_ref` of `system` (ADR-012).
    fn root_about(id: &str, system: &str, record_ref: &str) -> StoredMandate {
        let mut r = record(id, None, 0);
        r.mandate.source.system = system.into();
        r.mandate.source.record_ref = record_ref.into();
        r
    }

    /// ADR-012: a loan's live roots are found by their record; a revoking
    /// event's result is kept once and read back.
    async fn revocations<S: MandateStore>(store: &S) {
        for (id, system, record_ref) in [
            ("loan-a-1", "lms", "loan-a"),
            ("loan-a-2", "lms", "loan-a"),
            ("loan-a-gone", "lms", "loan-a"),
            ("loan-b-1", "lms", "loan-b"),
            ("other-system", "crm", "loan-a"),
        ] {
            store
                .insert(root_about(id, system, record_ref))
                .await
                .expect("root");
        }
        store
            .insert_child(record("loan-a-child", Some("loan-a-1"), 1))
            .await
            .expect("child");
        store
            .revoke_tree(TENANT, "loan-a-gone", RevocationReason::Manual)
            .await
            .expect("revoked");
        let mut live: Vec<String> = store
            .live_roots_for_record(TENANT, "lms", "loan-a")
            .await
            .expect("live roots")
            .into_iter()
            .map(|r| r.mandate.id)
            .collect();
        live.sort();
        assert_eq!(
            live,
            ["loan-a-1", "loan-a-2"],
            "active roots of this system and record only: not children, revoked ones, other records or systems"
        );

        let revocation = StoredRevocation {
            tenant_id: TENANT.into(),
            system: "lms".into(),
            event_id: "pay-1".into(),
            event_digest: format!("sha256-jcs-v1:{}", "ab".repeat(32)),
            event_type: "loan.paid".into(),
            record_ref: "loan-a".into(),
            occurred_at: Utc.with_ymd_and_hms(2026, 10, 1, 6, 0, 0).unwrap(),
            revoked: vec!["loan-a-1".into(), "loan-a-child".into()],
            // Microseconds survive storage.
            revoked_at: Utc.with_ymd_and_hms(2026, 10, 1, 6, 0, 1).unwrap()
                + chrono::TimeDelta::microseconds(123_456),
        };
        store
            .record_revocation(revocation.clone())
            .await
            .expect("recorded");
        let again = store
            .record_revocation(revocation.clone())
            .await
            .unwrap_err();
        assert_eq!(
            again.class,
            ErrorClass::Rejected,
            "an event is recorded once"
        );
        assert_eq!(
            store
                .revocation_for_event(TENANT, "lms", "pay-1")
                .await
                .expect("read"),
            Some(revocation.clone())
        );
        assert!(store
            .revocation_for_event(TENANT, "lms", "pay-2")
            .await
            .expect("read")
            .is_none());
        revocations_page_in_time_order(store, &revocation).await;
    }

    /// The reconciler's view: every revocation, by time then tenant, system
    /// and event id, resumed exactly after a cursor.
    async fn revocations_page_in_time_order<S: MandateStore>(store: &S, first: &StoredRevocation) {
        let at = |event_id: &str, revoked_at| StoredRevocation {
            event_id: event_id.into(),
            revoked_at,
            ..first.clone()
        };
        let earlier = at("pay-0", first.revoked_at - chrono::TimeDelta::seconds(5));
        let same_instant = at("pay-2", first.revoked_at);
        let later = at(
            "pay-3",
            first.revoked_at + chrono::TimeDelta::microseconds(1),
        );
        for revocation in [&later, &same_instant, &earlier] {
            store
                .record_revocation(revocation.clone())
                .await
                .expect("recorded");
        }
        let all = store.revocations_after(None, 100).await.expect("page");
        let ids: Vec<&str> = all.iter().map(|r| r.event_id.as_str()).collect();
        assert_eq!(
            ids,
            ["pay-0", "pay-1", "pay-2", "pay-3"],
            "time, then event id"
        );
        assert_eq!(all[1], *first, "read back whole, to the microsecond");

        let mut paged = Vec::new();
        let mut cursor = None;
        loop {
            let page = store.revocations_after(cursor, 1).await.expect("page");
            let Some(last) = page.last() else { break };
            cursor = Some(last.cursor());
            paged.extend(page);
        }
        assert_eq!(paged, all, "one at a time, nothing skipped or repeated");

        let from = kavach_ports::RevocationCursor::at(first.revoked_at);
        let tail = store
            .revocations_after(Some(from), 100)
            .await
            .expect("page");
        let ids: Vec<&str> = tail.iter().map(|r| r.event_id.as_str()).collect();
        assert_eq!(ids, ["pay-1", "pay-2", "pay-3"], "from an instant on");
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
        let by_event = store
            .root_for_event(TENANT, "lms", "evt-root")
            .await
            .expect("lookup")
            .expect("root found by its source event");
        assert_eq!(by_event.mandate.id, "root");
        assert!(
            store
                .root_for_event(TENANT, "lms", "evt-child")
                .await
                .unwrap()
                .is_none(),
            "children are not roots"
        );
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
        assert_eq!(
            store.ancestors(TENANT, "root", 8).await.unwrap(),
            Vec::<StoredMandate>::new()
        );

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

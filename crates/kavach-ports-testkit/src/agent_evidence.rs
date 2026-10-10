//! `AgentEvidenceStore` contract (H5a-3b). Every store — in-memory and
//! Postgres — runs this suite, including the concurrency cases.

use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::{Duration, NaiveDate, TimeZone, Utc};
use ed25519_dalek::{Signer, SigningKey};
use kavach_domain::Decision;
use kavach_ports::agent_evidence::{
    sign_outcome, verify_chain, Actor, AgentDecisionPayload, AgentEvidenceStore, ChainEntry,
    CommitRequest, CommitResult, ContactReservation, EvidenceSigner, Outcome, PolicyVersions,
    RequestBinding, TimeSync, HASH_ALG_V2, KIND_AGENT_DECISION,
};
use kavach_ports::chain_record::{ChainRecord, RevocationDraft};
use kavach_ports::{ErrorClass, KeyAlgorithm, PortError, PublicKey, SyncStatus};

use crate::FakeClock;

/// Ed25519 evidence signer for tests.
pub struct TestSigner {
    key: SigningKey,
    kid: String,
    fail: bool,
}

impl TestSigner {
    #[must_use]
    pub fn new(kid: &str, seed: u8) -> Self {
        Self {
            key: SigningKey::from_bytes(&[seed; 32]),
            kid: kid.into(),
            fail: false,
        }
    }

    /// A signer that always fails (signing unavailable).
    #[must_use]
    pub fn failing(kid: &str) -> Self {
        Self {
            fail: true,
            ..Self::new(kid, 1)
        }
    }

    #[must_use]
    pub fn keys(&self) -> BTreeMap<String, PublicKey> {
        BTreeMap::from([(
            self.kid.clone(),
            PublicKey {
                kid: self.kid.clone(),
                algorithm: KeyAlgorithm::Ed25519,
                bytes: self.key.verifying_key().to_bytes(),
            },
        )])
    }
}

impl EvidenceSigner for TestSigner {
    fn key_id(&self) -> &str {
        &self.kid
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, PortError> {
        if self.fail {
            return Err(PortError::unavailable("evidence key unavailable"));
        }
        Ok(self.key.sign(message).to_bytes().to_vec())
    }
}

const KID: &str = "evidence-test";
const SUBJECT: &str = "psn:subject";

fn t0() -> chrono::DateTime<Utc> {
    // 11:00 IST on 1 Oct 2026.
    Utc.with_ymd_and_hms(2026, 10, 1, 5, 30, 0).unwrap()
}

fn day() -> NaiveDate {
    NaiveDate::from_ymd_opt(2026, 10, 1).unwrap()
}

/// A contact request allowed before the commit, cap `max`.
#[must_use]
pub fn request(tenant: &str, request_id: &str, max: u32) -> CommitRequest {
    let draft = AgentDecisionPayload {
        record_id: String::new(),
        tenant_id: tenant.into(),
        partition_id: 0,
        seq: 0,
        prev_hash: String::new(),
        kind: KIND_AGENT_DECISION.into(),
        hash_alg: HASH_ALG_V2.into(),
        key_id: KID.into(),
        actor: Actor {
            agent_id: "collections-agent".into(),
            identity_key: "oidc:iss#collections-agent".into(),
        },
        chain: vec!["m-root".into()],
        mandate_id: "m-root".into(),
        purpose: "loan_recovery".into(),
        consent_refs: vec!["C-1".into()],
        action: "send_reminder".into(),
        request_id: request_id.into(),
        subject_pseudonym: SUBJECT.into(),
        params_mac: Some("mac:params".into()),
        policy_versions: PolicyVersions {
            cedar: "sha256:cedar".into(),
            cel: None,
            packs: vec![],
            tools: Some("sha256:tools".into()),
            build: "test".into(),
        },
        signals: vec!["authorized".into()],
        pre_commit_decision: Decision::Pass,
        policy_decision: Decision::Pass,
        returned_decision: Decision::Pass,
        obligations: vec![],
        credential_id: None,
        credential_expires_at: None,
        // The window closes at 19:00 IST.
        send_by: Some(Utc.with_ymd_and_hms(2026, 10, 1, 13, 30, 0).unwrap()),
        time_sync: TimeSync {
            status: String::new(),
            max_error_ms: None,
        },
        ts: t0(),
    };
    CommitRequest {
        tenant_id: tenant.into(),
        partition_id: 0,
        binding: RequestBinding {
            action: "send_reminder".into(),
            params_mac: Some("mac:params".into()),
            subject_pseudonym: SUBJECT.into(),
            mandate_id: "m-root".into(),
        },
        draft,
        contact: Some(ContactReservation {
            ist_date: day(),
            max_per_day: max,
        }),
        credential_id: format!("cred-{request_id}"),
        credential_ttl: Duration::seconds(15),
        max_clock_error_ms: 1_000,
    }
}

fn committed(result: CommitResult) -> kavach_ports::agent_evidence::AgentDecisionRecord {
    match result {
        CommitResult::Committed(record) => *record,
        other => panic!("expected a new commit, got {other:?}"),
    }
}

/// Runs the whole suite against an empty store.
pub async fn conformance<S: AgentEvidenceStore + 'static>(store: Arc<S>) {
    let signer = TestSigner::new(KID, 9);
    let clock = FakeClock::synced_at(t0());
    allow_replay_conflict_and_outcome(&*store, &clock, &signer).await;
    commit_time_checks(&*store, &clock, &signer).await;
    nothing_is_kept_when_signing_fails(&*store, &clock).await;
    every_outcome_kind_is_stored(&*store, &clock, &signer).await;
    one_creator_per_request_under_concurrency(Arc::clone(&store), TestSigner::new(KID, 9)).await;
    duplicates_race_near_the_cap(Arc::clone(&store), TestSigner::new(KID, 9)).await;
    revocations_in_the_chain(&*store, &clock, &signer).await;
    one_record_per_revocation_event(Arc::clone(&store)).await;
    cap_holds_under_concurrency(store, signer).await;
}

/// A revocation by a system-of-record event (ADR-012 §7).
#[must_use]
pub fn revocation_draft(tenant: &str, event_id: &str) -> RevocationDraft {
    RevocationDraft {
        tenant_id: tenant.into(),
        partition_id: 0,
        source_system: "lms".into(),
        event_id: event_id.into(),
        event_sha256: "ab".repeat(32),
        event_type: "loan.paid".into(),
        record_pseudonym: "psn:loan".into(),
        occurred_at: t0() - Duration::minutes(1),
        revoked: vec!["m-1".into(), "m-1-child".into()],
        revoked_at: t0(),
    }
}

/// Revocation records take their place in the chain between decisions, are
/// written once per event, and are never read as a decision.
async fn revocations_in_the_chain<S: AgentEvidenceStore>(
    store: &S,
    clock: &FakeClock,
    signer: &TestSigner,
) {
    let t = "ae-revocations";
    let mut before = request(t, "before", 3);
    before.contact = None;
    before.draft.send_by = None;
    store.commit(before, clock, signer).await.expect("commit");
    let draft = revocation_draft(t, "pay-1");
    let revocation = store
        .append_revocation(draft.clone(), clock, signer)
        .await
        .expect("revocation recorded");
    assert_eq!(revocation.payload.seq, 2);
    assert_eq!(revocation.payload.recorded_at, t0());
    let mut after = request(t, "after", 3);
    after.contact = None;
    after.draft.send_by = None;
    store.commit(after, clock, signer).await.expect("commit");

    let records = store.records(t, 0).await.unwrap();
    let kinds: Vec<&str> = records.iter().map(ChainEntry::kind).collect();
    assert_eq!(
        kinds,
        [
            KIND_AGENT_DECISION,
            "mandate_revocation",
            KIND_AGENT_DECISION
        ]
    );
    assert_eq!(records[1], ChainRecord::Revocation(revocation.clone()));
    verify_chain(&records, &signer.keys(), None, &[], t0()).expect("one chain of both kinds");

    // The same revocation again: the stored record, nothing new.
    let again = store
        .append_revocation(draft.clone(), clock, signer)
        .await
        .expect("idempotent");
    assert_eq!(again, revocation);
    // Other content for the same event: refused.
    let mut other = draft;
    other.revoked = vec!["m-2".into()];
    let err = store
        .append_revocation(other, clock, signer)
        .await
        .unwrap_err();
    assert_eq!(err.class, ErrorClass::Rejected, "{err:?}");
    assert_eq!(store.records(t, 0).await.unwrap().len(), 3);

    assert_eq!(
        store.revocation_record(t, "lms", "pay-1").await.unwrap(),
        Some(revocation.clone())
    );
    assert_eq!(
        store.revocation_record(t, "lms", "pay-2").await.unwrap(),
        None
    );
    assert_eq!(
        store.revocation_record(t, "crm", "pay-1").await.unwrap(),
        None
    );
    assert_eq!(
        store
            .revocation_record("other", "lms", "pay-1")
            .await
            .unwrap(),
        None
    );
    // The operator's read by record id is for decisions only.
    assert_eq!(
        store
            .record(t, &revocation.payload.record_id)
            .await
            .unwrap(),
        None
    );
}

/// The API and the reconciler may record one event at once: one record.
async fn one_record_per_revocation_event<S: AgentEvidenceStore + 'static>(store: Arc<S>) {
    let t = "ae-revocation-race";
    let signer = Arc::new(TestSigner::new(KID, 9));
    let clock = Arc::new(FakeClock::synced_at(t0()));
    let tasks: Vec<_> = (0..8)
        .map(|_| {
            let (store, signer, clock) =
                (Arc::clone(&store), Arc::clone(&signer), Arc::clone(&clock));
            tokio::spawn(async move {
                store
                    .append_revocation(revocation_draft(t, "pay-race"), &*clock, &*signer)
                    .await
            })
        })
        .collect();
    let mut hashes = std::collections::BTreeSet::new();
    for task in tasks {
        hashes.insert(task.await.unwrap().expect("recorded or returned").hash);
    }
    assert_eq!(hashes.len(), 1, "every writer sees the one record");
    let records = store.records(t, 0).await.unwrap();
    assert_eq!(records.len(), 1);
    verify_chain(&records, &signer.keys(), None, &[], t0()).expect("signed");
}

/// Duplicates of one request race distinct requests while the day's cap is
/// nearly reached. One record per request; the duplicate has exactly one
/// creator; the counter equals the allows on the chain, so a duplicate that
/// lost (and rolled back) left no reserved slot behind; the chain is
/// linear and signed.
async fn duplicates_race_near_the_cap<S: AgentEvidenceStore + 'static>(
    store: Arc<S>,
    signer: TestSigner,
) {
    let t = "ae-dup-race";
    let signer = Arc::new(signer);
    let clock = Arc::new(FakeClock::synced_at(t0()));
    // Two of the three slots are already used.
    for id in ["early-1", "early-2"] {
        let record = committed(
            store
                .commit(request(t, id, 3), &*clock, &*signer)
                .await
                .expect("commit"),
        );
        assert!(record.is_allow());
    }
    let tasks: Vec<_> = (0..24)
        .map(|i| {
            let (store, signer, clock) =
                (Arc::clone(&store), Arc::clone(&signer), Arc::clone(&clock));
            let id = if i % 2 == 0 {
                "dup".to_string()
            } else {
                format!("distinct-{i}")
            };
            tokio::spawn(async move { store.commit(request(t, &id, 3), &*clock, &*signer).await })
        })
        .collect();
    let (mut dup_created, mut dup_replayed) = (0, 0);
    for task in tasks {
        match task.await.expect("join").expect("commit") {
            CommitResult::Committed(record) if record.payload.request_id == "dup" => {
                dup_created += 1;
            }
            CommitResult::Replayed(record) => {
                assert_eq!(
                    record.payload.request_id, "dup",
                    "only the duplicate replays"
                );
                dup_replayed += 1;
            }
            CommitResult::Committed(_) => {}
            CommitResult::Conflict(_) => panic!("identical content is never a conflict"),
        }
    }
    assert_eq!((dup_created, dup_replayed), (1, 11), "exactly one creator");

    let records = store.records(t, 0).await.unwrap();
    assert_eq!(records.len(), 2 + 1 + 12, "one record per request");
    let allows = records
        .iter()
        .filter_map(ChainEntry::as_decision)
        .filter(|r| r.is_allow())
        .count();
    assert_eq!(allows, 3, "exactly the cap");
    assert_eq!(
        store.contacts_on(t, SUBJECT, day()).await.unwrap(),
        3,
        "no slot left behind by a duplicate that lost"
    );
    verify_chain(&records, &signer.keys(), None, &[], t0()).expect("linear, signed chain");
}

async fn allow_replay_conflict_and_outcome<S: AgentEvidenceStore>(
    store: &S,
    clock: &FakeClock,
    signer: &TestSigner,
) {
    let t = "ae-basic";
    let record = committed(
        store
            .commit(request(t, "r-1", 3), clock, signer)
            .await
            .unwrap(),
    );
    assert!(record.is_allow());
    assert_eq!(record.payload.seq, 1);
    assert_eq!(record.payload.credential_id.as_deref(), Some("cred-r-1"));
    let exp = record.payload.credential_expires_at.unwrap();
    assert!(exp <= record.payload.send_by.unwrap() && exp <= t0() + Duration::seconds(15));
    assert_eq!(store.contacts_on(t, SUBJECT, day()).await.unwrap(), 1);

    // A lost response retried: same record and credential, no second slot.
    match store
        .commit(request(t, "r-1", 3), clock, signer)
        .await
        .unwrap()
    {
        CommitResult::Replayed(again) => assert_eq!(*again, record),
        other => panic!("expected replay, got {other:?}"),
    }
    assert_eq!(store.contacts_on(t, SUBJECT, day()).await.unwrap(), 1);
    // The same request id with other content is a conflict.
    let mut other = request(t, "r-1", 3);
    other.binding.params_mac = Some("mac:different".into());
    assert!(matches!(
        store.commit(other, clock, signer).await.unwrap(),
        CommitResult::Conflict(_)
    ));

    // A denial is recorded but reserves nothing and carries no credential.
    let mut denied = request(t, "r-2", 3);
    denied.draft.pre_commit_decision = Decision::Block;
    let denied = committed(store.commit(denied, clock, signer).await.unwrap());
    assert!(!denied.is_allow() && denied.payload.credential_id.is_none());
    assert_eq!(store.contacts_on(t, SUBJECT, day()).await.unwrap(), 1);

    let records =
        outcomes_once_per_allowed_record(store, signer, t, &record.hash, &denied.hash).await;
    assert!(
        verify_chain(
            &records[..1],
            &signer.keys(),
            Some((2, &denied.hash)),
            &[],
            t0()
        )
        .is_err(),
        "a truncated tail is caught when the head is known"
    );
}

async fn commit_time_checks<S: AgentEvidenceStore>(
    store: &S,
    clock: &FakeClock,
    signer: &TestSigner,
) {
    let t = "ae-time";
    // Decided before 19:00 IST, committed at 19:00: closed.
    let late = FakeClock::synced_at(Utc.with_ymd_and_hms(2026, 10, 1, 13, 30, 0).unwrap());
    let record = committed(
        store
            .commit(request(t, "late", 3), &late, signer)
            .await
            .unwrap(),
    );
    assert_eq!(record.payload.pre_commit_decision, Decision::Pass);
    assert_eq!(record.payload.returned_decision, Decision::Block);
    assert!(record.payload.signals.iter().any(|s| s == "window_closed"));
    assert!(
        record.payload.credential_id.is_none(),
        "no credential for a converted allow"
    );

    // Trusted time lost at commit: blocked.
    let unsynced = FakeClock::new(t0(), SyncStatus::Unsynced);
    let record = committed(
        store
            .commit(request(t, "unsynced", 3), &unsynced, signer)
            .await
            .unwrap(),
    );
    assert!(record
        .payload
        .signals
        .iter()
        .any(|s| s == "trusted_time_unavailable"));
    assert_eq!(
        store.contacts_on(t, SUBJECT, day()).await.unwrap(),
        0,
        "no slot used"
    );

    // Still allowed with a synced clock before the deadline.
    assert!(committed(
        store
            .commit(request(t, "ok", 3), clock, signer)
            .await
            .unwrap()
    )
    .is_allow());
}

async fn nothing_is_kept_when_signing_fails<S: AgentEvidenceStore>(store: &S, clock: &FakeClock) {
    let t = "ae-fail";
    let err = store
        .commit(request(t, "r", 3), clock, &TestSigner::failing(KID))
        .await
        .unwrap_err();
    assert_eq!(err.class, kavach_ports::ErrorClass::Unavailable);
    assert!(store.records(t, 0).await.unwrap().is_empty(), "no record");
    assert_eq!(
        store.contacts_on(t, SUBJECT, day()).await.unwrap(),
        0,
        "no slot"
    );
    assert!(store
        .get_by_request(t, "collections-agent", "r")
        .await
        .unwrap()
        .is_none());
}

async fn cap_holds_under_concurrency<S: AgentEvidenceStore + 'static>(
    store: Arc<S>,
    signer: TestSigner,
) {
    let t = "ae-race";
    let signer = Arc::new(signer);
    let clock = Arc::new(FakeClock::synced_at(t0()));
    let tasks: Vec<_> = (0..50)
        .map(|i| {
            let (store, signer, clock) =
                (Arc::clone(&store), Arc::clone(&signer), Arc::clone(&clock));
            tokio::spawn(async move {
                store
                    .commit(request(t, &format!("race-{i}"), 3), &*clock, &*signer)
                    .await
            })
        })
        .collect();
    let mut allows = 0;
    for task in tasks {
        let record = committed(task.await.expect("join").expect("commit"));
        if record.is_allow() {
            allows += 1;
        } else {
            assert!(record
                .payload
                .signals
                .iter()
                .any(|s| s == "contact_cap_reached"));
        }
    }
    assert_eq!(allows, 3, "exactly the cap");
    assert_eq!(store.contacts_on(t, SUBJECT, day()).await.unwrap(), 3);
    let records = store.records(t, 0).await.unwrap();
    assert_eq!(records.len(), 50);
    verify_chain(&records, &signer.keys(), None, &[], t0()).expect("linear, signed chain");
}

/// Forward-once ownership: of many concurrent commits of the same request,
/// exactly one creates the record (`Committed`); the rest see it
/// (`Replayed`), so only one caller may ever forward.
async fn one_creator_per_request_under_concurrency<S: AgentEvidenceStore + 'static>(
    store: Arc<S>,
    signer: TestSigner,
) {
    let t = "ae-once";
    let signer = Arc::new(signer);
    let clock = Arc::new(FakeClock::synced_at(t0()));
    let tasks: Vec<_> = (0..20)
        .map(|_| {
            let (store, signer, clock) =
                (Arc::clone(&store), Arc::clone(&signer), Arc::clone(&clock));
            tokio::spawn(async move {
                store
                    .commit(request(t, "same-request", 3), &*clock, &*signer)
                    .await
            })
        })
        .collect();
    let (mut created, mut replayed) = (0, 0);
    for task in tasks {
        match task.await.expect("join").expect("commit") {
            CommitResult::Committed(_) => created += 1,
            CommitResult::Replayed(_) => replayed += 1,
            CommitResult::Conflict(_) => panic!("identical content is never a conflict"),
        }
    }
    assert_eq!((created, replayed), (1, 19), "exactly one creator");
    assert_eq!(store.contacts_on(t, SUBJECT, day()).await.unwrap(), 1);
    assert_eq!(store.records(t, 0).await.unwrap().len(), 1);
}

/// Every outcome kind can be stored and read back with its reason.
async fn every_outcome_kind_is_stored<S: AgentEvidenceStore>(
    store: &S,
    clock: &FakeClock,
    signer: &TestSigner,
) {
    let t = "ae-kinds";
    for (i, (outcome, reason)) in [
        (Outcome::Delivered, "provider_202"),
        (Outcome::Failed, "connect_failed"),
        (Outcome::Refused, "provider_422"),
        (Outcome::NotExecuted, "send_by_passed"),
        (Outcome::Unknown, "provider_409"),
    ]
    .into_iter()
    .enumerate()
    {
        // Distinct subjects, so the daily cap never interferes.
        let mut req = request(t, &format!("kind-{i}"), 3);
        req.binding.subject_pseudonym = format!("psn:kind-{i}");
        req.draft.subject_pseudonym = format!("psn:kind-{i}");
        let record = committed(store.commit(req, clock, signer).await.unwrap());
        let credential = record.payload.credential_id.clone().expect("allow");
        let written =
            sign_outcome(t, &credential, &record.hash, outcome, reason, t0(), signer).unwrap();
        store.record_outcome(written.clone()).await.unwrap();
        assert_eq!(store.outcome(t, &credential).await.unwrap(), Some(written));
    }
}

/// Outcomes: once per credential, only for an allowed record, with a signed
/// reason that round-trips; the verifier reports a missing outcome.
async fn outcomes_once_per_allowed_record<S: AgentEvidenceStore>(
    store: &S,
    signer: &TestSigner,
    t: &str,
    record_hash: &str,
    denied_hash: &str,
) -> Vec<kavach_ports::agent_evidence::AgentDecisionRecord> {
    // Outcomes: once per credential, only for an allowed record, with a
    // signed reason code that round-trips through the store.
    let outcome = sign_outcome(
        t,
        "cred-r-1",
        record_hash,
        Outcome::Delivered,
        "provider_202",
        t0(),
        signer,
    )
    .unwrap();
    store.record_outcome(outcome.clone()).await.unwrap();
    assert!(store.record_outcome(outcome.clone()).await.is_err(), "once");
    let later = sign_outcome(
        t,
        "cred-r-1",
        record_hash,
        Outcome::Unknown,
        "timeout_after_send",
        t0(),
        signer,
    )
    .unwrap();
    assert!(
        store.record_outcome(later).await.is_err(),
        "an outcome is never replaced"
    );
    let stray = sign_outcome(
        t,
        "cred-none",
        record_hash,
        Outcome::Failed,
        "connect_failed",
        t0(),
        signer,
    )
    .unwrap();
    assert!(
        store.record_outcome(stray).await.is_err(),
        "unknown credential"
    );
    let stored = store.outcome(t, "cred-r-1").await.unwrap();
    assert_eq!(stored, Some(outcome.clone()));
    assert_eq!(
        stored.and_then(|o| o.reason).as_deref(),
        Some("provider_202")
    );

    let records = store.records(t, 0).await.unwrap();
    let report = verify_chain(
        &records,
        &signer.keys(),
        Some((2, denied_hash)),
        &[outcome],
        t0() + Duration::minutes(5),
    )
    .expect("chain verifies");
    assert_eq!(report.outcome_missing, Vec::<String>::new());
    assert_eq!(report.outcome_unknown, Vec::<String>::new());
    // Without the outcome, the expired allow is reported missing.
    let report = verify_chain(
        &records,
        &signer.keys(),
        None,
        &[],
        t0() + Duration::minutes(5),
    )
    .expect("chain verifies");
    assert_eq!(report.outcome_missing, vec!["cred-r-1".to_string()]);
    records
        .into_iter()
        .map(|r| r.into_decision().expect("a chain of decisions only"))
        .collect()
}

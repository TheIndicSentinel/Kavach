//! `AgentEvidenceStore` contract (H5a-3b). Every store — in-memory and
//! Postgres — runs this suite, including the concurrency cases.

use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::{Duration, NaiveDate, TimeZone, Utc};
use ed25519_dalek::{Signer, SigningKey};
use kavach_domain::Decision;
use kavach_ports::agent_evidence::{
    sign_outcome, verify_chain, Actor, AgentDecisionPayload, AgentEvidenceStore, CommitRequest,
    CommitResult, ContactReservation, EvidenceSigner, Outcome, PolicyVersions, RequestBinding,
    TimeSync, HASH_ALG_V2, KIND_AGENT_DECISION,
};
use kavach_ports::{KeyAlgorithm, PortError, PublicKey, SyncStatus};

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
    cap_holds_under_concurrency(store, signer).await;
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

    // Outcomes: once per credential, only for an allowed record.
    let outcome = sign_outcome(
        t,
        "cred-r-1",
        &record.hash,
        Outcome::Delivered,
        t0(),
        signer,
    )
    .unwrap();
    store.record_outcome(outcome.clone()).await.unwrap();
    assert!(store.record_outcome(outcome.clone()).await.is_err(), "once");
    let stray = sign_outcome(t, "cred-none", &record.hash, Outcome::Failed, t0(), signer).unwrap();
    assert!(
        store.record_outcome(stray).await.is_err(),
        "unknown credential"
    );
    assert_eq!(
        store.outcome(t, "cred-r-1").await.unwrap(),
        Some(outcome.clone())
    );

    let records = store.records(t, 0).await.unwrap();
    let report = verify_chain(
        &records,
        &signer.keys(),
        Some((2, denied.hash.as_str())),
        &[outcome],
        t0() + Duration::minutes(5),
    )
    .expect("chain verifies");
    assert!(report.outcome_unknown.is_empty());
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

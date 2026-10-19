//! The reconciler of unknown outcomes (ADR-017 R2): it asks, never sends; it
//! writes only a provider's confirmed answer or its own `ambiguous`; it is
//! bounded in time, retries and rate; and it never releases a contact slot.

mod common;

use common::*;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Duration, Utc};
use kavach_dataplane::outcome_reconciler::{
    MAX_QUESTIONS_PER_OUTCOME, MAX_QUESTIONS_PER_PASS, UNKNOWN_OUTCOME_AMBIGUOUS_AFTER,
    UNKNOWN_OUTCOME_POLL_WINDOW,
};
use kavach_dataplane::{
    reconcile_outcomes, AgentIdentity, AuthorizeConfig, AuthorizeCore, CommitStatus, Mode,
    PollState, ProviderStatus, StatusAnswer, StatusAsker, ToolCall,
};
use kavach_domain::Decision;
use kavach_keys::{InMemoryKeyProvider, SubjectKeys};
use kavach_mandate::memory::{InMemoryConsentSource, InMemoryEventBus, InMemoryMandateStore};
use kavach_mandate::{MandateDeps, MandateService};
use kavach_ports::agent_evidence::{sign_outcome, AgentEvidenceStore, Outcome};
use kavach_ports::outcome_resolution::{
    governing, outcome_ref, sign_resolution, Governing, ResolutionDraft, ResolutionSource,
    ResolutionState,
};
use kavach_ports::{PortError, StatusQuestions, TimeSource, TokenSecret};
use kavach_ports_testkit::agent_evidence::TestSigner;
use kavach_ports_testkit::{FakeClock, InMemoryReplayGuard};
use kavach_storage::MemoryAgentEvidenceStore;

type Service = MandateService<
    InMemoryKeyProvider,
    InMemoryReplayGuard,
    InMemoryConsentSource,
    InMemoryMandateStore,
    InMemoryEventBus,
    Clock,
>;

struct World {
    clock: Arc<FakeClock>,
    mandates: Arc<Service>,
    core: AuthorizeCore<Arc<Service>, MemoryAgentEvidenceStore>,
    sor: InMemoryKeyProvider,
    signer: TestSigner,
}

fn world() -> World {
    let clock = Arc::new(FakeClock::synced_at(ist(11, 0, 0)));
    let Setup {
        kavach,
        sor,
        consents,
        config,
    } = setup();
    let mandates = Arc::new(
        MandateService::new(
            MandateDeps {
                keys: kavach,
                replay: InMemoryReplayGuard::new(),
                consents: InMemoryConsentSource::new(consents),
                store: InMemoryMandateStore::new(),
                events: InMemoryEventBus::new(),
                clock: Clock(Arc::clone(&clock)),
            },
            config,
        )
        .expect("valid config"),
    );
    let core = AuthorizeCore::new(
        Arc::clone(&mandates),
        Arc::new(MemoryAgentEvidenceStore::default()),
        common::tools(),
        SubjectKeys::from_secret([6u8; 32]),
        Box::new(TestSigner::new("evidence-test", 9)),
        Box::new(Clock(Arc::clone(&clock))),
        AuthorizeConfig::default(),
    )
    .expect("core");
    World {
        clock,
        mandates,
        core,
        sor,
        signer: TestSigner::new("evidence-test", 9),
    }
}

fn agent() -> AgentIdentity {
    AgentIdentity {
        agent_id: "collections-agent".into(),
        identity_key: "oidc:https://idp#collections-agent".into(),
    }
}

fn reminder(mandate_id: &str, request_id: &str) -> ToolCall {
    ToolCall {
        mandate_id: mandate_id.into(),
        action: "send_reminder".into(),
        request_id: request_id.into(),
        subject_ref: SUBJECT.into(),
        channel: Some("whatsapp".into()),
        waiver_bps: None,
        requested_fields: BTreeSet::new(),
        extra: BTreeMap::from([("template_id".to_string(), "emi_reminder_v1".to_string())]),
        violations: Vec::new(),
    }
}

/// What the provider is scripted to say, and what it was asked.
#[derive(Default)]
struct Provider {
    answer: Mutex<Option<StatusAnswer>>,
    asked: Mutex<Vec<(String, String)>>,
}

impl Provider {
    fn says(&self, status: Option<ProviderStatus>) {
        *self.answer.lock().unwrap() = status.map(|status| StatusAnswer {
            status,
            digest: "ab".repeat(32),
        });
    }

    fn questions(&self) -> usize {
        self.asked.lock().unwrap().len()
    }
}

impl StatusAsker for Provider {
    fn status(
        &self,
        provider: &str,
        jti: &str,
        question: &TokenSecret,
    ) -> impl std::future::Future<Output = Option<StatusAnswer>> + Send {
        assert!(!question.expose().contains("+91"), "a destination");
        self.asked
            .lock()
            .unwrap()
            .push((provider.to_string(), jti.to_string()));
        std::future::ready(self.answer.lock().unwrap().clone())
    }
}

struct Questions;

impl StatusQuestions for Questions {
    fn status_question(
        &self,
        tenant_id: &str,
        audience: &str,
        jti: &str,
        _now: DateTime<Utc>,
    ) -> impl std::future::Future<Output = Result<TokenSecret, PortError>> + Send {
        std::future::ready(Ok(TokenSecret::new(format!(
            "q.{tenant_id}.{audience}.{jti}"
        ))))
    }
}

impl World {
    async fn mandate_for(&self, borrower: &str) -> String {
        let token = event_token(&self.sor, borrower, self.clock.now().utc).await;
        self.mandates
            .issue_from_event(&token)
            .await
            .unwrap()
            .mandate
            .id
    }

    fn advance(&self, by: Duration) {
        self.clock.advance(by);
    }

    /// An allowed reminder whose send ended `unknown`; returns its credential.
    async fn unknown_send(&self, mandate: &str, request_id: &str) -> String {
        let decided = self
            .core
            .authorize(&agent(), &reminder(mandate, request_id), Mode::Commit)
            .await
            .unwrap();
        assert_eq!(decided.decision, Decision::Pass, "{:?}", decided.reasons);
        assert_eq!(decided.status, CommitStatus::Committed);
        let record = decided.record.unwrap();
        let credential = record.payload.credential_id.clone().unwrap();
        let outcome = sign_outcome(
            TENANT,
            &credential,
            &record.hash,
            Outcome::Unknown,
            "timeout_after_send",
            self.clock.now().utc,
            &self.signer,
        )
        .unwrap();
        self.core.store().record_outcome(outcome).await.unwrap();
        credential
    }

    async fn pass(
        &self,
        provider: &Provider,
        polls: &mut PollState,
    ) -> kavach_dataplane::OutcomeReconcileReport {
        reconcile_outcomes(&self.core, provider, &Questions, polls).await
    }

    async fn resolutions(
        &self,
        credential: &str,
    ) -> Vec<kavach_ports::outcome_resolution::ResolutionRecord> {
        self.core
            .store()
            .resolutions(TENANT, credential)
            .await
            .unwrap()
    }
}

/// A confirmed answer inside the window becomes a `provider_status`
/// resolution carrying the digest of the answer, and the question is not
/// asked again once it is settled.
#[tokio::test]
async fn a_confirmed_answer_is_written_as_a_provider_status_resolution() {
    for (says, state) in [
        (
            ProviderStatus::Delivered,
            ResolutionState::ConfirmedDelivered,
        ),
        (
            ProviderStatus::NotDelivered,
            ResolutionState::ConfirmedNotDelivered,
        ),
    ] {
        let w = world();
        let provider = Provider::default();
        let mut polls = PollState::default();
        let mandate = w.mandate_for("B-9382").await;
        let credential = w.unknown_send(&mandate, "r-1").await;

        // Too soon: nothing is asked in the first 30 seconds.
        assert_eq!(w.pass(&provider, &mut polls).await.asked, 0);
        w.advance(Duration::seconds(31));
        provider.says(Some(says));
        let report = w.pass(&provider, &mut polls).await;
        assert_eq!((report.open, report.asked), (1, 1), "{report:?}");
        let expected = if state == ResolutionState::ConfirmedDelivered {
            (1, 0)
        } else {
            (0, 1)
        };
        assert_eq!(
            (report.confirmed_delivered, report.confirmed_not_delivered),
            expected
        );

        let rows = w.resolutions(&credential).await;
        let [row] = rows.as_slice() else {
            panic!("one resolution, got {rows:?}");
        };
        assert_eq!(
            (row.state, row.source),
            (state, ResolutionSource::ProviderStatus)
        );
        assert_eq!(
            row.evidence_digest.as_deref(),
            Some("ab".repeat(32).as_str())
        );
        assert!(row.resolved_by.is_none() && row.approved_by.is_none());
        assert!(matches!(governing(&rows), Governing::Confirmed { .. }));
        let outcome = w
            .core
            .store()
            .outcome(TENANT, &credential)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.outcome_ref, outcome_ref(&outcome), "names that row");
        assert_eq!(
            outcome.outcome,
            Outcome::Unknown,
            "the outcome is not rewritten"
        );

        // Settled: the next pass has nothing to do and asks nothing.
        w.advance(Duration::minutes(5));
        let after = w.pass(&provider, &mut polls).await;
        assert_eq!((after.open, after.asked), (0, 0));
        assert_eq!(provider.questions(), 1);
    }
}

/// "I cannot say" and no answer write nothing; the question is repeated with
/// back-off, at most [`MAX_QUESTIONS_PER_OUTCOME`] times, and never after the
/// window.
#[tokio::test]
async fn no_answer_writes_nothing_and_the_questions_are_bounded() {
    let w = world();
    let provider = Provider::default();
    let mut polls = PollState::default();
    let mandate = w.mandate_for("B-9382").await;
    let credential = w.unknown_send(&mandate, "r-1").await;

    provider.says(Some(ProviderStatus::Unknown));
    w.advance(Duration::seconds(31));
    assert_eq!(w.pass(&provider, &mut polls).await.no_answer, 1);
    // Back-off: asked again at once, nothing is put.
    assert_eq!(w.pass(&provider, &mut polls).await.asked, 0);
    w.advance(Duration::seconds(30));
    assert_eq!(
        w.pass(&provider, &mut polls).await.asked,
        0,
        "waits a minute"
    );
    w.advance(Duration::seconds(31));
    provider.says(None);
    assert_eq!(w.pass(&provider, &mut polls).await.no_answer, 1);

    // Keep going; the count stops at the cap and never passes the window.
    for _ in 0..40 {
        w.advance(Duration::minutes(2));
        if w.clock.now().utc
            - w.core
                .store()
                .outcome(TENANT, &credential)
                .await
                .unwrap()
                .unwrap()
                .ts
            >= UNKNOWN_OUTCOME_POLL_WINDOW
        {
            break;
        }
        w.pass(&provider, &mut polls).await;
    }
    assert!(
        provider.questions() <= usize::try_from(MAX_QUESTIONS_PER_OUTCOME).unwrap(),
        "{} questions",
        provider.questions()
    );
    assert_eq!(w.resolutions(&credential).await, [], "nothing was learned");

    // Past the window and before 24 hours: left alone.
    w.advance(UNKNOWN_OUTCOME_POLL_WINDOW);
    let asked = provider.questions();
    let report = w.pass(&provider, &mut polls).await;
    assert_eq!((report.open, report.asked, report.ambiguous), (1, 0, 0));
    assert_eq!(provider.questions(), asked);
}

/// 24 hours with nothing confirmed: `ambiguous`, from the reconciler, once.
/// A person's later attestation still governs; nothing is promoted.
#[tokio::test]
async fn after_24_hours_it_says_ambiguous_once_and_never_promotes_it() {
    let w = world();
    let provider = Provider::default();
    let mut polls = PollState::default();
    let mandate = w.mandate_for("B-9382").await;
    let credential = w.unknown_send(&mandate, "r-1").await;

    w.advance(UNKNOWN_OUTCOME_AMBIGUOUS_AFTER - Duration::seconds(1));
    assert_eq!(w.pass(&provider, &mut polls).await.ambiguous, 0);
    w.advance(Duration::seconds(1));
    let report = w.pass(&provider, &mut polls).await;
    assert_eq!((report.ambiguous, report.asked), (1, 0), "{report:?}");
    let rows = w.resolutions(&credential).await;
    let [row] = rows.as_slice() else {
        panic!("one row, got {rows:?}");
    };
    assert_eq!(
        (row.state, row.source),
        (ResolutionState::Ambiguous, ResolutionSource::Reconciler)
    );
    assert!(row.evidence_digest.is_none() && row.resolved_by.is_none());
    assert_eq!(governing(&rows), Governing::Ambiguous);

    // Once: the outcome leaves the work list, so a later pass writes nothing.
    assert_eq!(w.pass(&provider, &mut polls).await.open, 0);
    assert_eq!(w.resolutions(&credential).await.len(), 1);
    assert_eq!(provider.questions(), 0, "nobody was asked after the window");
}

/// A person who has attested "delivered" stops the reconciler from saying
/// `ambiguous` over it.
#[tokio::test]
async fn an_attested_outcome_is_not_called_ambiguous() {
    let w = world();
    let provider = Provider::default();
    let mut polls = PollState::default();
    let mandate = w.mandate_for("B-9382").await;
    let credential = w.unknown_send(&mandate, "r-1").await;
    let outcome = w
        .core
        .store()
        .outcome(TENANT, &credential)
        .await
        .unwrap()
        .unwrap();
    let attested = sign_resolution(
        ResolutionDraft {
            tenant_id: TENANT.into(),
            credential_id: credential.clone(),
            outcome_ref: outcome_ref(&outcome),
            state: ResolutionState::ConfirmedDelivered,
            source: ResolutionSource::OperatorAttested,
            reason: "console".into(),
            evidence_digest: Some("cd".repeat(32)),
            resolved_by: Some("oidc:https://idp#ops-1".into()),
            approved_by: None,
        },
        w.clock.now().utc,
        &w.signer,
    )
    .unwrap();
    w.core.store().record_resolution(attested).await.unwrap();

    w.advance(UNKNOWN_OUTCOME_AMBIGUOUS_AFTER + Duration::hours(1));
    let report = w.pass(&provider, &mut polls).await;
    assert_eq!((report.open, report.ambiguous, report.asked), (0, 0, 0));
    assert_eq!(w.resolutions(&credential).await.len(), 1);
}

/// The rate limit: no pass puts more than [`MAX_QUESTIONS_PER_PASS`]
/// questions, whatever is waiting; the rest wait for the next pass.
#[tokio::test]
async fn a_pass_puts_a_bounded_number_of_questions() {
    let w = world();
    let provider = Provider::default();
    let mut polls = PollState::default();
    provider.says(Some(ProviderStatus::Unknown));
    let wanted = MAX_QUESTIONS_PER_PASS + 3;
    // Committed straight to the store, so that one mandate's daily cap does
    // not limit how many unknown sends there are.
    let store = w.core.store();
    for n in 0..wanted {
        let committed = store
            .commit(
                kavach_ports_testkit::agent_evidence::request(TENANT, &format!("rate-{n}"), 100),
                &Clock(Arc::clone(&w.clock)),
                &w.signer,
            )
            .await
            .unwrap();
        let kavach_ports::agent_evidence::CommitResult::Committed(record) = committed else {
            panic!("committed");
        };
        let outcome = sign_outcome(
            TENANT,
            record.payload.credential_id.as_deref().unwrap(),
            &record.hash,
            Outcome::Unknown,
            "timeout_after_send",
            w.clock.now().utc,
            &w.signer,
        )
        .unwrap();
        store.record_outcome(outcome).await.unwrap();
    }
    w.advance(Duration::seconds(31));
    let report = w.pass(&provider, &mut polls).await;
    assert_eq!(report.open, wanted);
    assert_eq!(report.asked, MAX_QUESTIONS_PER_PASS, "{report:?}");
    assert_eq!(report.deferred, 3);
    assert_eq!(provider.questions(), MAX_QUESTIONS_PER_PASS);
}

/// A resolution never releases the contact slot: `confirmed_not_delivered`
/// is the case where releasing it would be most tempting.
#[tokio::test]
async fn learning_that_nothing_was_delivered_does_not_free_a_contact_slot() {
    let w = world();
    let provider = Provider::default();
    let mut polls = PollState::default();
    let mandate = w.mandate_for("B-9382").await;
    // The window allows three contacts a day; use all three, each unknown.
    let mut credentials = Vec::new();
    for n in 0..3 {
        credentials.push(w.unknown_send(&mandate, &format!("r-{n}")).await);
    }
    let fourth = |id: &str| reminder(&mandate, id);
    let blocked = w
        .core
        .authorize(&agent(), &fourth("r-3"), Mode::Commit)
        .await
        .unwrap();
    assert_eq!(blocked.decision, Decision::Block, "the cap is used up");

    w.advance(Duration::seconds(31));
    provider.says(Some(ProviderStatus::NotDelivered));
    let report = w.pass(&provider, &mut polls).await;
    assert_eq!(report.confirmed_not_delivered, 3, "{report:?}");
    for credential in &credentials {
        assert!(matches!(
            governing(&w.resolutions(credential).await),
            Governing::Confirmed {
                state: ResolutionState::ConfirmedNotDelivered,
                ..
            }
        ));
    }

    // Still blocked: the slots stay counted whatever was learned.
    let still = w
        .core
        .authorize(&agent(), &fourth("r-4"), Mode::Commit)
        .await
        .unwrap();
    assert_eq!(still.decision, Decision::Block, "{:?}", still.reasons);
}

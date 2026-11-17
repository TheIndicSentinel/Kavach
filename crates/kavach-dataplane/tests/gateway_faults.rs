//! The gateway under injected faults (F7 and the fault-injection table).
//!
//! The authorization core runs on a real store wrapped in a double that fails
//! on command; the resolver, the broker and the forwarder are doubles too.
//! Whatever fails, a message goes to the provider at most once, and an allow
//! whose outcome could not be written does not stay "in flight" forever.

mod common;

use common::*;

use std::future::Future;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Duration, Utc};
use kavach_dataplane::gateway::{execute, GatewayDeps, GatewayError, GatewayObserver};
use kavach_dataplane::{
    reconcile_outcomes, AgentIdentity, AuthorizeConfig, AuthorizeCore, ForwardResult, Forwarder,
    MandateVerifier, PollState, ProviderStatus, StatusAnswer, StatusAsker, ToolRequest,
};
use kavach_domain::Decision;
use kavach_keys::{InMemoryKeyProvider, SubjectKeys};
use kavach_mandate::memory::{InMemoryConsentSource, InMemoryEventBus, InMemoryMandateStore};
use kavach_mandate::{MandateDeps, MandateService};
use kavach_ports::agent_evidence::{AgentEvidenceStore, Outcome};
use kavach_ports::{
    CredentialBroker, CredentialRequest, Destination, ErrorClass, IssuedCredential, PortError,
    ReferenceResolver, StatusQuestions, TimeSource, TokenSecret,
};
use kavach_ports_testkit::agent_evidence::TestSigner;
use kavach_ports_testkit::faulty_store::{Faults, FaultyStore};
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

/// The mandate verifier, failing from its `n`th call on (the first call is
/// the decision, the second the check just before the credential is minted).
struct Gate {
    inner: Arc<Service>,
    calls: AtomicU32,
    fail_from: AtomicU32,
    class: Mutex<ErrorClass>,
}

impl MandateVerifier for Gate {
    async fn verify(
        &self,
        tenant_id: &str,
        mandate_id: &str,
    ) -> Result<kavach_mandate::VerifiedChain, PortError> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        let from = self.fail_from.load(Ordering::SeqCst);
        if from != 0 && n >= from {
            let class = *self.class.lock().unwrap();
            return Err(PortError {
                class,
                message: "injected".into(),
            });
        }
        MandateVerifier::verify(&self.inner, tenant_id, mandate_id).await
    }
}

#[derive(Default)]
struct Resolver {
    fail: Mutex<Option<ErrorClass>>,
}

impl ReferenceResolver for Resolver {
    fn resolve(
        &self,
        _tenant_id: &str,
        _subject_ref: &str,
        _channel: &str,
    ) -> impl Future<Output = Result<Destination, PortError>> + Send {
        std::future::ready(match *self.fail.lock().unwrap() {
            Some(class) => Err(PortError {
                class,
                message: "injected".into(),
            }),
            None => Ok(Destination::new("+910000000001")),
        })
    }

    fn describe(&self) -> String {
        "test double".into()
    }
}

#[derive(Default)]
struct Broker {
    fail: Mutex<Option<ErrorClass>>,
}

impl CredentialBroker for Broker {
    fn issue(
        &self,
        request: &CredentialRequest<'_>,
    ) -> impl Future<Output = Result<IssuedCredential, PortError>> + Send {
        std::future::ready(match *self.fail.lock().unwrap() {
            Some(class) => Err(PortError {
                class,
                message: "injected".into(),
            }),
            None => Ok(IssuedCredential {
                credential_id: request.credential_id.into(),
                token: TokenSecret::new("test-credential"),
                expires_at: request.expires_at,
            }),
        })
    }

    fn revoke_by_mandate(
        &self,
        _t: &str,
        _m: &str,
    ) -> impl Future<Output = Result<u64, PortError>> + Send {
        std::future::ready(Ok(0))
    }

    fn is_test_double(&self) -> bool {
        true
    }
}

/// What the provider "said", and how many times it was sent to.
struct Forwarder_ {
    result: Mutex<ForwardResult>,
    sends: AtomicUsize,
}

impl Default for Forwarder_ {
    fn default() -> Self {
        Self {
            result: Mutex::new(ForwardResult::Responded {
                status: 202,
                message_id: Some("pm-1".into()),
            }),
            sends: AtomicUsize::new(0),
        }
    }
}

impl Forwarder for Forwarder_ {
    fn forward(
        &self,
        _provider: &str,
        _credential: &TokenSecret,
    ) -> impl Future<Output = ForwardResult> + Send {
        self.sends.fetch_add(1, Ordering::SeqCst);
        std::future::ready(self.result.lock().unwrap().clone())
    }
}

#[derive(Default)]
struct Observer {
    outcome_write_failures: AtomicU32,
}

impl GatewayObserver for Observer {
    fn call(&self, _tool: &str, _decision: Decision, _outcome: Option<Outcome>) {}
    fn jti_conflict(&self) {}
    fn outcome_write_failed(&self) {
        self.outcome_write_failures.fetch_add(1, Ordering::SeqCst);
    }
}

/// What the provider answers a status question with.
#[derive(Default)]
struct Asker {
    answer: Mutex<Option<ProviderStatus>>,
    asked: AtomicUsize,
}

impl StatusAsker for Asker {
    fn status(
        &self,
        _provider: &str,
        _jti: &str,
        _question: &TokenSecret,
    ) -> impl std::future::Future<Output = Option<StatusAnswer>> + Send {
        self.asked.fetch_add(1, Ordering::SeqCst);
        std::future::ready(self.answer.lock().unwrap().map(|status| StatusAnswer {
            status,
            digest: "ab".repeat(32),
        }))
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

type Core = AuthorizeCore<Arc<Gate>, FaultyStore<MemoryAgentEvidenceStore>>;

struct World {
    clock: Arc<FakeClock>,
    mandates: Arc<Service>,
    core: Core,
    gate: Arc<Gate>,
    sor: InMemoryKeyProvider,
    resolver: Resolver,
    broker: Broker,
    forwarder: Forwarder_,
    observer: Observer,
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
    let gate = Arc::new(Gate {
        inner: Arc::clone(&mandates),
        calls: AtomicU32::new(0),
        fail_from: AtomicU32::new(0),
        class: Mutex::new(ErrorClass::Unavailable),
    });
    let core = AuthorizeCore::new(
        Arc::clone(&gate),
        Arc::new(FaultyStore::new(MemoryAgentEvidenceStore::default())),
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
        gate,
        sor,
        resolver: Resolver::default(),
        broker: Broker::default(),
        forwarder: Forwarder_::default(),
        observer: Observer::default(),
    }
}

fn agent() -> AgentIdentity {
    AgentIdentity {
        agent_id: "collections-agent".into(),
        identity_key: "oidc:https://idp#collections-agent".into(),
    }
}

fn request(mandate: &str, request_id: &str) -> ToolRequest {
    let params = serde_json::json!({
        "subject_ref": SUBJECT,
        "channel": "whatsapp",
        "template_id": "emi_reminder_v1",
    });
    ToolRequest {
        mandate_id: mandate.into(),
        request_id: request_id.into(),
        approval_id: None,
        params: params.as_object().unwrap().clone(),
    }
}

impl World {
    async fn mandate(&self) -> String {
        let token = event_token(&self.sor, "B-9382", self.clock.now().utc).await;
        self.mandates
            .issue_from_event(&token)
            .await
            .unwrap()
            .mandate
            .id
    }

    async fn call(
        &self,
        mandate: &str,
        request_id: &str,
    ) -> Result<kavach_dataplane::gateway::GatewayReply, GatewayError> {
        let deps = GatewayDeps {
            core: &self.core,
            resolver: &self.resolver,
            broker: &self.broker,
            forwarder: &self.forwarder,
            gateway_held: None,
            observer: &self.observer,
        };
        execute(
            &deps,
            &agent(),
            "send_reminder",
            request(mandate, request_id),
        )
        .await
    }

    fn gate_fails_from(&self, n: u32, class: ErrorClass) {
        self.gate.fail_from.store(n, Ordering::SeqCst);
        *self.gate.class.lock().unwrap() = class;
    }

    fn forward_returns(&self, result: ForwardResult) {
        *self.forwarder.result.lock().unwrap() = result;
    }

    fn sends(&self) -> usize {
        self.forwarder.sends.load(Ordering::SeqCst)
    }

    fn advance(&self, by: Duration) {
        self.clock.advance(by);
    }

    fn store(&self) -> &FaultyStore<MemoryAgentEvidenceStore> {
        self.core.store()
    }

    async fn stored_outcome(
        &self,
        request_id: &str,
    ) -> Option<kavach_ports::agent_evidence::OutcomeRecord> {
        let record = self
            .store()
            .get_by_request(TENANT, "collections-agent", request_id)
            .await
            .unwrap()?;
        self.store()
            .outcome(TENANT, record.payload.credential_id.as_deref()?)
            .await
            .unwrap()
    }

    /// One reconciler pass, with a provider that answers `says`.
    async fn reconcile(
        &self,
        says: Option<ProviderStatus>,
    ) -> kavach_dataplane::OutcomeReconcileReport {
        let asker = Asker::default();
        *asker.answer.lock().unwrap() = says;
        let mut polls = PollState::default();
        reconcile_outcomes(&self.core, &asker, &Questions, &mut polls).await
    }
}

/// F7, part one: a transient failure of the outcome write is retried, so the
/// outcome is recorded and the agent is told so.
#[tokio::test]
async fn a_transient_outcome_write_failure_is_retried() {
    let w = world();
    let mandate = w.mandate().await;
    Faults::fail(&w.store().faults.record_outcome, 2);
    let reply = w.call(&mandate, "r-1").await.unwrap();
    assert_eq!(reply.outcome, Some(Outcome::Delivered));
    assert!(reply.outcome_recorded, "the write was retried: {reply:?}");
    assert_eq!(
        w.stored_outcome("r-1").await.map(|o| o.outcome),
        Some(Outcome::Delivered)
    );
    assert_eq!(w.sends(), 1);
}

/// F7, part two: a write that keeps failing leaves an allow with no outcome.
/// It must not stay "in flight" for ever: after the stuck window the
/// reconciler records `unknown` (never delivered or not delivered, because it
/// does not know), the retry then gets that stored outcome, and the existing
/// status question resolves it. The message was sent once throughout.
#[tokio::test]
async fn an_allow_whose_outcome_was_never_recorded_is_recovered_as_unknown() {
    let w = world();
    let mandate = w.mandate().await;
    Faults::fail(&w.store().faults.record_outcome, Faults::FOREVER);
    let reply = w.call(&mandate, "r-1").await.unwrap();
    assert!(!reply.outcome_recorded);
    assert_eq!(w.sends(), 1);
    assert!(matches!(
        w.call(&mandate, "r-1").await,
        Err(GatewayError::InFlight)
    ));

    // The store comes back. Before the window the reconciler leaves it alone
    // (a live call may still be about to write its own outcome).
    Faults::fail(&w.store().faults.record_outcome, 0);
    w.advance(Duration::seconds(30));
    let early = w.reconcile(None).await;
    assert_eq!(early.recovered, 0, "{early:?}");
    assert!(matches!(
        w.call(&mandate, "r-1").await,
        Err(GatewayError::InFlight)
    ));

    // Past the window it records unknown.
    w.advance(Duration::minutes(10));
    let pass = w.reconcile(None).await;
    assert_eq!(pass.recovered, 1, "{pass:?}");
    let stored = w.stored_outcome("r-1").await.expect("an outcome now");
    assert_eq!(stored.outcome, Outcome::Unknown);
    assert_eq!(stored.reason.as_deref(), Some("outcome_not_recorded"));
    let again = w.call(&mandate, "r-1").await.unwrap();
    assert_eq!(
        again.outcome,
        Some(Outcome::Unknown),
        "the in-flight answer ended"
    );
    assert_eq!(w.sends(), 1, "never sent again");

    // And the existing path resolves it from the provider's own answer.
    w.advance(Duration::minutes(1));
    let resolved = w.reconcile(Some(ProviderStatus::Delivered)).await;
    assert_eq!(resolved.confirmed_delivered, 1, "{resolved:?}");
}

/// What a fault must leave behind, however it happens.
#[derive(Debug, Clone, Copy)]
enum Expect {
    /// Nothing reached the provider; the call ended with this recorded
    /// outcome and reason (`None`: no decision, nothing recorded at all).
    NeverForwarded(Option<(Outcome, &'static str)>),
    /// The provider was sent to exactly once; the outcome recorded is this.
    ForwardedOnce(Outcome, &'static str),
}

/// A fault to inject, where, and what must follow.
struct Case {
    name: &'static str,
    inject: fn(&World),
    expect: Expect,
}

fn responded(status: u16) -> ForwardResult {
    ForwardResult::Responded {
        status,
        message_id: None,
    }
}

fn cases() -> Vec<Case> {
    let mut all = before_the_send();
    all.extend(the_send_and_its_answer());
    all
}

/// Faults before anything is sent: nothing may reach the provider.
fn before_the_send() -> Vec<Case> {
    use Expect::NeverForwarded;
    use Outcome::NotExecuted;
    vec![
        // Reference resolution.
        Case {
            name: "resolver unavailable",
            inject: |w| *w.resolver.fail.lock().unwrap() = Some(ErrorClass::Unavailable),
            expect: NeverForwarded(Some((NotExecuted, "resolver_unavailable"))),
        },
        Case {
            name: "resolver has no destination",
            inject: |w| *w.resolver.fail.lock().unwrap() = Some(ErrorClass::Rejected),
            expect: NeverForwarded(Some((NotExecuted, "no_destination"))),
        },
        Case {
            name: "resolver refuses the reference",
            inject: |w| *w.resolver.fail.lock().unwrap() = Some(ErrorClass::Invalid),
            expect: NeverForwarded(Some((NotExecuted, "invalid_reference"))),
        },
        // The check just before the credential is minted.
        Case {
            name: "mandate store unavailable at the second check",
            inject: |w| w.gate_fails_from(2, ErrorClass::Unavailable),
            expect: NeverForwarded(Some((NotExecuted, "mandate_unavailable"))),
        },
        Case {
            name: "mandate gone at the second check",
            inject: |w| w.gate_fails_from(2, ErrorClass::Rejected),
            expect: NeverForwarded(Some((NotExecuted, "mandate_revoked"))),
        },
        Case {
            name: "agent state unreadable at the second check",
            inject: |w| {
                Faults::fail(&w.store().faults.agent_state, Faults::FOREVER);
                // The decision reads the state once; the check reads it again.
                w.store().faults.agent_state_skip.store(1, Ordering::SeqCst);
            },
            expect: NeverForwarded(Some((NotExecuted, "mandate_unavailable"))),
        },
        // Minting the credential.
        Case {
            name: "broker unavailable",
            inject: |w| *w.broker.fail.lock().unwrap() = Some(ErrorClass::Unavailable),
            expect: NeverForwarded(Some((NotExecuted, "credential_unavailable"))),
        },
        Case {
            name: "broker refuses",
            inject: |w| *w.broker.fail.lock().unwrap() = Some(ErrorClass::Rejected),
            expect: NeverForwarded(Some((NotExecuted, "credential_refused"))),
        },
        Case {
            name: "broker rejects the request as malformed",
            inject: |w| *w.broker.fail.lock().unwrap() = Some(ErrorClass::Invalid),
            expect: NeverForwarded(Some((NotExecuted, "credential_invalid"))),
        },
    ]
}

/// The send, and how every answer is classified: sent exactly once.
fn the_send_and_its_answer() -> Vec<Case> {
    use Expect::ForwardedOnce;
    use Outcome::{Delivered, Failed, Refused, Unknown};
    vec![
        Case {
            name: "provider unreachable (nothing was sent)",
            inject: |w| w.forward_returns(ForwardResult::NotSent),
            expect: ForwardedOnce(Failed, "connect_failed"),
        },
        Case {
            name: "response lost after sending",
            inject: |w| w.forward_returns(ForwardResult::Lost),
            expect: ForwardedOnce(Unknown, "timeout_after_send"),
        },
        Case {
            name: "provider says 202",
            inject: |w| w.forward_returns(responded(202)),
            expect: ForwardedOnce(Delivered, "provider_202"),
        },
        Case {
            name: "provider says 200 (a repeat)",
            inject: |w| w.forward_returns(responded(200)),
            expect: ForwardedOnce(Delivered, "provider_200"),
        },
        Case {
            name: "provider says 422",
            inject: |w| w.forward_returns(responded(422)),
            expect: ForwardedOnce(Refused, "provider_422"),
        },
        Case {
            name: "provider says 429",
            inject: |w| w.forward_returns(responded(429)),
            expect: ForwardedOnce(Refused, "provider_429"),
        },
        Case {
            name: "provider says 408",
            inject: |w| w.forward_returns(responded(408)),
            expect: ForwardedOnce(Unknown, "provider_408"),
        },
        Case {
            name: "provider says 409 (the id was used for other claims)",
            inject: |w| w.forward_returns(responded(409)),
            expect: ForwardedOnce(Unknown, "provider_409"),
        },
        Case {
            name: "provider says 500",
            inject: |w| w.forward_returns(responded(500)),
            expect: ForwardedOnce(Unknown, "provider_500"),
        },
        Case {
            name: "provider answers with a redirect",
            inject: |w| w.forward_returns(responded(302)),
            expect: ForwardedOnce(Unknown, "provider_302"),
        },
        Case {
            name: "provider answers 201, which is not in the contract",
            inject: |w| w.forward_returns(responded(201)),
            expect: ForwardedOnce(Unknown, "provider_201"),
        },
    ]
}

/// Whatever fails at whatever stage, the provider is sent to at most once,
/// the outcome recorded is the conservative reading of what happened, and
/// the agent retrying (twice more) neither sends again nor invents an
/// outcome.
#[tokio::test]
async fn every_fault_leaves_a_message_sent_once_or_never() {
    for case in cases() {
        check_case(&case).await;
    }
}

/// One fault, end to end, then the agent retrying twice.
async fn check_case(case: &Case) {
    let w = world();
    let mandate = w.mandate().await;
    (case.inject)(&w);
    let reply = w
        .call(&mandate, "r-1")
        .await
        .unwrap_or_else(|e| panic!("{}: {e:?}", case.name));
    let (sends, outcome) = match case.expect {
        Expect::NeverForwarded(o) => (0, o),
        Expect::ForwardedOnce(o, r) => (1, Some((o, r))),
    };
    assert_eq!(w.sends(), sends, "{}: sends", case.name);
    assert_eq!(
        reply.outcome.zip(reply.outcome_reason.as_deref()),
        outcome,
        "{}: reply {reply:?}",
        case.name
    );
    assert!(reply.outcome_recorded, "{}: {reply:?}", case.name);
    // What the store holds is what the reply said.
    let stored = w.stored_outcome("r-1").await;
    assert_eq!(
        stored
            .as_ref()
            .map(|o| (o.outcome, o.reason.clone().unwrap_or_default())),
        outcome.map(|(o, r)| (o, r.to_string())),
        "{}: stored",
        case.name
    );
    // Retries are answered from the record, never sent.
    for _ in 0..2 {
        let again = w.call(&mandate, "r-1").await.unwrap();
        assert!(again.replayed || again.outcome.is_some(), "{}", case.name);
        assert_eq!(
            again.outcome.zip(again.outcome_reason.as_deref()),
            outcome,
            "{}: replay",
            case.name
        );
    }
    assert_eq!(w.sends(), sends, "{}: sends after retries", case.name);
}

/// The evidence commit fails: there is no decision and nothing is sent; the
/// agent's retry, once the store is back, is a first call (the failed one
/// left nothing behind) and sends exactly once.
#[tokio::test]
async fn a_failed_commit_leaves_nothing_and_a_retry_sends_once() {
    let w = world();
    let mandate = w.mandate().await;
    Faults::fail(&w.store().faults.commit, 1);
    let reply = w.call(&mandate, "r-1").await.unwrap();
    assert_ne!(reply.decision, Decision::Pass, "{reply:?}");
    assert_eq!(w.sends(), 0);
    assert!(w.stored_outcome("r-1").await.is_none());
    assert!(w
        .store()
        .get_by_request(TENANT, "collections-agent", "r-1")
        .await
        .unwrap()
        .is_none());
    let retry = w.call(&mandate, "r-1").await.unwrap();
    assert_eq!(retry.outcome, Some(Outcome::Delivered), "{retry:?}");
    assert_eq!(w.sends(), 1);
    assert_eq!(
        w.call(&mandate, "r-1").await.unwrap().outcome,
        Some(Outcome::Delivered)
    );
    assert_eq!(w.sends(), 1, "forward-once");
}

/// The outcome cannot be read when a retry arrives: the answer is "in flight"
/// (a retry is never sent), and when the store is back the stored outcome is
/// returned.
#[tokio::test]
async fn an_unreadable_outcome_is_in_flight_never_a_second_send() {
    let w = world();
    let mandate = w.mandate().await;
    w.call(&mandate, "r-1").await.unwrap();
    Faults::fail(&w.store().faults.read_outcome, 1);
    assert!(matches!(
        w.call(&mandate, "r-1").await,
        Err(GatewayError::InFlight)
    ));
    assert_eq!(
        w.call(&mandate, "r-1").await.unwrap().outcome,
        Some(Outcome::Delivered)
    );
    assert_eq!(w.sends(), 1);
}

/// A write that never succeeds, at every point of the table: the recovery
/// finds the allow, records `unknown`, and nothing is ever sent twice.
#[tokio::test]
async fn an_outcome_that_cannot_be_written_is_recoverable_whatever_the_provider_said() {
    for result in [
        ForwardResult::Lost,
        ForwardResult::NotSent,
        responded(202),
        responded(422),
        responded(500),
    ] {
        let w = world();
        let mandate = w.mandate().await;
        w.forward_returns(result.clone());
        Faults::fail(&w.store().faults.record_outcome, Faults::FOREVER);
        let reply = w.call(&mandate, "r-1").await.unwrap();
        assert!(!reply.outcome_recorded, "{result:?}");
        assert_eq!(w.observer.outcome_write_failures.load(Ordering::SeqCst), 1);
        Faults::fail(&w.store().faults.record_outcome, 0);
        w.advance(Duration::minutes(10));
        let pass = w.reconcile(None).await;
        assert_eq!(pass.recovered, 1, "{result:?}: {pass:?}");
        // Unknown, whatever the provider said: this process does not know.
        assert_eq!(
            w.stored_outcome("r-1").await.map(|o| o.outcome),
            Some(Outcome::Unknown),
            "{result:?}"
        );
        assert_eq!(w.sends(), 1, "{result:?}");
        // A second pass finds nothing more to recover.
        assert_eq!(w.reconcile(None).await.recovered, 0);
    }
}

/// An allow that did record its outcome is never "recovered", whatever its
/// age; and neither is an allow that is still inside the window.
#[tokio::test]
async fn recovery_leaves_alone_what_has_an_outcome_or_is_still_young() {
    let w = world();
    let mandate = w.mandate().await;
    w.call(&mandate, "done").await.unwrap();
    Faults::fail(&w.store().faults.record_outcome, Faults::FOREVER);
    w.call(&mandate, "young").await.unwrap();
    Faults::fail(&w.store().faults.record_outcome, 0);
    w.advance(Duration::minutes(4));
    assert_eq!(w.reconcile(None).await.recovered, 0, "inside the window");
    w.advance(Duration::minutes(2));
    assert_eq!(
        w.reconcile(None).await.recovered,
        1,
        "only the one without an outcome"
    );
    assert_eq!(
        w.stored_outcome("done").await.map(|o| o.outcome),
        Some(Outcome::Delivered),
        "an outcome that exists is not touched"
    );
}

#[test]
fn the_stuck_window_is_far_above_the_longest_call() {
    use kavach_dataplane::outcome_reconciler::STUCK_OUTCOME_WINDOW;
    // A credential lives at most this long, and the provider timeout is below it.
    let longest = Duration::seconds(kavach_ports::MAX_CREDENTIAL_TTL_SECONDS);
    assert!(
        STUCK_OUTCOME_WINDOW >= longest * 10,
        "{STUCK_OUTCOME_WINDOW:?} vs {longest:?}"
    );
}

/// Two reconciler replicas recovering the same stuck allow: the second one
/// read its work list before the first wrote, so it tries to write an outcome
/// that now exists. It loses cleanly: no second outcome, no error, nothing
/// reported as a problem, and the first replica's `unknown` stands.
#[tokio::test]
async fn a_second_replica_recovering_the_same_allow_loses_cleanly() {
    let w = world();
    let mandate = w.mandate().await;
    Faults::fail(&w.store().faults.record_outcome, Faults::FOREVER);
    w.call(&mandate, "r-1").await.unwrap();
    Faults::fail(&w.store().faults.record_outcome, 0);
    w.advance(Duration::minutes(10));

    // Replica B read its list, then replica A recovered the allow.
    let now = w.clock.now().utc;
    let seen_by_b = w
        .store()
        .stuck_allows(
            TENANT,
            now - Duration::days(7),
            now - Duration::minutes(5),
            100,
        )
        .await
        .unwrap();
    assert_eq!(seen_by_b.len(), 1);
    let a = w.reconcile(None).await;
    assert_eq!((a.recovered, a.problems.len()), (1, 0), "{a:?}");
    let first = w.stored_outcome("r-1").await.unwrap();

    *w.store().faults.stale_stuck_allows.lock().unwrap() = Some(seen_by_b);
    let b = w.reconcile(None).await;
    *w.store().faults.stale_stuck_allows.lock().unwrap() = None;
    assert_eq!(b.recovered, 0, "{b:?}");
    assert!(b.problems.is_empty() && b.error.is_none(), "{b:?}");
    assert_eq!(
        w.stored_outcome("r-1").await.unwrap(),
        first,
        "A's row stands"
    );
    assert_eq!(w.sends(), 1);
}

/// An allow older than the recovery's lookback with no outcome is not hidden:
/// the pass does not record it (it is outside what the query looks at), and
/// says how many there are, so a metric can show it. The bundle verifier
/// reports it as `outcome_missing` however old it is
/// (`recovered_outcome.rs`).
#[tokio::test]
async fn an_allow_beyond_the_lookback_stays_visible() {
    use kavach_dataplane::outcome_reconciler::STUCK_OUTCOME_LOOKBACK;
    let w = world();
    let mandate = w.mandate().await;
    Faults::fail(&w.store().faults.record_outcome, Faults::FOREVER);
    w.call(&mandate, "old").await.unwrap();
    Faults::fail(&w.store().faults.record_outcome, 0);

    // Inside the lookback it is recovered and nothing is beyond it.
    w.advance(Duration::minutes(10));
    let inside = w.reconcile(None).await;
    assert_eq!(
        (inside.recovered, inside.beyond_lookback),
        (1, 0),
        "{inside:?}"
    );

    // A second one that nobody recovered in time: now older than the lookback.
    Faults::fail(&w.store().faults.record_outcome, Faults::FOREVER);
    w.call(&mandate, "older").await.unwrap();
    Faults::fail(&w.store().faults.record_outcome, 0);
    w.advance(STUCK_OUTCOME_LOOKBACK + Duration::hours(1));
    let beyond = w.reconcile(None).await;
    assert_eq!(
        beyond.recovered, 0,
        "outside the lookback it is not written: {beyond:?}"
    );
    assert_eq!(beyond.beyond_lookback, 1, "{beyond:?}");
    assert!(
        w.stored_outcome("older").await.is_none(),
        "still without an outcome"
    );
    // And it stays visible on every later pass.
    assert_eq!(w.reconcile(None).await.beyond_lookback, 1);
}

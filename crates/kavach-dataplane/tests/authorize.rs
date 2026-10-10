//! Authorization core scenarios (PRD acceptance 1, 2 partial, 3, 5; NFR-7),
//! with a real mandate issued from a signed system-of-record event.

mod common;

use common::*;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use kavach_authz::AgentState;
use kavach_dataplane::MandateVerifier as _;
use kavach_dataplane::{
    reconcile_revocations, AgentIdentity, AuthorizeConfig, AuthorizeCore, CommitStatus, Mode,
    ReconcileConfig, ToolCall,
};
use kavach_domain::mandate::RevocationReason;
use kavach_domain::Decision;
use kavach_keys::{InMemoryKeyProvider, SubjectKeys};
use kavach_mandate::memory::{InMemoryConsentSource, InMemoryEventBus, InMemoryMandateStore};
use kavach_mandate::{MandateDeps, MandateService};
use kavach_ports::agent_evidence::AgentEvidenceStore;
use kavach_ports::{SyncStatus, TimeSource};
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
}

fn world_with(signer: TestSigner) -> World {
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
        Box::new(signer),
        Box::new(Clock(Arc::clone(&clock))),
        AuthorizeConfig::default(),
    )
    .expect("core");
    World {
        clock,
        mandates,
        core,
        sor,
    }
}

fn world() -> World {
    world_with(TestSigner::new("evidence-test", 9))
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

    fn at(&self, t: DateTime<Utc>) {
        self.clock.advance(t - self.clock.now().utc);
    }
}

fn agent(id: &str) -> AgentIdentity {
    AgentIdentity {
        agent_id: id.into(),
        identity_key: format!("oidc:https://idp#{id}"),
        state: AgentState::Active,
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

#[tokio::test]
async fn scenario1_reminder_at_11_ist_is_allowed_and_recorded() {
    let w = world();
    let mandate = w.mandate_for("B-9382").await;
    let decided = w
        .core
        .authorize(
            &agent("collections-agent"),
            &reminder(&mandate, "r-1"),
            Mode::Commit,
        )
        .await
        .unwrap();
    assert_eq!(decided.decision, Decision::Pass, "{:?}", decided.reasons);
    assert_eq!(decided.status, CommitStatus::Committed);
    let grant = decided.grant.expect("credential grant");
    let record = decided.record.expect("record");
    assert_eq!(
        record.payload.credential_id.as_deref(),
        Some(grant.credential_id.as_str())
    );
    assert_eq!(grant.send_by, Some(ist(19, 0, 0)), "window end");
    assert!(grant.expires_at <= ist(11, 0, 15));
    assert_eq!(record.payload.chain, vec![mandate.clone()]);
    assert!(record.payload.policy_versions.cedar.starts_with("sha256:"));
    assert_eq!(
        record.payload.policy_versions.tools.as_deref(),
        Some(w.core.tools().digest()),
        "the registry digest is recorded"
    );
    let text = serde_json::to_string(&record).unwrap();
    assert!(!text.contains("B-9382"), "no raw subject reference");

    // A retry returns the same decision and credential; no second slot.
    let again = w
        .core
        .authorize(
            &agent("collections-agent"),
            &reminder(&mandate, "r-1"),
            Mode::Commit,
        )
        .await
        .unwrap();
    assert_eq!(again.status, CommitStatus::Replayed);
    assert_eq!(again.grant.unwrap().credential_id, grant.credential_id);
    // Same id, different content: conflict.
    let mut other = reminder(&mandate, "r-1");
    other.channel = Some("voice".into());
    let conflict = w
        .core
        .authorize(&agent("collections-agent"), &other, Mode::Commit)
        .await
        .unwrap();
    assert_eq!(conflict.status, CommitStatus::Conflict);
    assert!(conflict.grant.is_none());
}

/// NFR-7 boundaries, via pre-check (which reserves and records nothing).
#[tokio::test]
async fn contact_boundaries_at_08_00_and_19_00_ist() {
    let w = world();
    // Issued before the window opens, so only the window decides.
    w.at(ist(7, 0, 0));
    let mandate = w.mandate_for("B-9382").await;
    let cases = [
        (ist(7, 59, 59), Decision::Block),
        (ist(8, 0, 0), Decision::Pass),
        (ist(18, 59, 59), Decision::Pass),
        (ist(19, 0, 0), Decision::Block),
        (ist(19, 45, 0), Decision::Block),
    ];
    for (i, (t, expected)) in cases.into_iter().enumerate() {
        w.at(t);
        let decided = w
            .core
            .authorize(
                &agent("collections-agent"),
                &reminder(&mandate, &format!("b-{i}")),
                Mode::Precheck,
            )
            .await
            .unwrap();
        assert_eq!(decided.decision, expected, "{t}: {:?}", decided.reasons);
        assert_eq!(decided.status, CommitStatus::NotRecorded);
        assert!(decided.record.is_none() && decided.grant.is_none());
    }
    assert_eq!(w.core.prechecks(), 5);
    assert!(
        w.core.store().records(TENANT, 0).await.unwrap().is_empty(),
        "pre-checks are off the chain"
    );
}

#[tokio::test]
async fn scenario3_fourth_contact_in_a_day_is_blocked() {
    let w = world();
    let mandate = w.mandate_for("B-9382").await;
    let a = agent("collections-agent");
    for i in 0..3 {
        let d = w
            .core
            .authorize(&a, &reminder(&mandate, &format!("c-{i}")), Mode::Commit)
            .await
            .unwrap();
        assert_eq!(d.decision, Decision::Pass);
    }
    let fourth = w
        .core
        .authorize(&a, &reminder(&mandate, "c-3"), Mode::Commit)
        .await
        .unwrap();
    assert_eq!(fourth.decision, Decision::Block);
    assert!(
        fourth.reasons.iter().any(|r| r == "contact-daily-cap"),
        "{:?}",
        fourth.reasons
    );
    // The next IST day starts a new count.
    w.at(ist(11, 0, 0) + Duration::days(1));
    let next_day = w
        .core
        .authorize(&a, &reminder(&mandate, "c-4"), Mode::Commit)
        .await
        .unwrap();
    assert_eq!(next_day.decision, Decision::Pass, "{:?}", next_day.reasons);
}

#[tokio::test]
async fn scenario5_other_subject_wrong_holder_and_revoked_mandates_are_blocked() {
    let w = world();
    let mandate = w.mandate_for("B-9382").await;
    w.mandate_for("B-5511").await;
    let mut other = reminder(&mandate, "s-1");
    other.subject_ref = "ref:borrower:B-5511".into();
    let d = w
        .core
        .authorize(&agent("collections-agent"), &other, Mode::Commit)
        .await
        .unwrap();
    assert_eq!(d.decision, Decision::Block);
    assert!(
        d.reasons.iter().any(|r| r == "subject-binding"),
        "{:?}",
        d.reasons
    );

    let d = w
        .core
        .authorize(
            &agent("translator-agent"),
            &reminder(&mandate, "s-2"),
            Mode::Commit,
        )
        .await
        .unwrap();
    assert_eq!(d.decision, Decision::Block, "only the holder");

    w.mandates
        .revoke(TENANT, &mandate, RevocationReason::Dispute)
        .await
        .unwrap();
    let d = w
        .core
        .authorize(
            &agent("collections-agent"),
            &reminder(&mandate, "s-3"),
            Mode::Commit,
        )
        .await
        .unwrap();
    assert_eq!(d.decision, Decision::Block);
    assert_eq!(d.reasons, vec!["mandate_invalid"]);
    assert!(d.record.is_some(), "the refused attempt is recorded");
}

/// Item 5 taxonomy: an allowlist or reference-only violation found by the
/// registry is a recorded BLOCK (reason and parameter only); an action with
/// no registered tool is a malformed request.
#[tokio::test]
async fn registry_violations_are_recorded_blocks_and_unregistered_actions_are_invalid() {
    let w = world();
    let mandate = w.mandate_for("B-9382").await;
    let request = |request_id: &str, channel: &str| {
        serde_json::from_value::<kavach_dataplane::ToolRequest>(serde_json::json!({
            "mandate_id": mandate,
            "request_id": request_id,
            "params": {
                "subject_ref": SUBJECT,
                "channel": channel,
                "template_id": "emi_reminder_v1",
            },
        }))
        .unwrap()
    };
    let a = agent("collections-agent");

    let ok = w
        .core
        .tools()
        .extract("send_reminder", request("x-1", "whatsapp"))
        .unwrap();
    assert_eq!(
        ok,
        reminder(&mandate, "x-1"),
        "extraction builds the same call"
    );

    let call = w
        .core
        .tools()
        .extract("send_reminder", request("x-2", "+919876543210"))
        .unwrap();
    let d = w.core.authorize(&a, &call, Mode::Commit).await.unwrap();
    assert_eq!(d.decision, Decision::Block);
    assert_eq!(d.status, CommitStatus::Committed);
    assert!(d.grant.is_none());
    assert_eq!(d.reasons[0], "value_not_allowed:channel", "{:?}", d.reasons);
    let record = d.record.expect("the violation is recorded");
    assert!(record.payload.params_mac.is_none());
    let text = serde_json::to_string(&record).unwrap();
    assert!(!text.contains("9876543210"), "{text}");

    let status = ToolCall {
        action: "update_status".into(),
        ..reminder(&mandate, "x-3")
    };
    let err = w
        .core
        .authorize(&a, &status, Mode::Commit)
        .await
        .unwrap_err();
    assert_eq!(err.class, kavach_ports::ErrorClass::Invalid);
    assert!(
        err.message.contains("no registered tool"),
        "{}",
        err.message
    );
}

#[tokio::test]
async fn scenario2_partial_raw_identifiers_are_blocked_without_a_trace() {
    let w = world();
    let mandate = w.mandate_for("B-9382").await;
    let mut call = reminder(&mandate, "p-1");
    call.extra
        .insert("template_id".into(), "call me on +91 98765 43210".into());
    let d = w
        .core
        .authorize(&agent("collections-agent"), &call, Mode::Commit)
        .await
        .unwrap();
    assert_eq!(d.decision, Decision::Block);
    assert!(
        d.reasons
            .iter()
            .any(|r| r == "raw_identifier:template_id:phone"),
        "{:?}",
        d.reasons
    );
    let record = d.record.unwrap();
    assert!(record.payload.params_mac.is_none());
    let text = serde_json::to_string(&record).unwrap();
    // Any form the number could leak in; a bare "98765" could also occur by
    // chance in the record's hex hashes and signature.
    for leak in ["98765 43210", "9876543210", "+91"] {
        assert!(!text.contains(leak), "{leak}: {text}");
    }

    // A raw value as the subject itself.
    let mut call = reminder(&mandate, "p-2");
    call.subject_ref = "9876543210".into();
    let d = w
        .core
        .authorize(&agent("collections-agent"), &call, Mode::Commit)
        .await
        .unwrap();
    assert!(d
        .reasons
        .iter()
        .any(|r| r == "reference_only_violation:subject_ref"));
    assert!(!serde_json::to_string(&d.record)
        .unwrap()
        .contains("9876543210"));
}

#[tokio::test]
async fn lost_time_or_evidence_blocks_without_a_credential() {
    let w = world();
    let mandate = w.mandate_for("B-9382").await;
    w.clock.set_sync(SyncStatus::Unsynced);
    let d = w
        .core
        .authorize(
            &agent("collections-agent"),
            &reminder(&mandate, "t-1"),
            Mode::Commit,
        )
        .await
        .unwrap();
    assert_eq!(d.decision, Decision::Block);
    assert!(d.reasons.iter().any(|r| r == "trusted_time_unavailable"));
    assert!(d.grant.is_none());

    // Evidence cannot be written: BLOCK-shaped, nothing recorded, no slot.
    let w = world_with(TestSigner::failing("evidence-test"));
    let mandate = w.mandate_for("B-9382").await;
    let d = w
        .core
        .authorize(
            &agent("collections-agent"),
            &reminder(&mandate, "t-2"),
            Mode::Commit,
        )
        .await
        .unwrap();
    assert_eq!(
        (d.decision, d.status),
        (Decision::Block, CommitStatus::Failed)
    );
    assert_eq!(d.reasons, vec!["dependency_unavailable"]);
    assert!(d.record.is_none() && d.grant.is_none());
}

#[tokio::test]
async fn plans_need_a_waiver_and_large_waivers_need_review() {
    let w = world();
    let mandate = w.mandate_for("B-9382").await;
    let plan = |request_id: &str, waiver: Option<i64>| ToolCall {
        action: "propose_plan".into(),
        channel: None,
        waiver_bps: waiver,
        extra: BTreeMap::new(),
        ..reminder(&mandate, request_id)
    };
    let a = agent("collections-agent");
    let d = w
        .core
        .authorize(&a, &plan("w-1", None), Mode::Commit)
        .await
        .unwrap();
    assert_eq!(d.decision, Decision::Block, "missing waiver");
    let d = w
        .core
        .authorize(&a, &plan("w-2", Some(3500)), Mode::Commit)
        .await
        .unwrap();
    assert_eq!(d.decision, Decision::HumanReview);
    assert!(d.grant.is_none(), "review is not an allow");
    let d = w
        .core
        .authorize(&a, &plan("w-3", Some(500)), Mode::Commit)
        .await
        .unwrap();
    assert_eq!(d.decision, Decision::Pass);
    assert!(
        d.grant.is_some_and(|g| g.send_by.is_none()),
        "not a contact action"
    );
}

#[tokio::test]
async fn malformed_requests_are_invalid() {
    let w = world();
    let mandate = w.mandate_for("B-9382").await;
    for bad in ["", "has space", &"x".repeat(129)] {
        let err = w
            .core
            .authorize(
                &agent("collections-agent"),
                &reminder(&mandate, bad),
                Mode::Commit,
            )
            .await
            .unwrap_err();
        assert_eq!(err.class, kavach_ports::ErrorClass::Invalid);
    }
}

/// Forward-once ownership and outcomes (step 8a): only the call that
/// created the record may forward; an outcome is recorded once, with a
/// reason, and only for an allow.
#[tokio::test]
async fn only_the_creator_may_forward_and_outcomes_are_recorded_once() {
    use kavach_ports::agent_evidence::Outcome;
    let w = world();
    let mandate = w.mandate_for("B-9382").await;
    let a = agent("collections-agent");
    let call = reminder(&mandate, "o-1");

    // Concurrent duplicates of one request: exactly one creator.
    let (r1, r2, r3, r4) = tokio::join!(
        w.core.authorize(&a, &call, Mode::Commit),
        w.core.authorize(&a, &call, Mode::Commit),
        w.core.authorize(&a, &call, Mode::Commit),
        w.core.authorize(&a, &call, Mode::Commit),
    );
    let all = [r1.unwrap(), r2.unwrap(), r3.unwrap(), r4.unwrap()];
    assert_eq!(all.iter().filter(|d| d.created()).count(), 1, "one creator");
    assert!(all.iter().all(|d| d.decision == Decision::Pass));
    let creator = all.iter().find(|d| d.created()).unwrap();
    let record = creator.record.clone().expect("record");
    let credential = creator.grant.clone().expect("grant").credential_id;
    assert_eq!(
        w.core.outcome(&credential).await.unwrap(),
        None,
        "nothing yet"
    );

    let written = w
        .core
        .record_outcome(&record, Outcome::Delivered, "provider_202")
        .await
        .unwrap();
    assert_eq!(written.reason.as_deref(), Some("provider_202"));
    assert_eq!(w.core.outcome(&credential).await.unwrap(), Some(written));
    assert!(
        w.core
            .record_outcome(&record, Outcome::Unknown, "timeout_after_send")
            .await
            .is_err(),
        "an outcome is recorded once and never replaced"
    );
    // A reason must be a code, never a value.
    let other = w
        .core
        .authorize(&a, &reminder(&mandate, "o-2"), Mode::Commit)
        .await
        .unwrap();
    assert!(w
        .core
        .record_outcome(
            other.record.as_ref().unwrap(),
            Outcome::Failed,
            "to +91 98765 43210"
        )
        .await
        .is_err());

    // No outcome for a refusal.
    w.at(ist(20, 0, 0));
    let late = w
        .core
        .authorize(&a, &reminder(&mandate, "o-3"), Mode::Commit)
        .await
        .unwrap();
    assert_eq!(late.decision, Decision::Block);
    let err = w
        .core
        .record_outcome(
            late.record.as_ref().unwrap(),
            Outcome::Delivered,
            "provider_202",
        )
        .await
        .unwrap_err();
    assert_eq!(err.class, kavach_ports::ErrorClass::Invalid);
}

/// A resolver that takes so long the deadline passes while it runs.
struct SlowResolver {
    clock: Arc<FakeClock>,
    by: Duration,
}

impl kavach_ports::ReferenceResolver for SlowResolver {
    fn resolve(
        &self,
        _tenant_id: &str,
        _subject_ref: &str,
        _channel: &str,
    ) -> impl std::future::Future<Output = Result<kavach_ports::Destination, kavach_ports::PortError>>
           + Send {
        self.clock.advance(self.by);
        std::future::ready(Ok(kavach_ports::Destination::new("+910000000001")))
    }

    fn describe(&self) -> String {
        "slow".into()
    }
}

/// Counts forwards; a forward must never happen in these tests.
#[derive(Default)]
struct CountingForwarder(std::sync::atomic::AtomicUsize);

impl kavach_dataplane::Forwarder for CountingForwarder {
    fn forward(
        &self,
        _provider: &str,
        _credential: &kavach_ports::TokenSecret,
    ) -> impl std::future::Future<Output = kavach_dataplane::ForwardResult> + Send {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        std::future::ready(kavach_dataplane::ForwardResult::Responded {
            status: 202,
            message_id: None,
        })
    }
}

struct NoMetrics;

impl kavach_dataplane::GatewayObserver for NoMetrics {
    fn call(&self, _: &str, _: Decision, _: Option<kavach_ports::agent_evidence::Outcome>) {}
    fn jti_conflict(&self) {}
    fn outcome_write_failed(&self) {}
}

/// Addition 2: a slow resolver or broker must not push a send past
/// `send_by`. Trusted time is re-checked just before forwarding; a passed
/// deadline is `not_executed` / `send_by_passed`, and nothing is sent.
#[tokio::test]
async fn a_send_that_would_land_after_send_by_is_not_executed() {
    use kavach_ports::agent_evidence::Outcome;
    let w = world();
    w.at(ist(18, 59, 50));
    let mandate = w.mandate_for("B-9382").await;
    let mut keys = InMemoryKeyProvider::new();
    keys.insert_seed("kavach-credential-1", [5u8; 32]).unwrap();
    let broker = kavach_credential::JoseCredentialBroker::new(
        keys,
        "kavach-credential-1",
        "kavach",
        BTreeMap::from([(
            "mock-messaging".to_string(),
            kavach_credential::DecryptionKey::from_bytes("enc", [11u8; 32]).recipient(),
        )]),
    );
    let forwarder = CountingForwarder::default();
    let resolver = SlowResolver {
        clock: Arc::clone(&w.clock),
        by: Duration::seconds(20),
    };
    let deps = kavach_dataplane::GatewayDeps {
        core: &w.core,
        resolver: &resolver,
        broker: &broker,
        forwarder: &forwarder,
        observer: &NoMetrics,
    };
    let request: kavach_dataplane::ToolRequest = serde_json::from_value(serde_json::json!({
        "mandate_id": mandate,
        "request_id": "slow-1",
        "params": { "subject_ref": SUBJECT, "channel": "whatsapp", "template_id": "emi_reminder_v1" }
    }))
    .unwrap();
    let reply =
        kavach_dataplane::execute(&deps, &agent("collections-agent"), "send_reminder", request)
            .await
            .unwrap();
    assert_eq!(reply.decision, Decision::Pass, "allowed at 18:59:50");
    // The broker itself refuses a credential past send_by.
    assert_eq!(reply.outcome, Some(Outcome::NotExecuted));
    assert_eq!(reply.outcome_reason.as_deref(), Some("credential_refused"));

    // A slow broker: the credential is issued in time, the deadline passes
    // before the forward; the gateway's own re-check catches it.
    w.at(ist(18, 59, 50));
    let slow_broker = SlowBroker {
        inner: broker,
        clock: Arc::clone(&w.clock),
        by: Duration::seconds(15),
    };
    let fast = SlowResolver {
        clock: Arc::clone(&w.clock),
        by: Duration::zero(),
    };
    let deps = kavach_dataplane::GatewayDeps {
        core: &w.core,
        resolver: &fast,
        broker: &slow_broker,
        forwarder: &forwarder,
        observer: &NoMetrics,
    };
    let request: kavach_dataplane::ToolRequest = serde_json::from_value(serde_json::json!({
        "mandate_id": mandate,
        "request_id": "slow-2",
        "params": { "subject_ref": SUBJECT, "channel": "whatsapp", "template_id": "emi_reminder_v1" }
    }))
    .unwrap();
    let reply =
        kavach_dataplane::execute(&deps, &agent("collections-agent"), "send_reminder", request)
            .await
            .unwrap();
    assert_eq!(reply.outcome, Some(Outcome::NotExecuted));
    assert_eq!(reply.outcome_reason.as_deref(), Some("send_by_passed"));
    assert_eq!(
        forwarder.0.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "never forwarded"
    );
}

/// A broker whose issuance takes `by` (the clock moves while it runs).
struct SlowBroker<B> {
    inner: B,
    clock: Arc<FakeClock>,
    by: Duration,
}

impl<B: kavach_ports::CredentialBroker> kavach_ports::CredentialBroker for SlowBroker<B> {
    async fn issue(
        &self,
        request: &kavach_ports::CredentialRequest<'_>,
    ) -> Result<kavach_ports::IssuedCredential, kavach_ports::PortError> {
        let issued = self.inner.issue(request).await;
        self.clock.advance(self.by);
        issued
    }

    fn revoke_by_mandate(
        &self,
        tenant_id: &str,
        mandate_id: &str,
    ) -> impl std::future::Future<Output = Result<u64, kavach_ports::PortError>> + Send {
        self.inner.revoke_by_mandate(tenant_id, mandate_id)
    }
}

/// A resolver that revokes the mandate while it resolves: the decision is
/// already recorded, the credential not yet minted (ADR-012 §5).
struct RevokingResolver {
    mandates: Arc<Service>,
    mandate: String,
}

impl kavach_ports::ReferenceResolver for RevokingResolver {
    fn resolve(
        &self,
        tenant_id: &str,
        _subject_ref: &str,
        _channel: &str,
    ) -> impl std::future::Future<Output = Result<kavach_ports::Destination, kavach_ports::PortError>>
           + Send {
        let (mandates, mandate, tenant) = (
            Arc::clone(&self.mandates),
            self.mandate.clone(),
            tenant_id.to_string(),
        );
        async move {
            mandates
                .revoke(&tenant, &mandate, RevocationReason::Payment)
                .await
                .expect("revoked");
            Ok(kavach_ports::Destination::new("+910000000001"))
        }
    }

    fn describe(&self) -> String {
        "revoking".into()
    }
}

/// Counts credentials minted.
struct CountingBroker<B> {
    inner: B,
    issued: std::sync::atomic::AtomicUsize,
}

impl<B: kavach_ports::CredentialBroker> kavach_ports::CredentialBroker for CountingBroker<B> {
    async fn issue(
        &self,
        request: &kavach_ports::CredentialRequest<'_>,
    ) -> Result<kavach_ports::IssuedCredential, kavach_ports::PortError> {
        self.issued
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.issue(request).await
    }

    fn revoke_by_mandate(
        &self,
        tenant_id: &str,
        mandate_id: &str,
    ) -> impl std::future::Future<Output = Result<u64, kavach_ports::PortError>> + Send {
        self.inner.revoke_by_mandate(tenant_id, mandate_id)
    }
}

/// ADR-012 §5: a mandate revoked after the decision was recorded but before
/// the credential is minted gets no credential, and nothing is sent; the
/// recorded allow ends `not_executed` / `mandate_revoked`.
#[tokio::test]
async fn a_mandate_revoked_after_the_decision_mints_nothing_and_sends_nothing() {
    use kavach_ports::agent_evidence::Outcome;
    let w = world();
    let mandate = w.mandate_for("B-9382").await;
    let mut keys = InMemoryKeyProvider::new();
    keys.insert_seed("kavach-credential-1", [5u8; 32]).unwrap();
    let broker = CountingBroker {
        inner: kavach_credential::JoseCredentialBroker::new(
            keys,
            "kavach-credential-1",
            "kavach",
            BTreeMap::from([(
                "mock-messaging".to_string(),
                kavach_credential::DecryptionKey::from_bytes("enc", [11u8; 32]).recipient(),
            )]),
        ),
        issued: std::sync::atomic::AtomicUsize::new(0),
    };
    let forwarder = CountingForwarder::default();
    let resolver = RevokingResolver {
        mandates: Arc::clone(&w.mandates),
        mandate: mandate.clone(),
    };
    let deps = kavach_dataplane::GatewayDeps {
        core: &w.core,
        resolver: &resolver,
        broker: &broker,
        forwarder: &forwarder,
        observer: &NoMetrics,
    };
    let request: kavach_dataplane::ToolRequest = serde_json::from_value(serde_json::json!({
        "mandate_id": mandate,
        "request_id": "revoked-1",
        "params": { "subject_ref": SUBJECT, "channel": "whatsapp", "template_id": "emi_reminder_v1" }
    }))
    .unwrap();
    let reply =
        kavach_dataplane::execute(&deps, &agent("collections-agent"), "send_reminder", request)
            .await
            .unwrap();
    assert_eq!(reply.decision, Decision::Pass, "allowed when decided");
    assert_eq!(reply.outcome, Some(Outcome::NotExecuted));
    assert_eq!(reply.outcome_reason.as_deref(), Some("mandate_revoked"));
    assert_eq!(
        broker.issued.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "no credential"
    );
    assert_eq!(
        forwarder.0.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "nothing sent"
    );
}

/// A signed revoking event (ADR-012) about `borrower`'s loan.
async fn revocation(
    sor: &InMemoryKeyProvider,
    borrower: &str,
    event_type: &str,
    event_id: &str,
    occurred_at: DateTime<Utc>,
) -> String {
    let event = kavach_domain::mandate::SorEvent {
        event_id: event_id.into(),
        tenant_id: TENANT.into(),
        system: "lms".into(),
        event_type: event_type.into(),
        record_ref: format!("lms:loan/{borrower}"),
        subject_ref: format!("ref:borrower:{borrower}"),
        principal: "nbfc-collections-system".into(),
        consent_refs: BTreeSet::new(),
        assigned_agent: String::new(),
        occurred_at,
        nonce: format!("n-{event_id}"),
    };
    kavach_mandate::jws::sign(
        sor,
        "lms-issuer-1",
        kavach_mandate::jws::TYP_SOR_EVENT,
        &event,
    )
    .await
    .unwrap()
}

/// ADR-012: a payment revokes the loan's live mandates and every mandate
/// delegated from them; a retry gets the stored result; the id reused for
/// other content, a forged, a stale or a non-revoking event is refused.
#[tokio::test]
async fn a_payment_event_revokes_the_loans_mandates_and_their_delegations() {
    let w = world();
    let mandate = w.mandate_for("B-9382").await;
    let child = w
        .mandates
        .delegate(
            TENANT,
            &mandate,
            "collections-agent",
            "translator-agent",
            &kavach_domain::mandate::DelegationRequest {
                actions: common::set(&["read_fields"]),
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .mandate
        .id;
    w.at(ist(12, 0, 0));
    let paid = revocation(&w.sor, "B-9382", "loan.paid", "pay-1", w.clock.now().utc).await;
    assert!(kavach_mandate::is_revoking_event(&paid));
    let done = w.mandates.revoke_from_event(&paid).await.unwrap();
    assert_eq!(
        done.revoked,
        [mandate.clone(), child.clone()],
        "the root and its delegation"
    );
    assert!(!done.replayed);
    for id in [&mandate, &child] {
        assert!(
            w.mandates.verify(TENANT, id).await.is_err(),
            "{id} no longer authorises"
        );
    }

    // The same event again: the stored result, nothing revoked now.
    assert!(
        w.mandates.revoke_from_event(&paid).await.is_err(),
        "the replay guard"
    );
    let again = w
        .mandates
        .existing_revocation(&paid)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((again.revoked, again.replayed), (done.revoked, true));
    // The id reused for another record: refused.
    let other = revocation(&w.sor, "B-1111", "loan.paid", "pay-1", w.clock.now().utc).await;
    let conflict = w.mandates.existing_revocation(&other).await.unwrap_err();
    assert!(
        conflict.message.contains("different content"),
        "{conflict:?}"
    );

    // Forged (another key), stale, and not a revoking type.
    let mut other_keys = InMemoryKeyProvider::new();
    other_keys.insert_seed("lms-issuer-1", [99u8; 32]).unwrap();
    let forged = revocation(
        &other_keys,
        "B-9382",
        "loan.paid",
        "pay-2",
        w.clock.now().utc,
    )
    .await;
    assert!(
        w.mandates.revoke_from_event(&forged).await.is_err(),
        "forged"
    );
    let stale = revocation(&w.sor, "B-9382", "loan.disputed", "pay-3", ist(11, 0, 0)).await;
    assert!(
        w.mandates.revoke_from_event(&stale).await.is_err(),
        "stale (an hour old)"
    );
    let wrong = revocation(&w.sor, "B-9382", "loan.dpd30", "pay-4", w.clock.now().utc).await;
    assert!(!kavach_mandate::is_revoking_event(&wrong));
    assert!(
        w.mandates.revoke_from_event(&wrong).await.is_err(),
        "loan.dpd30 does not revoke"
    );
}

/// ADR-012 §3: a revocation never reaches forward. A mandate issued after
/// the revoking event occurred (a new default after a payment) stays.
#[tokio::test]
async fn a_revocation_never_reaches_a_mandate_issued_after_it() {
    let w = world();
    let occurred = w.clock.now().utc;
    w.at(ist(11, 1, 0));
    let mandate = w.mandate_for("B-9382").await;
    // A payment that occurred a minute before the mandate was issued
    // (fresh enough to be accepted) does not revoke it.
    let paid = revocation(&w.sor, "B-9382", "loan.paid", "pay-old", occurred).await;
    let done = w.mandates.revoke_from_event(&paid).await.unwrap();
    assert!(done.revoked.is_empty(), "{done:?}");
    assert!(
        w.mandates.verify(TENANT, &mandate).await.is_ok(),
        "still live"
    );
}

/// ADR-012 §7: a revocation whose evidence record was never written (the
/// request that revoked could not write it) is recorded by the reconciler,
/// once settled, and never twice. The record names the loan only by its
/// keyed pseudonym, and the chain verifies.
#[tokio::test]
async fn the_reconciler_records_a_revocation_the_request_could_not() {
    let w = world();
    w.mandate_for("B-9382").await;
    w.at(ist(12, 0, 0));
    let paid = revocation(&w.sor, "B-9382", "loan.paid", "pay-1", w.clock.now().utc).await;
    // Revoked through the service alone: no evidence record yet.
    let done = w.mandates.revoke_from_event(&paid).await.unwrap();
    let store = w.core.store();
    assert_eq!(
        store
            .revocation_record(TENANT, "lms", "pay-1")
            .await
            .unwrap(),
        None
    );

    let config = ReconcileConfig::default();
    let pass =
        |watermark, now| reconcile_revocations(w.mandates.store(), &w.core, watermark, now, config);
    // Not settled yet: left to the request that made it.
    let first = pass(None, w.clock.now().utc).await;
    assert_eq!((first.checked, first.watermark), (0, None), "{first:?}");

    w.at(ist(12, 1, 0));
    let second = pass(None, w.clock.now().utc).await;
    assert_eq!(second.reconciled, ["pay-1"], "{second:?}");
    assert!(second.missing.is_empty() && second.error.is_none());
    assert_eq!(second.watermark, Some(done.stored.revoked_at));

    let record = store
        .revocation_record(TENANT, "lms", "pay-1")
        .await
        .unwrap()
        .expect("recorded");
    let p = &record.payload;
    assert_eq!(p.revoked, done.revoked);
    assert_eq!(p.revoked_at, done.stored.revoked_at);
    assert!(
        p.recorded_at > p.revoked_at,
        "written later, by the reconciler"
    );
    assert!(p.record_pseudonym.starts_with("psn:"));
    let json = serde_json::to_string(&record).unwrap();
    assert!(
        !json.contains("L-") && !json.contains("B-9382"),
        "no reference: {json}"
    );
    let records = store.records(TENANT, 0).await.unwrap();
    kavach_ports::agent_evidence::verify_chain(
        &records,
        &TestSigner::new("evidence-test", 9).keys(),
        None,
        &[],
        w.clock.now().utc,
    )
    .expect("the chain verifies");

    // The next pass sees it recorded and writes nothing.
    let third = pass(second.watermark, w.clock.now().utc).await;
    assert_eq!((third.checked, third.reconciled.len()), (1, 0), "{third:?}");
    assert_eq!(store.records(TENANT, 0).await.unwrap().len(), records.len());
}

/// A record that cannot be written is reported missing, and the watermark
/// never moves past it, so the next pass tries it again.
#[tokio::test]
async fn a_revocation_record_that_cannot_be_written_is_missing_and_retried() {
    let w = world_with(TestSigner::failing("evidence-test"));
    w.mandate_for("B-9382").await;
    w.at(ist(12, 0, 0));
    let paid = revocation(&w.sor, "B-9382", "loan.paid", "pay-1", w.clock.now().utc).await;
    w.mandates.revoke_from_event(&paid).await.unwrap();
    w.at(ist(12, 1, 0));
    let report = reconcile_revocations(
        w.mandates.store(),
        &w.core,
        None,
        w.clock.now().utc,
        ReconcileConfig::default(),
    )
    .await;
    assert_eq!(report.checked, 1);
    assert_eq!(report.missing.len(), 1, "{report:?}");
    assert_eq!(report.missing[0].0, "pay-1");
    assert!(report.reconciled.is_empty());
    assert_eq!(report.watermark, None, "not past what is missing");
}

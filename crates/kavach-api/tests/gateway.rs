//! The gateway end to end (H5b step 8b): `POST /v1/tools/{tool}` on the
//! agent listener → authorize and record → resolve → credential → forward
//! once to a real mock provider over loopback HTTP → signed outcome. One
//! test clock drives Kavach and the provider (11:00 IST), so the contact
//! window does not depend on when CI runs.

mod agent_fixture;

use std::sync::Arc;
use std::time::Duration as StdDuration;

use axum::http::StatusCode;
use chrono::{DateTime, Duration, TimeZone, Utc};
use kavach_api::dataplane::{agent_router, TestClock};
use kavach_api::{AppState, EvidenceStoreKind};
use kavach_jws::KeySet;
use kavach_mock_provider::{
    MockProvider, ProviderConfig, ERROR_NUMBER, HANG_NUMBER, REFUSE_NUMBER,
};
use kavach_ports::agent_evidence::{AgentEvidenceStore, Outcome};
use kavach_ports::{KeyAlgorithm, PublicKey, TimeSource};
use kavach_ports_testkit::FakeClock;
use serde_json::{json, Value};

use agent_fixture::*;

const NUMBER: &str = "+910000000001";

/// Every log line written by this test binary (all tests share one global
/// subscriber: the real redacting one, writing here instead of stderr).
#[derive(Clone, Default)]
struct Capture(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn logs() -> &'static Capture {
    static LOGS: std::sync::OnceLock<Capture> = std::sync::OnceLock::new();
    LOGS.get_or_init(|| {
        let capture = Capture::default();
        let writer = capture.clone();
        kavach_telemetry::init_with(kavach_telemetry::LogFormat::Json, move || writer.clone())
            .expect("subscriber");
        capture
    })
}

fn log_text() -> String {
    String::from_utf8_lossy(&logs().0.lock().unwrap()).into_owned()
}

/// Today at `h`:00 IST.
fn ist_today(h: i64) -> DateTime<Utc> {
    let ist = chrono::FixedOffset::east_opt(5 * 3600 + 1800).unwrap();
    let date = Utc::now().with_timezone(&ist).date_naive();
    ist.from_local_datetime(&date.and_hms_opt(0, 0, 0).unwrap())
        .unwrap()
        .with_timezone(&Utc)
        + Duration::hours(h)
}

struct Gw {
    state: Arc<AppState>,
    clock: Arc<FakeClock>,
    provider: Arc<MockProvider>,
    mandate: String,
}

/// A production-shaped data plane (memory stores, `--insecure-dev` for the
/// test clock) whose `mock-messaging` provider is a real mock provider on
/// loopback, and whose subject resolves to `destination` on WhatsApp.
async fn gateway(destination: Option<&str>, provider_up: bool) -> Gw {
    gateway_on(config_for_gateway(), destination, provider_up).await
}

async fn gateway_on(
    mut api: kavach_api::ApiConfig,
    destination: Option<&str>,
    provider_up: bool,
) -> Gw {
    logs();
    let clock = Arc::new(FakeClock::synced_at(ist_today(11)));
    let credential_public = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32])
        .verifying_key()
        .to_bytes();
    let mut config = ProviderConfig::new(
        "mock-messaging",
        messaging_key(),
        KeySet::new([PublicKey {
            kid: "kavach-credential-1".into(),
            algorithm: KeyAlgorithm::Ed25519,
            bytes: credential_public,
        }]),
    );
    config.hang = StdDuration::from_secs(4);
    let read = Arc::clone(&clock);
    let provider = MockProvider::new(config, Arc::new(move || read.now().utc));
    let endpoint = if provider_up {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = kavach_mock_provider::router(provider.clone());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    } else {
        CLOSED_PORT.to_string()
    };

    let dp = api.dataplane.as_mut().unwrap();
    dp.test_clock = Some(TestClock(clock.clone()));
    write_providers(&dp.providers, &endpoint, CLOSED_PORT);
    let destinations = match destination {
        Some(d) => json!({ "whatsapp": d, "sms": d }),
        None => json!({ "voice": "+910000000002" }),
    };
    std::fs::write(
        &dp.references,
        json!({ "references": [{ "tenant_id": "default", "subject_ref": SUBJECT,
            "destinations": destinations }] })
        .to_string(),
    )
    .unwrap();
    let state = Arc::new(AppState::from_config(&api).await.expect("state"));
    let mandate = issue_at(&state, "evt-gw", clock.now().utc).await;
    Gw {
        state,
        clock,
        provider,
        mandate,
    }
}

fn config_for_gateway() -> kavach_api::ApiConfig {
    config(EvidenceStoreKind::Memory, true, 50)
}

fn reminder(mandate: &str, request_id: &str) -> Value {
    json!({
        "mandate_id": mandate,
        "request_id": request_id,
        "params": {
            "subject_ref": SUBJECT,
            "channel": "whatsapp",
            "template_id": "emi_reminder_v1"
        }
    })
}

impl Gw {
    async fn call(&self, tool: &str, body: Value) -> (StatusCode, Value) {
        let (status, reply) = send(
            agent_router(self.state.clone()),
            &format!("/v1/tools/{tool}"),
            &[(
                "authorization",
                format!("Bearer {}", agent_token("collections-agent")),
            )],
            body,
        )
        .await;
        let text = reply.to_string();
        assert!(!text.contains("+91"), "destination leaked: {text}");
        assert!(!text.contains("eyJ"), "a token leaked: {text}");
        (status, reply)
    }

    async fn remind(&self, request_id: &str) -> (StatusCode, Value) {
        self.call("send_reminder", reminder(&self.mandate, request_id))
            .await
    }

    async fn stored_outcome(&self, request_id: &str) -> Option<(Outcome, Option<String>)> {
        let dp = self.state.dataplane().unwrap();
        let record = dp
            .core()
            .store()
            .get_by_request("default", "collections-agent", request_id)
            .await
            .unwrap()?;
        let credential = record.payload.credential_id?;
        dp.core()
            .outcome(&credential)
            .await
            .unwrap()
            .map(|o| (o.outcome, o.reason))
    }
}

/// Acceptance scenario 1, end to end.
#[tokio::test]
async fn scenario1_a_reminder_is_delivered_once_and_the_agent_never_sees_the_destination() {
    let gw = gateway(Some(NUMBER), true).await;
    let (status, reply) = gw.remind("gw-1").await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["decision"], "PASS", "{reply}");
    assert_eq!(reply["outcome"], "delivered");
    assert_eq!(reply["outcome_reason"], "provider_202");
    assert_eq!(reply["replayed"], false);
    assert_eq!(reply["outcome_recorded"], true);
    assert!(reply["provider_message_id"]
        .as_str()
        .unwrap()
        .starts_with("pm-"));
    // Exactly the allowlisted fields.
    let mut keys: Vec<&str> = reply
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "decision",
            "outcome",
            "outcome_reason",
            "outcome_recorded",
            "provider_message_id",
            "reasons",
            "record_id",
            "replayed",
            "request_id"
        ]
    );

    // The provider got the destination; the evidence did not.
    let inbox = gw.provider.inbox();
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].destination.expose(), NUMBER);
    assert_eq!(
        gw.stored_outcome("gw-1").await,
        Some((Outcome::Delivered, Some("provider_202".into())))
    );
    let records = gw
        .state
        .dataplane()
        .unwrap()
        .core()
        .store()
        .records("default", 0)
        .await
        .unwrap();
    assert!(!serde_json::to_string(&records)
        .unwrap()
        .contains("0000000001"));

    // A retry: the stored result, no second delivery, one contact slot.
    let (status, again) = gw.remind("gw-1").await;
    assert_eq!(
        (status, again["replayed"].as_bool()),
        (StatusCode::OK, Some(true))
    );
    assert_eq!(again["outcome"], "delivered");
    assert_eq!(gw.provider.inbox().len(), 1);
}

/// Forward-once ownership over HTTP: concurrent identical calls produce
/// exactly one provider call.
#[tokio::test]
async fn concurrent_identical_calls_reach_the_provider_exactly_once() {
    let gw = gateway(Some(NUMBER), true).await;
    let replies = futures_join(&gw, "gw-race", 6).await;
    let firsts = replies
        .iter()
        .filter(|(s, r)| *s == StatusCode::OK && r["replayed"] == false)
        .count();
    assert_eq!(firsts, 1, "{replies:?}");
    for (status, reply) in &replies {
        assert!(
            *status == StatusCode::OK || *status == StatusCode::CONFLICT,
            "{status} {reply}"
        );
    }
    assert_eq!(gw.provider.inbox().len(), 1, "exactly one provider call");
}

async fn futures_join(gw: &Gw, request_id: &str, n: usize) -> Vec<(StatusCode, Value)> {
    let calls: Vec<_> = (0..n).map(|_| gw.remind(request_id)).collect();
    let mut out = Vec::new();
    // Polled together on one task: the commits interleave at their awaits.
    let mut pinned: Vec<_> = calls.into_iter().map(Box::pin).collect();
    while !pinned.is_empty() {
        let (result, _, rest) = futures_select(pinned).await;
        out.push(result);
        pinned = rest;
    }
    out
}

/// A minimal select_all over boxed futures (no extra dependency).
async fn futures_select<F: std::future::Future + Unpin>(
    mut futures: Vec<F>,
) -> (F::Output, usize, Vec<F>) {
    std::future::poll_fn(move |cx| {
        for i in 0..futures.len() {
            if let std::task::Poll::Ready(output) = std::pin::Pin::new(&mut futures[i]).poll(cx) {
                drop(futures.swap_remove(i));
                return std::task::Poll::Ready((output, i, std::mem::take(&mut futures)));
            }
        }
        std::task::Poll::Pending
    })
    .await
}

/// Each provider behaviour maps to the agreed outcome, and only final
/// outcomes are returned on retry.
#[tokio::test]
async fn outcomes_follow_the_provider_and_unknown_is_never_retried() {
    // Refused (422): final; a retry returns it.
    let gw = gateway(Some(REFUSE_NUMBER), true).await;
    let (_, reply) = gw.remind("r-1").await;
    assert_eq!(
        (reply["outcome"].as_str(), reply["outcome_reason"].as_str()),
        (Some("refused"), Some("provider_422"))
    );
    let (status, again) = gw.remind("r-1").await;
    assert_eq!(
        (status, again["outcome"].as_str()),
        (StatusCode::OK, Some("refused"))
    );

    // Provider error (500): unknown; a retry is refused as in flight.
    let gw = gateway(Some(ERROR_NUMBER), true).await;
    let (_, reply) = gw.remind("e-1").await;
    assert_eq!(
        (reply["outcome"].as_str(), reply["outcome_reason"].as_str()),
        (Some("unknown"), Some("provider_500"))
    );
    let (status, body) = gw.remind("e-1").await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");

    // Delivered but the response is lost (timeout): unknown, not retried,
    // still exactly one delivery.
    let gw = gateway(Some(HANG_NUMBER), true).await;
    let (_, reply) = gw.remind("h-1").await;
    assert_eq!(
        (reply["outcome"].as_str(), reply["outcome_reason"].as_str()),
        (Some("unknown"), Some("timeout_after_send"))
    );
    assert_eq!(gw.remind("h-1").await.0, StatusCode::CONFLICT);
    assert_eq!(gw.provider.inbox().len(), 1);

    // Provider down: nothing was sent.
    let gw = gateway(Some(NUMBER), false).await;
    let (_, reply) = gw.remind("d-1").await;
    assert_eq!(
        (reply["outcome"].as_str(), reply["outcome_reason"].as_str()),
        (Some("failed"), Some("connect_failed"))
    );
    assert_eq!(
        gw.stored_outcome("d-1").await,
        Some((Outcome::Failed, Some("connect_failed".into())))
    );

    // No WhatsApp address: allowed, but never sent.
    let gw = gateway(None, true).await;
    let (_, reply) = gw.remind("n-1").await;
    assert_eq!(
        (reply["outcome"].as_str(), reply["outcome_reason"].as_str()),
        (Some("not_executed"), Some("no_destination"))
    );
    assert!(gw.provider.inbox().is_empty());
}

/// Refusals and malformed calls never reach the provider.
#[tokio::test]
async fn refusals_and_malformed_calls_never_reach_the_provider() {
    let gw = gateway(Some(NUMBER), true).await;

    // Outside the contact window: a recorded BLOCK, no outcome.
    gw.clock.advance(ist_today(20) - gw.clock.now().utc);
    let (status, reply) = gw.remind("late-1").await;
    assert_eq!(
        (status, reply["decision"].as_str()),
        (StatusCode::OK, Some("BLOCK"))
    );
    assert!(reply.get("outcome").is_none(), "{reply}");
    gw.clock.advance(ist_today(11) - gw.clock.now().utc);

    // Off-allowlist template: a recorded BLOCK.
    let mut body = reminder(&gw.mandate, "tpl-1");
    body["params"]["template_id"] = json!("free_text_v1");
    let (_, reply) = gw.call("send_reminder", body).await;
    assert_eq!(reply["decision"], "BLOCK");

    // Malformed: 400, nothing recorded, counted.
    let mut body = reminder(&gw.mandate, "bad-1");
    body["params"]["message"] = json!("pay now +91 98765 43210");
    assert_eq!(
        gw.call("send_reminder", body).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        gw.call(
            "send_reminder",
            json!({ "mandate_id": gw.mandate, "request_id": "x" })
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        gw.call("wire_money", reminder(&gw.mandate, "u-1")).await.0,
        StatusCode::BAD_REQUEST
    );
    let metrics = gw.state.metrics().gather_text().unwrap();
    assert!(
        metrics.contains("kavach_gateway_malformed_total 3"),
        "{metrics}"
    );

    // Not executed by the gateway yet.
    let read = json!({ "mandate_id": gw.mandate, "request_id": "rf-1",
        "params": { "subject_ref": SUBJECT, "requested_fields": ["name"] } });
    assert_eq!(
        gw.call("read_fields", read).await.0,
        StatusCode::NOT_IMPLEMENTED
    );

    // The same request_id with other content.
    gw.remind("c-1").await;
    let mut other = reminder(&gw.mandate, "c-1");
    other["params"]["channel"] = json!("sms");
    assert_eq!(
        gw.call("send_reminder", other).await.0,
        StatusCode::CONFLICT
    );

    assert_eq!(gw.provider.inbox().len(), 1, "only c-1 was delivered");
    assert!(metrics.contains("kavach_gateway_calls_total{decision=\"BLOCK\",outcome=\"none\",tool=\"send_reminder\"}"), "{metrics}");
}

/// The same flow on Postgres, as the least-privilege runtime role.
#[tokio::test(flavor = "multi_thread")]
async fn gateway_on_postgres_delivers_once_and_records_the_outcome() {
    let Some((owner, runtime)) = kavach_storage::testing::isolated_database_urls().await else {
        return;
    };
    let mut api = config(
        EvidenceStoreKind::Postgres {
            database_url: runtime,
        },
        true,
        50,
    );
    api.migration_database_url = Some(owner);
    let gw = gateway_on(api, Some(NUMBER), true).await;
    let (status, reply) = gw.remind("pg-1").await;
    assert_eq!(
        (status, reply["outcome"].as_str()),
        (StatusCode::OK, Some("delivered")),
        "{reply}"
    );
    let (_, again) = gw.remind("pg-1").await;
    assert_eq!(again["replayed"], true);
    assert_eq!(gw.provider.inbox().len(), 1);
    assert_eq!(
        gw.stored_outcome("pg-1").await,
        Some((Outcome::Delivered, Some("provider_202".into())))
    );
}

/// Logs carry a correlation id on every line of a request and the gateway's
/// decision and outcome, and never a destination or a credential.
#[tokio::test]
async fn logs_carry_correlation_and_never_the_destination_or_credential() {
    use tower::ServiceExt;
    let gw = gateway(Some(NUMBER), true).await;
    let call = |request_id: &'static str| {
        axum::http::Request::post("/v1/tools/send_reminder")
            .header("content-type", "application/json")
            .header(
                "authorization",
                format!("Bearer {}", agent_token("collections-agent")),
            )
            .header("x-request-id", request_id)
            .body(axum::body::Body::from(
                reminder(&gw.mandate, "log-1").to_string(),
            ))
            .unwrap()
    };
    let response = agent_router(gw.state.clone())
        .oneshot(call("corr-test-42"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["x-request-id"], "corr-test-42", "echoed");

    // A malformed caller id is replaced, never logged or echoed.
    let response = agent_router(gw.state.clone())
        .oneshot(call("<script>"))
        .await
        .unwrap();
    let echoed = response.headers()["x-request-id"]
        .to_str()
        .unwrap()
        .to_string();
    assert_ne!(echoed, "<script>");
    assert_eq!(echoed.len(), 36, "a fresh UUID");

    let text = log_text();
    let ours: Vec<&str> = text
        .lines()
        .filter(|l| l.contains("corr-test-42"))
        .collect();
    assert!(
        ours.iter().any(|l| l.contains("gateway call")
            && l.contains("send_reminder")
            && l.contains("delivered")
            && l.contains("provider_202")),
        "{text}"
    );
    assert!(
        ours.iter()
            .any(|l| l.contains("handled") && l.contains("/v1/tools/{tool}")),
        "{text}"
    );
    assert!(!text.contains("<script>"), "{text}");
    for secret in [
        "0000000001",
        "+91",
        "eyJ",
        "Kavach-Credential ",
        "Bearer ey",
    ] {
        assert!(!text.contains(secret), "{secret} in logs:\n{text}");
    }
}

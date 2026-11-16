//! The gateway end to end (H5b step 8b): `POST /v1/tools/{tool}` on the
//! agent listener → authorize and record → resolve → credential → forward
//! once to a real mock provider over loopback HTTP → signed outcome. One
//! test clock drives Kavach and the provider (11:00 IST), so the contact
//! window does not depend on when CI runs.

mod agent_fixture;
mod contract;

use contract::{agent_router, sor_router};
use std::sync::Arc;

use axum::http::StatusCode;

use kavach_api::EvidenceStoreKind;
use kavach_mock_provider::{ERROR_NUMBER, HANG_NUMBER, REFUSE_NUMBER};
use kavach_ports::agent_evidence::{AgentEvidenceStore, Outcome};
use kavach_ports::TimeSource;
use serde_json::{json, Value};

use agent_fixture::*;

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

/// The shared harness, with this binary's log capture installed first.
async fn gateway(destination: Option<&str>, provider_up: bool) -> Gw {
    logs();
    agent_fixture::gateway(destination, provider_up).await
}

async fn gateway_on(
    api: kavach_api::ApiConfig,
    destination: Option<&str>,
    provider_up: bool,
) -> Gw {
    logs();
    agent_fixture::gateway_on(api, destination, provider_up).await
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

/// Each provider behaviour maps to the agreed outcome, and a retry gets
/// the recorded outcome (even `unknown`), replayed, never a second send.
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

    // Provider error (500): unknown; a retry gets that recorded outcome,
    // replayed, and is not sent again.
    let gw = gateway(Some(ERROR_NUMBER), true).await;
    let (_, reply) = gw.remind("e-1").await;
    assert_eq!(
        (reply["outcome"].as_str(), reply["outcome_reason"].as_str()),
        (Some("unknown"), Some("provider_500"))
    );
    let (status, again) = gw.remind("e-1").await;
    assert_eq!(
        (
            status,
            again["outcome"].as_str(),
            again["replayed"].as_bool()
        ),
        (StatusCode::OK, Some("unknown"), Some(true)),
        "{again}"
    );

    // Delivered but the response is lost (timeout): unknown, not retried,
    // still exactly one delivery.
    let gw = gateway(Some(HANG_NUMBER), true).await;
    let (_, reply) = gw.remind("h-1").await;
    assert_eq!(
        (reply["outcome"].as_str(), reply["outcome_reason"].as_str()),
        (Some("unknown"), Some("timeout_after_send"))
    );
    let (status, again) = gw.remind("h-1").await;
    assert_eq!(
        (
            status,
            again["outcome"].as_str(),
            again["replayed"].as_bool()
        ),
        (StatusCode::OK, Some("unknown"), Some(true)),
        "{again}"
    );
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

/// A retry while the first call is still running is in flight (409); once
/// the first call's outcome is recorded (here `unknown`: the response was
/// lost), a retry gets it, replayed. Never a second credential or send.
#[tokio::test]
async fn a_retry_is_in_flight_while_the_first_call_runs_then_gets_its_outcome() {
    let gw = gateway(Some(HANG_NUMBER), true).await;
    let first = gw.remind("w-1");
    let during = async {
        // The first call is waiting on the provider (1.5 s timeout).
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        gw.remind("w-1").await
    };
    let ((status, reply), (during_status, during_body)) = tokio::join!(first, during);
    assert_eq!(
        (
            status,
            reply["outcome"].as_str(),
            reply["replayed"].as_bool()
        ),
        (StatusCode::OK, Some("unknown"), Some(false)),
        "{reply}"
    );
    assert_eq!(during_status, StatusCode::CONFLICT, "{during_body}");
    assert_eq!(during_body["code"], "in_flight", "{during_body}");

    let (status, after) = gw.remind("w-1").await;
    assert_eq!(
        (
            status,
            after["outcome"].as_str(),
            after["replayed"].as_bool()
        ),
        (StatusCode::OK, Some("unknown"), Some(true)),
        "{after}"
    );
    assert_eq!(after["outcome_reason"], "timeout_after_send");
    assert_eq!(gw.provider.inbox().len(), 1, "sent once");
    let metrics = gw.state.metrics().gather_text().unwrap();
    assert_eq!(
        stage_count(&metrics, "credential"),
        1,
        "minted once: {metrics}"
    );
}

/// ADR-012 end to end: a signed payment event for the loan revokes its
/// mandate (200, the revoked ids); the same event again is answered with
/// the same ids, replayed; the agent's next call is refused; nothing more
/// reaches the provider.
#[tokio::test]
async fn a_payment_event_stops_contact_for_that_loan() {
    let gw = gateway(Some(NUMBER), true).await;
    assert_eq!(gw.remind("p-1").await.1["decision"], "PASS");
    let paid = revocation_at("pay-1", "loan.paid", "lms:loan/L-1", gw.clock_now()).await;
    let post = |event: String| {
        send(
            sor_router(gw.state.clone()),
            "/v1/sor/events",
            &[],
            json!({ "event": event }),
        )
    };
    let (status, body) = post(paid.clone()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["revoked"], json!([gw.mandate]), "{body}");
    assert_eq!(body["replayed"], false);
    let (status, again) = post(paid).await;
    assert_eq!(status, StatusCode::OK, "{again}");
    assert_eq!(
        (again["revoked"].clone(), again["replayed"].clone()),
        (body["revoked"].clone(), json!(true))
    );

    let (status, refused) = gw.remind("p-2").await;
    assert_eq!(status, StatusCode::OK, "{refused}");
    assert_eq!(refused["decision"], "BLOCK", "{refused}");
    assert_eq!(
        gw.provider.inbox().len(),
        1,
        "only the call before the payment"
    );

    // ADR-012 §7: the revocation is in the evidence chain, written by the
    // request that revoked, naming the loan only by its pseudonym.
    let store = gw.state.dataplane().unwrap().core().store();
    let record = store
        .revocation_record("default", "lms", "pay-1")
        .await
        .unwrap()
        .expect("a revocation record");
    assert_eq!(record.payload.revoked, vec![gw.mandate.clone()]);
    assert_eq!(
        record.payload.recorded_at, record.payload.revoked_at,
        "written at once"
    );
    let json = serde_json::to_string(&record).unwrap();
    assert!(!json.contains("L-1"), "no loan reference: {json}");
    let kinds: Vec<String> = store
        .records("default", 0)
        .await
        .unwrap()
        .iter()
        .map(|r| kavach_ports::agent_evidence::ChainEntry::kind(r).to_string())
        .collect();
    assert_eq!(
        kinds,
        ["agent_decision", "mandate_revocation", "agent_decision"],
        "the allowed call, the revocation, the refused call"
    );
}

/// Refusals and malformed calls never reach the provider.
/// The count recorded for one stage in `kavach_gateway_stage_seconds`.
fn stage_count(metrics: &str, stage: &str) -> u64 {
    let series = format!("kavach_gateway_stage_seconds_count{{stage=\"{stage}\"}} ");
    metrics
        .lines()
        .find_map(|line| line.strip_prefix(&series))
        .map_or(0, |n| n.parse().unwrap())
}

#[tokio::test]
async fn each_stage_of_a_call_is_timed_and_only_the_stages_it_ran() {
    let gw = gateway(Some(NUMBER), true).await;
    let (status, reply) = gw.remind("stages-1").await;
    assert_eq!(
        (status, &reply["outcome"]),
        (StatusCode::OK, &json!("delivered"))
    );
    let metrics = gw.state.metrics().gather_text().unwrap();
    for stage in [
        "decide",
        "commit",
        "resolve",
        "credential",
        "forward",
        "outcome",
    ] {
        assert_eq!(stage_count(&metrics, stage), 1, "{stage}: {metrics}");
    }

    // A refusal is decided and recorded, and goes no further.
    let mut other = reminder(&gw.mandate, "stages-2");
    other["params"]["subject_ref"] = json!("ref:borrower:B-5511");
    let (_, reply) = gw.call("send_reminder", other).await;
    assert_eq!(reply["decision"], "BLOCK");
    let metrics = gw.state.metrics().gather_text().unwrap();
    assert_eq!(stage_count(&metrics, "decide"), 2);
    assert_eq!(stage_count(&metrics, "commit"), 2);
    for stage in ["resolve", "credential", "forward", "outcome"] {
        assert_eq!(stage_count(&metrics, stage), 1, "{stage}");
    }
    // Only the fixed stage names appear as labels.
    for line in metrics
        .lines()
        .filter(|l| l.starts_with("kavach_gateway_stage_seconds"))
    {
        let stage = line
            .split("stage=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        assert!(
            [
                "decide",
                "commit",
                "resolve",
                "credential",
                "forward",
                "outcome"
            ]
            .contains(&stage),
            "{line}"
        );
    }
}

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

/// `GET /v1/agent-decisions/{id}` (`kavach why`): admins only, every read
/// audited (found or not), and the record carries no raw reference,
/// destination, token or credential.
#[tokio::test]
async fn evidence_reads_are_admin_only_audited_and_hold_no_secrets() {
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    let gw = gateway(Some("+910000000001"), true).await;
    let (status, reply) = gw.remind("why-1").await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let record_id = reply["record_id"].as_str().unwrap().to_string();

    let read = |id: String, token: Option<String>| {
        let app = contract::router(gw.state.clone());
        async move {
            let mut request = Request::get(format!("/v1/agent-decisions/{id}"));
            if let Some(t) = token {
                request = request.header("authorization", format!("Bearer {t}"));
            }
            let response = app
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = response.status();
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            (status, String::from_utf8_lossy(&bytes).into_owned())
        }
    };

    let (status, body) = read(record_id.clone(), Some(operator_token())).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let doc: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(doc["record"]["record_id"], record_id.as_str());
    assert!(
        doc["outcome"].is_object(),
        "the allow's outcome is included"
    );
    assert_eq!(doc["resolutions"], json!([]));
    for secret in [
        "+91",
        "910000000001",
        "eyJ",
        "Kavach-Credential",
        SUBJECT,
        "B-9382",
    ] {
        assert!(!body.contains(secret), "{secret} in {body}");
    }

    // Not an admin, not an operator at all, or no token: refused.
    let viewer = token(
        "kavach-api",
        json!({ "sub": "viewer-1", "groups": ["viewers"] }),
    );
    assert_eq!(
        read(record_id.clone(), Some(viewer)).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        read(record_id.clone(), Some(agent_token("collections-agent")))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        read(record_id.clone(), None).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        read("not-a-record".into(), Some(operator_token())).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        read("adr:default:0:999".into(), Some(operator_token()))
            .await
            .0,
        StatusCode::NOT_FOUND
    );

    // Both reads by the admin are audited: who, which record, found or not.
    let audit = gw.state.admin().list_audit(50).await.unwrap();
    let reads: Vec<_> = audit
        .iter()
        .filter(|e| e.action == "read_evidence")
        .map(|e| {
            (
                e.resource_id.as_str(),
                e.actor_principal.as_str(),
                e.payload["found"].clone(),
            )
        })
        .collect();
    assert!(
        reads.contains(&(record_id.as_str(), "ops-1", json!(true))),
        "{reads:?}"
    );
    assert!(
        reads.contains(&("adr:default:0:999", "ops-1", json!(false))),
        "{reads:?}"
    );
    assert_eq!(reads.len(), 2, "refused requests read nothing: {reads:?}");
}

/// One stack serves one tenant: a validly signed payment for the same loan
/// but another tenant is refused before it is acted on, and the mandate
/// still works. A revocation's evidence record is read like an agent
/// record (`GET /v1/agent-revocations/{system}/{event_id}`): admins only,
/// every read audited, and it never holds the loan reference.
#[tokio::test]
async fn another_tenants_event_is_refused_and_revocation_reads_are_audited() {
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    let gw = gateway(Some(NUMBER), true).await;
    let post = |event: String| {
        send(
            sor_router(gw.state.clone()),
            "/v1/sor/events",
            &[],
            json!({ "event": event }),
        )
    };
    let foreign = any_event(&AnyEvent {
        event_id: "pay-other",
        event_type: "loan.paid",
        tenant_id: "another-tenant",
        subject_ref: SUBJECT,
        record_ref: "lms:loan/L-1",
        consent_refs: &[],
        assigned_agent: "",
        at: gw.clock_now(),
        key: EventKey::Registered,
    })
    .await;
    let (status, body) = post(foreign).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["detail"].as_str().unwrap().contains("tenant"),
        "{body}"
    );
    assert_eq!(gw.remind("tenant-1").await.1["decision"], "PASS");

    let paid = revocation_at("pay-1", "loan.paid", "lms:loan/L-1", gw.clock_now()).await;
    assert_eq!(post(paid).await.0, StatusCode::OK);

    let read = |path: String, token: Option<String>| {
        let app = contract::router(gw.state.clone());
        async move {
            let mut request = Request::get(format!("/v1/agent-revocations/{path}"));
            if let Some(t) = token {
                request = request.header("authorization", format!("Bearer {t}"));
            }
            let response = app
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = response.status();
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            (status, String::from_utf8_lossy(&bytes).into_owned())
        }
    };
    let (status, body) = read("lms/pay-1".into(), Some(operator_token())).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let doc: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(doc["record"]["kind"], "mandate_revocation");
    assert_eq!(doc["record"]["event_id"], "pay-1");
    assert_eq!(doc["record"]["revoked"], json!([gw.mandate]));
    for secret in ["L-1", "B-9382", SUBJECT, "+91"] {
        assert!(!body.contains(secret), "{secret} in {body}");
    }
    let viewer = token(
        "kavach-api",
        json!({ "sub": "viewer-1", "groups": ["viewers"] }),
    );
    assert_eq!(
        read("lms/pay-1".into(), Some(viewer)).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        read("lms/pay-1".into(), None).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        read("lms/a%20b".into(), Some(operator_token())).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        read("lms/pay-other".into(), Some(operator_token())).await.0,
        StatusCode::NOT_FOUND,
        "the refused event left no record"
    );

    let audit = gw.state.admin().list_audit(50).await.unwrap();
    let reads: Vec<_> = audit
        .iter()
        .filter(|e| e.action == "read_evidence" && e.resource_type == "mandate_revocation")
        .map(|e| (e.resource_id.as_str(), e.payload["found"].clone()))
        .collect();
    assert_eq!(reads.len(), 2, "refused requests read nothing: {reads:?}");
    assert!(reads.contains(&("lms/pay-1", json!(true))), "{reads:?}");
    assert!(
        reads.contains(&("lms/pay-other", json!(false))),
        "{reads:?}"
    );
}

/// A call outlives its client. Once its decision is recorded the call
/// completes (forward, outcome) even when the client disconnects, so it
/// never ends as an allow with no outcome, and its retry gets the stored
/// reply instead of being refused as in flight for good.
#[tokio::test]
async fn a_call_completes_when_its_client_goes_away() {
    use std::time::Duration;

    let gw = gateway(Some(HANG_NUMBER), true).await;
    let dp = gw.state.dataplane().unwrap();
    let headers = [(
        "authorization",
        format!("Bearer {}", agent_token("collections-agent")),
    )];
    let client = send(
        agent_router(gw.state.clone()),
        "/v1/tools/send_reminder",
        &headers,
        reminder(&gw.mandate, "gone-1"),
    );
    // The client gives up the moment its call is under way (what a closed
    // connection does to the handler: its future is dropped).
    let started = async {
        while dp.in_flight().current() == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    };
    tokio::select! {
        _ = client => panic!("the call finished before its client could give up"),
        () = started => {}
    }
    assert_eq!(
        dp.in_flight().current(),
        1,
        "it carries on without its client"
    );

    // It completes: sent once, and its outcome is recorded.
    assert_eq!(dp.in_flight().drain(Duration::from_secs(15)).await, 0);
    assert_eq!(
        gw.stored_outcome("gone-1").await,
        Some((Outcome::Unknown, Some("timeout_after_send".into()))),
        "an outcome, never a missing one"
    );
    assert_eq!(gw.provider.inbox().len(), 1);

    // The retry gets the stored reply, and nothing is sent again.
    let (status, again) = gw.remind("gone-1").await;
    assert_eq!(status, StatusCode::OK, "{again}");
    assert_eq!(
        (again["outcome"].as_str(), again["replayed"].as_bool()),
        (Some("unknown"), Some(true)),
        "{again}"
    );
    assert_eq!(gw.provider.inbox().len(), 1, "never sent twice");
}

/// An orderly stop (SIGTERM): the listener stops accepting at once, a call
/// in flight finishes with its outcome, every call that started is waited
/// for, and a final checkpoint covers everything recorded. Run on a real
/// listener, so a new connection is really refused.
#[tokio::test(flavor = "multi_thread")]
async fn an_orderly_stop_finishes_calls_in_flight_then_checkpoints() {
    use std::time::Duration;

    use kavach_ports::checkpoint::{CheckpointStore, Scope, CHAIN_AGENT_DECISIONS};

    let gw = gateway(Some(HANG_NUMBER), true).await;
    let dp = gw.state.dataplane().unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let stop = Arc::new(tokio::sync::Notify::new());
    let stopper = Arc::clone(&stop);
    let server = tokio::spawn(kavach_api::serve_http_on_until(
        agent_router(gw.state.clone()),
        listener,
        None,
        async move { stopper.notified().await },
        Duration::from_secs(20),
    ));

    // A call is under way: the provider holds it until its timeout.
    let call = tokio::spawn({
        let url = format!("http://{addr}/v1/tools/send_reminder");
        let body = reminder(&gw.mandate, "stop-1");
        async move {
            let response = reqwest::Client::new()
                .post(url)
                .bearer_auth(agent_token("collections-agent"))
                .json(&body)
                .send()
                .await
                .expect("the call was accepted before the stop");
            (
                response.status().as_u16(),
                response.json::<Value>().await.unwrap(),
            )
        }
    });
    while dp.in_flight().current() == 0 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // SIGTERM: no new connection from here on.
    stop.notify_one();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let refused = reqwest::Client::new()
        .get(format!("http://{addr}/health"))
        .timeout(Duration::from_secs(2))
        .send()
        .await;
    assert!(refused.is_err(), "a stopped listener accepts nothing");

    // The call in flight finishes, with its outcome, and the listener ends.
    let (status, reply) = call.await.unwrap();
    assert_eq!(status, 200, "{reply}");
    assert_eq!(reply["outcome"], "unknown", "{reply}");
    assert_eq!(reply["outcome_recorded"], true, "{reply}");
    server.await.unwrap().expect("the listener drained");

    // Everything started is waited for; a final checkpoint covers it.
    let finish =
        kavach_api::shutdown::drain_and_checkpoint(Some(dp), Duration::from_secs(10)).await;
    assert!(finish.clean(), "{finish:?}");
    let core = dp.core();
    let records = core.store().records("default", 0).await.unwrap();
    for record in records.iter().filter_map(|r| {
        kavach_ports::agent_evidence::ChainEntry::as_decision(r).filter(|d| d.is_allow())
    }) {
        let id = record.payload.credential_id.as_deref().unwrap();
        assert!(
            core.outcome(id).await.unwrap().is_some(),
            "{id} has an outcome: none is missing"
        );
    }
    let head = i64::try_from(records.len()).unwrap();
    let scope = Scope {
        tenant_id: "default",
        partition_id: 0,
        chain: CHAIN_AGENT_DECISIONS,
    };
    let checkpoints = core.store().list(scope, 0, 100).await.unwrap();
    assert_eq!(
        checkpoints.last().map(|c| c.payload.seq),
        Some(head),
        "the final checkpoint covers the last record"
    );
}

/// ADR-017 R2 end to end: a send whose response was lost (`unknown`) is
/// resolved by asking the real mock provider, not by sending again. The
/// provider says what it stored: delivered for the lost response, not
/// delivered for a provider error. The message is delivered exactly once,
/// the gateway's forward-once still holds, and the outcome row is untouched.
#[tokio::test]
async fn an_unknown_outcome_is_resolved_by_asking_the_provider_never_by_sending() {
    use kavach_dataplane::PollState;
    use kavach_ports::outcome_resolution::{
        governing, Governing, ResolutionSource, ResolutionState,
    };

    for (number, request, expected, deliveries) in [
        (HANG_NUMBER, "h-1", ResolutionState::ConfirmedDelivered, 1),
        (
            ERROR_NUMBER,
            "e-1",
            ResolutionState::ConfirmedNotDelivered,
            0,
        ),
    ] {
        let gw = gateway(Some(number), true).await;
        let (_, reply) = gw.remind(request).await;
        assert_eq!(reply["outcome"], "unknown", "{reply}");
        let before = gw.stored_outcome(request).await;
        assert_eq!(gw.provider.inbox().len(), deliveries);

        let dp = gw.state.dataplane().unwrap();
        let mut polls = PollState::default();
        // Not due yet: the first question waits 30 seconds.
        let early = kavach_api::outcome_reconciler::pass(
            dp.core(),
            dp.broker(),
            dp.forwarder(),
            &mut polls,
            gw.state.metrics(),
        )
        .await;
        assert_eq!((early.open, early.asked), (1, 0), "{early:?}");

        gw.clock.advance(chrono::Duration::seconds(31));
        let report = kavach_api::outcome_reconciler::pass(
            dp.core(),
            dp.broker(),
            dp.forwarder(),
            &mut polls,
            gw.state.metrics(),
        )
        .await;
        assert_eq!(report.asked, 1, "{report:?}");
        assert!(report.problems.is_empty(), "{report:?}");

        let record = dp.core().store();
        // The credential, from the stored record rather than from the reply.
        let records = record.records("default", 0).await.unwrap();
        let credential = records
            .iter()
            .filter_map(kavach_ports::agent_evidence::ChainEntry::as_decision)
            .find_map(|r| r.payload.credential_id.clone())
            .expect("a credential");
        let rows = record.resolutions("default", &credential).await.unwrap();
        let [row] = rows.as_slice() else {
            panic!("one resolution, got {rows:?}");
        };
        assert_eq!(
            (row.state, row.source),
            (expected, ResolutionSource::ProviderStatus)
        );
        assert!(row.evidence_digest.is_some());
        assert!(matches!(governing(&rows), Governing::Confirmed { .. }));

        // Nothing was sent: the inbox is as it was, a retry is replayed, and
        // the outcome row is as it was.
        assert_eq!(gw.provider.inbox().len(), deliveries);
        let (_, again) = gw.remind(request).await;
        assert_eq!(again["replayed"], true, "{again}");
        assert_eq!(gw.provider.inbox().len(), deliveries);
        assert_eq!(gw.stored_outcome(request).await, before);
    }
}

/// The value of one unlabelled or labelled series in the metrics text.
fn series(metrics: &str, name: &str) -> Option<i64> {
    metrics
        .lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(' '))
        .and_then(|n| n.parse().ok())
}

async fn run_pass(
    gw: &Gw,
    polls: &mut kavach_dataplane::PollState,
) -> kavach_dataplane::OutcomeReconcileReport {
    let dp = gw.state.dataplane().unwrap();
    kavach_api::outcome_reconciler::pass(
        dp.core(),
        dp.broker(),
        dp.forwarder(),
        polls,
        gw.state.metrics(),
    )
    .await
}

/// ADR-017 R3a: an unresolved or ambiguous call is visible. Counts and ages
/// only, by state and by source, and a reconciler that stops shows as an old
/// pass. Nothing in the series names a loan, a borrower or a destination.
#[tokio::test]
async fn unknown_outcomes_show_in_the_metrics_by_state_age_and_source() {
    use kavach_dataplane::PollState;
    let gw = gateway(Some(HANG_NUMBER), true).await;
    let (_, reply) = gw.remind("sig-1").await;
    assert_eq!(reply["outcome"], "unknown", "{reply}");
    let mut polls = PollState::default();
    let read = |name: &str| series(&gw.state.metrics().gather_text().unwrap(), name);
    let age = "kavach_outcome_oldest_unconfirmed_age_seconds";

    // Before any pass the series are 0; after one, the call is unresolved.
    run_pass(&gw, &mut polls).await;
    assert_eq!(read("kavach_outcomes_unresolved"), Some(1));
    assert_eq!(read("kavach_outcomes_ambiguous"), Some(0));
    assert_eq!(read("kavach_outcomes_conflicted"), Some(0));
    assert_eq!(read(age), Some(0));

    // Past the hour in which the provider is asked and before the 24 hours
    // after which the reconciler gives up, nothing happens to the call: it
    // is silent, and the age is what shows it.
    gw.clock.advance(chrono::Duration::hours(2));
    run_pass(&gw, &mut polls).await;
    assert_eq!(read(age), Some(2 * 3600), "age on the clock of the outcome");
    assert_eq!(read("kavach_outcomes_unresolved"), Some(1));

    // Past 24 hours the reconciler gives up: ambiguous, still unconfirmed,
    // and the oldest age keeps counting.
    gw.clock.advance(chrono::Duration::hours(23));
    run_pass(&gw, &mut polls).await;
    let metrics = gw.state.metrics().gather_text().unwrap();
    assert_eq!(series(&metrics, "kavach_outcomes_unresolved"), Some(0));
    assert_eq!(series(&metrics, "kavach_outcomes_ambiguous"), Some(1));
    assert_eq!(series(&metrics, age), Some(25 * 3600));
    let by_source = |source: &str| {
        series(
            &metrics,
            &format!("kavach_outcome_resolution_rows{{source=\"{source}\"}}"),
        )
    };
    assert_eq!(by_source("reconciler"), Some(1));
    for source in [
        "provider_status",
        "operator_attested",
        "conflict_resolution",
    ] {
        assert_eq!(by_source(source), Some(0), "{source}");
    }
    assert!(
        series(
            &metrics,
            "kavach_outcome_reconcile_last_pass_timestamp_seconds"
        )
        .unwrap()
            > 0
    );
    for forbidden in ["+91", "sig-1", "B-9382", "cred-"] {
        assert!(!metrics.contains(forbidden), "{forbidden} in the metrics");
    }
}

/// The agent surfaces add their own relaxations to the list, and each is a
/// series: this fixture runs on memory stores with a test clock under
/// `--insecure-dev`, and says exactly that.
#[tokio::test]
async fn the_agent_surfaces_report_the_relaxations_they_run_with() {
    use kavach_api::relaxations::Relaxation::{
        InsecureDev, MemoryAgentStores, PrincipalHeader, TestClock,
    };
    let gw = gateway(Some(NUMBER), true).await;
    let on = gw.state.relaxations();
    for expected in [InsecureDev, PrincipalHeader, MemoryAgentStores, TestClock] {
        assert!(on.contains(&expected), "{expected:?} missing from {on:?}");
    }
    let metrics = gw.state.metrics().gather_text().unwrap();
    assert_eq!(
        series(
            &metrics,
            "kavach_relaxation_active{relaxation=\"memory_agent_stores\"}"
        ),
        Some(1)
    );
    assert_eq!(series(&metrics, "kavach_insecure_dev"), Some(1));
    // Every name the process reports is one of the fixed set, and the others read 0.
    for name in kavach_api::relaxations::Relaxation::ALL {
        let value = series(
            &metrics,
            &format!(
                "kavach_relaxation_active{{relaxation=\"{}\"}}",
                name.as_str()
            ),
        );
        assert_eq!(
            value,
            Some(i64::from(on.contains(&name))),
            "{}",
            name.as_str()
        );
    }
}

/// The registry is "unsigned" only when `--insecure-dev` lets it be and no
/// signers are configured; and a weaker database mode counts only when the URL
/// asks for one and a development mode allows it.
#[test]
fn relaxations_follow_the_configuration() {
    use kavach_api::relaxations::{of_config, Relaxation};
    let mut config = agent_fixture::config_for_gateway();
    let signed = of_config(&config);
    let dp = config.dataplane.as_mut().unwrap();
    let signers = dp.tool_signers.take();
    config.pack_signers = None;
    assert!(of_config(&config).contains(&Relaxation::UnsignedToolRegistry));
    // With signers it is not.
    config.dataplane.as_mut().unwrap().tool_signers = signers;
    assert_eq!(of_config(&config), signed);
    // Not under production settings, whatever else is set.
    config.insecure_dev = false;
    let production = of_config(&config);
    assert!(
        !production.contains(&Relaxation::InsecureDev),
        "{production:?}"
    );
    assert!(!production.contains(&Relaxation::UnsignedToolRegistry));

    // A weaker database mode: the URL asks and a development mode allows.
    let url = "postgres://u:p@db:5432/k";
    let weaker = format!("{url}?sslmode=require");
    for (database_url, development, expected) in [
        (url.to_string(), true, false),
        (weaker.clone(), false, false),
        (weaker, true, true),
        (format!("{url}?sslmode=verify-full"), true, false),
    ] {
        config.evidence_store = kavach_api::EvidenceStoreKind::Postgres { database_url };
        config.database_tls = kavach_api::DatabaseTls::new(development, None);
        assert_eq!(
            of_config(&config).contains(&Relaxation::WeakerDatabaseTls),
            expected
        );
    }
}

/// What the outcome reconciler leaves beyond its lookback is a metric: a
/// gauge another pass sets, so it can be alerted on while it is above zero.
#[tokio::test]
async fn allows_without_an_outcome_beyond_the_lookback_show_in_a_metric() {
    let gw = gateway(Some(NUMBER), true).await;
    let name = "kavach_allows_without_outcome_beyond_lookback";
    assert_eq!(
        series(&gw.state.metrics().gather_text().unwrap(), name),
        Some(0)
    );
    let report = kavach_dataplane::OutcomeReconcileReport {
        beyond_lookback: 3,
        at: Some(chrono::Utc::now()),
        ..kavach_dataplane::OutcomeReconcileReport::default()
    };
    gw.state.metrics().observe_outcome_reconcile(&report);
    assert_eq!(
        series(&gw.state.metrics().gather_text().unwrap(), name),
        Some(3)
    );
}

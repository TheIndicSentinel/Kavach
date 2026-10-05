//! Refusals are RFC 9457 problems on every listener: the shape, the
//! correlation id, the standard headers, and never the caller's input.

mod agent_fixture;
mod contract;

use axum::body::Body;
use axum::http::{header, HeaderMap, Method, Request, StatusCode};
use contract::{agent_router, sor_router};
use http_body_util::BodyExt;

use serde_json::{json, Value};
use tower::ServiceExt;

use agent_fixture::*;

/// Text no problem body may repeat: a PAN, a phone number, a JWT, SQL.
const HOSTILE: [&str; 6] = [
    "ABCPE1234F",
    "98765",
    "eyJhbGciOi",
    "DROP TABLE",
    "OR 1=1",
    "<script>",
];

async fn raw(
    app: axum::Router,
    method: Method,
    uri: &str,
    headers: &[(&str, String)],
    body: impl Into<Body>,
) -> (StatusCode, HeaderMap, Value, String) {
    let mut req = Request::builder().method(method).uri(uri);
    for (k, v) in headers {
        req = req.header(*k, v);
    }
    let response = app.oneshot(req.body(body.into()).unwrap()).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8_lossy(&bytes).into_owned();
    (
        status,
        headers,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        text,
    )
}

/// The RFC 9457 shape, the correlation id, and no hostile text.
fn assert_problem(status: StatusCode, headers: &HeaderMap, body: &Value, text: &str) {
    assert!(
        status.is_client_error() || status.is_server_error(),
        "{status}: {text}"
    );
    assert_eq!(
        headers[header::CONTENT_TYPE],
        kavach_api::problem::CONTENT_TYPE,
        "{status}: {text}"
    );
    let code = body["code"].as_str().unwrap_or_default();
    assert!(
        kavach_api::problem::CODES
            .iter()
            .any(|(c, _, _)| *c == code),
        "unknown code: {text}"
    );
    assert_eq!(
        body["type"],
        format!("/problems/{}", code.replace('_', "-"))
    );
    assert_eq!(body["status"], status.as_u16(), "{text}");
    assert!(
        body["title"].is_string() && body["detail"].is_string(),
        "{text}"
    );
    assert_eq!(body["error"], body["detail"], "kept through v0.1");
    assert_eq!(
        body["request_id"].as_str(),
        headers.get("x-request-id").and_then(|v| v.to_str().ok()),
        "{text}"
    );
    for hostile in HOSTILE {
        assert!(!text.contains(hostile), "{hostile} echoed: {text}");
    }
}

#[tokio::test]
async fn hostile_input_is_never_echoed_in_a_problem() {
    let gw = gateway(Some(NUMBER), true).await;
    let agent = || {
        vec![(
            "authorization",
            format!("Bearer {}", agent_token("collections-agent")),
        )]
    };
    let json_type = ("content-type", "application/json".to_string());

    // Unknown parameter names and values carrying a PAN, a phone, SQL.
    let mut body = reminder(&gw.mandate, "h-1");
    body["params"]["ABCPE1234F' OR 1=1--"] = json!("+91 98765 43210");
    let mut headers = agent();
    headers.push(json_type.clone());
    let (status, h, body, text) = raw(
        agent_router(gw.state.clone()),
        Method::POST,
        "/v1/tools/send_reminder",
        &headers,
        body.to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{text}");
    assert_eq!(body["code"], "unknown_parameter", "{text}");
    assert_problem(status, &h, &body, &text);

    // A tool name that is SQL, and one that is a JWT.
    for tool in [
        "x%27%20OR%201%3D1%3B%20DROP%20TABLE%20mandates",
        "eyJhbGciOiJIUzI1NiJ9.e30.sig",
    ] {
        let (status, h, body, text) = raw(
            agent_router(gw.state.clone()),
            Method::POST,
            &format!("/v1/tools/{tool}"),
            &headers,
            reminder(&gw.mandate, "h-2").to_string(),
        )
        .await;
        assert_eq!(body["code"], "unknown_tool", "{text}");
        assert_problem(status, &h, &body, &text);
    }

    // A request id with a PAN in it; a parameter value of the wrong type.
    let mut bad_id = reminder(&gw.mandate, "ABCPE1234F <script>");
    bad_id["request_id"] = json!("ABCPE1234F <script>");
    let mut wrong_type = reminder(&gw.mandate, "h-3");
    wrong_type["params"]["channel"] = json!(["ABCPE1234F", "+91 98765 43210"]);
    for body in [bad_id, wrong_type] {
        let (status, h, body, text) = raw(
            agent_router(gw.state.clone()),
            Method::POST,
            "/v1/tools/send_reminder",
            &headers,
            body.to_string(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{text}");
        assert_problem(status, &h, &body, &text);
    }

    // Bodies that are not JSON, or not the envelope.
    for body in [
        "eyJhbGciOiJIUzI1NiJ9.e30.sig DROP TABLE x".to_string(),
        json!({ "ABCPE1234F": "+91 98765 43210" }).to_string(),
        json!(["OR 1=1"]).to_string(),
    ] {
        let (status, h, body, text) = raw(
            agent_router(gw.state.clone()),
            Method::POST,
            "/v1/tools/send_reminder",
            &headers,
            body,
        )
        .await;
        assert_problem(status, &h, &body, &text);
    }
}

#[tokio::test]
async fn hostile_input_is_never_echoed_by_the_sor_or_operator_listeners() {
    let gw = gateway(Some(NUMBER), true).await;
    let json_type = ("content-type", "application/json".to_string());

    // The SoR listener: not a JSON object, and a forged event.
    for body in [
        "DROP TABLE mandates".to_string(),
        json!({ "event": "eyJhbGciOiJIUzI1NiJ9.e30.sig" }).to_string(),
        json!({ "event": "x", "ABCPE1234F": 1 }).to_string(),
    ] {
        let (status, h, body, text) = raw(
            sor_router(gw.state.clone()),
            Method::POST,
            "/v1/sor/events",
            std::slice::from_ref(&json_type),
            body,
        )
        .await;
        assert_problem(status, &h, &body, &text);
    }

    // The operator API: strict bodies with hostile keys and values, a
    // hostile query, and a hostile path id.
    let operator = vec![
        ("authorization", format!("Bearer {}", operator_token())),
        json_type.clone(),
    ];
    for (method, uri, body) in [
        (
            Method::POST,
            "/v1/evaluate",
            json!({ "ABCPE1234F": "OR 1=1", "applicant": "+91 98765 43210" }).to_string(),
        ),
        (
            Method::POST,
            "/v1/evaluate",
            "<script>DROP TABLE x".to_string(),
        ),
        (
            Method::POST,
            "/v1/evaluate",
            json!({ "model_id": 98765, "input": { "pan": "ABCPE1234F" } }).to_string(),
        ),
        (
            Method::GET,
            "/v1/admin/incidents?status=ABCPE1234F%27%20OR%201%3D1&limit=%3Cscript%3E",
            String::new(),
        ),
        (
            Method::GET,
            "/v1/agent-decisions/ABCPE1234F%27%20OR%201%3D1",
            String::new(),
        ),
        (
            Method::GET,
            "/v1/decision-events/eyJhbGciOiJIUzI1NiJ9",
            String::new(),
        ),
    ] {
        let (status, h, body, text) = raw(
            contract::router(gw.state.clone()),
            method,
            uri,
            &operator,
            body,
        )
        .await;
        assert_problem(status, &h, &body, &text);
    }
}

#[tokio::test]
async fn problems_carry_the_request_id_and_the_standard_headers() {
    let gw = gateway(Some(NUMBER), true).await;

    // 401: WWW-Authenticate (RFC 6750); a caller's plain request id is kept.
    let (status, h, body, text) = raw(
        agent_router(gw.state.clone()),
        Method::POST,
        "/v1/tools/send_reminder",
        &[
            ("content-type", "application/json".to_string()),
            ("x-request-id", "req-problem-1".to_string()),
        ],
        reminder(&gw.mandate, "r-1").to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{text}");
    assert_eq!(body["code"], "unauthorized");
    assert_eq!(body["request_id"], "req-problem-1");
    assert!(h[header::WWW_AUTHENTICATE]
        .to_str()
        .unwrap()
        .starts_with("Bearer"));
    assert_problem(status, &h, &body, &text);

    // Unknown paths and wrong methods, on every listener.
    for (app, uri) in [
        (agent_router(gw.state.clone()), "/v1/nope"),
        (sor_router(gw.state.clone()), "/v1/nope"),
        (contract::router(gw.state.clone()), "/v1/nope"),
    ] {
        let (status, h, body, text) = raw(app, Method::POST, uri, &[], "").await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{text}");
        assert_eq!(body["code"], "not_found");
        assert_problem(status, &h, &body, &text);
    }
    for (app, uri) in [
        (agent_router(gw.state.clone()), "/v1/authorize"),
        (sor_router(gw.state.clone()), "/v1/sor/events"),
        (contract::router(gw.state.clone()), "/v1/evaluate"),
    ] {
        let (status, h, body, text) = raw(app, Method::DELETE, uri, &[], "").await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED, "{text}");
        assert_eq!(body["code"], "method_not_allowed");
        assert_problem(status, &h, &body, &text);
    }

    // 413 and 415 from the body extractors.
    let huge = json!({ "event": "x".repeat(kavach_api::dataplane::SOR_BODY_LIMIT + 1) });
    let (status, h, body, text) = raw(
        sor_router(gw.state.clone()),
        Method::POST,
        "/v1/sor/events",
        &[("content-type", "application/json".to_string())],
        huge.to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{text}");
    assert_problem(status, &h, &body, &text);
    let (status, h, body, text) = raw(
        sor_router(gw.state.clone()),
        Method::POST,
        "/v1/sor/events",
        &[],
        json!({ "event": "x" }).to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE, "{text}");
    assert_problem(status, &h, &body, &text);
}

#[tokio::test]
async fn rate_limited_problems_say_when_to_retry() {
    let s = state(2).await;
    let mut limited = None;
    for i in 0..4 {
        let (status, h, body, text) = raw(
            sor_router(s.clone()),
            Method::POST,
            "/v1/sor/events",
            &[("content-type", "application/json".to_string())],
            json!({ "event": event(&format!("rl-{i}"), "lms:loan/L-1").await }).to_string(),
        )
        .await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            assert_problem(status, &h, &body, &text);
            limited = Some((h, body));
        }
    }
    let (h, body) = limited.expect("the third event is over the limit");
    assert_eq!(body["code"], "rate_limited");
    assert!(
        h[header::RETRY_AFTER]
            .to_str()
            .unwrap()
            .parse::<u32>()
            .unwrap()
            > 0
    );
}

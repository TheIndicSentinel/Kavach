//! Security headers on API responses (roadmap 1.3): every response of the
//! operator, agent and system-of-record listeners, success or problem, 404
//! and 405 and the fallbacks' problems included, carries `nosniff`,
//! `no-store`, `no-referrer` and the API's Content-Security-Policy. The
//! console's own responses keep the console's policy.

mod agent_fixture;
mod contract;

use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use axum::Router;
use kavach_api::http::{API_CACHE_CONTROL, API_CONTENT_SECURITY_POLICY};
use serde_json::json;
use tower::ServiceExt;

use agent_fixture::*;

/// One request: its status and headers.
async fn hit(
    app: Router,
    method: Method,
    uri: &str,
    headers: &[(&str, String)],
    body: String,
) -> (StatusCode, HeaderMap) {
    let mut req = Request::builder().method(method).uri(uri);
    for (k, v) in headers {
        req = req.header(*k, v);
    }
    let response = app
        .oneshot(req.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    (response.status(), response.headers().clone())
}

fn assert_api_headers(what: &str, headers: &HeaderMap) {
    assert_eq!(headers["x-content-type-options"], "nosniff", "{what}");
    assert_eq!(headers["cache-control"], API_CACHE_CONTROL, "{what}");
    assert_eq!(headers["referrer-policy"], "no-referrer", "{what}");
    assert_eq!(
        headers["content-security-policy"], API_CONTENT_SECURITY_POLICY,
        "{what}"
    );
    // One of each: the layer adds, it never duplicates.
    for name in [
        "x-content-type-options",
        "cache-control",
        "referrer-policy",
        "content-security-policy",
    ] {
        assert_eq!(headers.get_all(name).iter().count(), 1, "{what}: {name}");
    }
}

fn bearer(token: &str) -> Vec<(&'static str, String)> {
    vec![("authorization", format!("Bearer {token}"))]
}

fn json_header() -> (&'static str, String) {
    ("content-type", "application/json".to_string())
}

#[test]
fn the_api_policy_is_the_strict_one() {
    assert_eq!(
        API_CONTENT_SECURITY_POLICY,
        "default-src 'none'; frame-ancestors 'none'"
    );
    assert_eq!(API_CACHE_CONTROL, "no-store");
}

#[tokio::test]
async fn operator_responses_carry_the_api_headers() {
    let s = state(50).await;
    let app = || kavach_api::router(s.clone());

    let (status, h) = hit(
        app(),
        Method::GET,
        "/health",
        &bearer(&operator_token()),
        String::new(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_api_headers("operator success", &h);

    // An agent's token is not an operator credential: a 401 problem.
    let (status, h) = hit(
        app(),
        Method::GET,
        "/v1/runtime",
        &bearer(&agent_token("collections-agent")),
        String::new(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_api_headers("operator 401", &h);

    let (status, h) = hit(app(), Method::DELETE, "/health", &[], String::new()).await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_api_headers("operator 405", &h);

    // The console fallback's problems: an unknown API path, a write to a
    // page path, and a missing file.
    for (method, path) in [
        (Method::GET, "/v1/no-such-route"),
        (Method::POST, "/"),
        (Method::GET, "/assets/no-such-file.js"),
    ] {
        let (status, h) = hit(app(), method.clone(), path, &[], String::new()).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path}");
        assert_api_headers(&format!("operator fallback {method} {path}"), &h);
    }
}

/// The console page keeps the console's own headers: its policy, not the
/// API's, and one of each.
#[tokio::test]
async fn the_console_keeps_its_own_headers() {
    let s = state(50).await;
    let (_, h) = hit(kavach_api::router(s), Method::GET, "/", &[], String::new()).await;
    assert_eq!(
        h["content-security-policy"],
        kavach_api::console::CONTENT_SECURITY_POLICY
    );
    assert_ne!(h["content-security-policy"], API_CONTENT_SECURITY_POLICY);
    assert_eq!(h["cache-control"], "no-store");
    assert_eq!(h["x-content-type-options"], "nosniff");
    assert_eq!(h["referrer-policy"], "no-referrer");
    for name in ["content-security-policy", "cache-control"] {
        assert_eq!(h.get_all(name).iter().count(), 1, "{name}");
    }
}

#[tokio::test]
async fn agent_responses_carry_the_api_headers() {
    let s = state(50).await;
    let app = || kavach_api::dataplane::agent_router(s.clone());

    let (status, h) = hit(app(), Method::GET, "/health", &[], String::new()).await;
    assert_eq!(status, StatusCode::OK);
    assert_api_headers("agent success", &h);

    let (status, h) = hit(
        app(),
        Method::POST,
        "/v1/tools/send_reminder",
        &[json_header()],
        reminder("m-none", "r-1").to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_api_headers("agent 401", &h);

    let (status, h) = hit(app(), Method::DELETE, "/v1/authorize", &[], String::new()).await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_api_headers("agent 405", &h);

    let (status, h) = hit(app(), Method::POST, "/v1/nope", &[], String::new()).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_api_headers("agent fallback", &h);
}

#[tokio::test]
async fn system_of_record_responses_carry_the_api_headers() {
    let s = state(50).await;
    let app = || kavach_api::dataplane::sor_router(s.clone());

    let (status, h) = hit(
        app(),
        Method::POST,
        "/v1/sor/events",
        &[json_header()],
        json!({ "event": event("evt-headers-1", "lms:loan/L-1").await }).to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_api_headers("sor success", &h);

    let (status, h) = hit(
        app(),
        Method::POST,
        "/v1/sor/events",
        &[json_header()],
        json!({ "event": "not-a-signed-event" }).to_string(),
    )
    .await;
    assert!(status.is_client_error(), "{status}");
    assert_api_headers("sor refusal", &h);

    let (status, h) = hit(app(), Method::DELETE, "/v1/sor/events", &[], String::new()).await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_api_headers("sor 405", &h);

    let (status, h) = hit(app(), Method::POST, "/v1/nope", &[], String::new()).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_api_headers("sor fallback", &h);
}

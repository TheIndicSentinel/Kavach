//! Agent-only mode (hosted builds; the credit track is frozen): the
//! operator listener serves the agent path's operator surface and nothing
//! of Decision Governance. The same requests against a normal stack are
//! the control: they are served there, so a 404 here is the mode, not a
//! typo in a path.

mod agent_fixture;
mod contract;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use kavach_api::EvidenceStoreKind;
use tower::ServiceExt;

use agent_fixture::*;

async fn world(agent_only: bool) -> Gw {
    let mut api = config(EvidenceStoreKind::Memory, true, 50);
    api.dataplane.as_mut().expect("agent surfaces").agent_only = agent_only;
    gateway_on(api, Some(NUMBER), true).await
}

/// One request to the operator router as an admin: its status and body.
async fn operator(gw: &Gw, method: &str, path: &str, body: Option<&str>) -> (StatusCode, String) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {}", operator_token()));
    if body.is_some() {
        request = request.header("content-type", "application/json");
    }
    let response = kavach_api::router(gw.state.clone())
        .oneshot(
            request
                .body(Body::from(body.unwrap_or_default().to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

const CREDIT_TRACK_GETS: [&str; 7] = [
    "/v1/packs",
    "/v1/models",
    "/v1/decision-events/11111111-1111-1111-1111-111111111111",
    "/v1/admin/retention",
    "/v1/admin/tombstones",
    "/v1/admin/incidents",
    "/v1/admin/batch-jobs",
];

#[tokio::test]
async fn agent_only_serves_the_agent_path_and_none_of_the_credit_track() {
    let gw = world(true).await;
    // The agent path works, and is what is recorded.
    let (status, reply) = gw.remind("ao-1").await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["decision"], "PASS", "{reply}");
    let record_id = reply["record_id"].as_str().unwrap().to_string();

    // What an operator of the agent path needs is served.
    for path in ["/health", "/v1/runtime", "/metrics", "/v1/admin/audit"] {
        let (status, body) = operator(&gw, "GET", path, None).await;
        assert_eq!(status, StatusCode::OK, "{path}: {body}");
    }
    let (status, body) = operator(
        &gw,
        "GET",
        &format!("/v1/agent-decisions/{record_id}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = operator(&gw, "GET", "/v1/change-requests", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Nothing of the credit track is. (A route that exists answers a
    // missing record with its own 404, "no such decision event"; an unknown
    // path does not say that.)
    for path in CREDIT_TRACK_GETS {
        let (status, body) = operator(&gw, "GET", path, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}: {body}");
        assert!(!body.contains("no such decision event"), "{path}: {body}");
    }
    let (status, body) = operator(&gw, "POST", "/v1/evaluate", Some("{}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

    // A change request of the credit track cannot be proposed.
    let (status, body) = operator(
        &gw,
        "POST",
        "/v1/change-requests",
        Some(r#"{"kind":"update_retention","params":{"evidence_retention_days":30}}"#),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert!(body.contains("agent-only"), "{body}");
}

/// The console is served in agent-only mode too (the built console, or the
/// plain "not built" page), with its security headers; the credit-track
/// API paths above stay problems, not the console page.
#[tokio::test]
async fn agent_only_serves_the_console() {
    let gw = world(true).await;
    let response = kavach_api::router(gw.state.clone())
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let headers = response.headers().clone();
    assert_eq!(
        headers["content-security-policy"],
        kavach_api::console::CONTENT_SECURITY_POLICY
    );
    assert_eq!(headers["cache-control"], "no-store");
    #[cfg(console_embedded)]
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8_lossy(&bytes);
    #[cfg(console_embedded)]
    assert!(body.contains("src=\"/assets/"), "{body}");
    #[cfg(not(console_embedded))]
    assert_eq!(body, kavach_api::console::NOT_BUILT);

    for path in CREDIT_TRACK_GETS {
        let (_, body) = operator(&gw, "GET", path, None).await;
        assert!(!body.contains("<html"), "{path}: {body}");
    }
}

#[tokio::test]
async fn the_same_requests_are_served_without_agent_only() {
    let gw = world(false).await;
    for path in CREDIT_TRACK_GETS {
        let (status, body) = operator(&gw, "GET", path, None).await;
        // The decision-event route answers an unknown id with its own 404.
        let route_exists =
            status != StatusCode::NOT_FOUND || body.contains("no such decision event");
        assert!(route_exists, "{path}: {status} {body}");
    }
    // /v1/packs and /v1/models list; evaluate answers a malformed body
    // itself (it is a route here).
    let (status, _) = operator(&gw, "GET", "/v1/packs", None).await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = operator(&gw, "POST", "/v1/evaluate", Some("{}")).await;
    assert_ne!(status, StatusCode::NOT_FOUND, "{body}");
    let (status, body) = operator(
        &gw,
        "POST",
        "/v1/change-requests",
        Some(r#"{"kind":"update_retention","params":{"evidence_retention_days":30}}"#),
    )
    .await;
    assert_ne!(status, StatusCode::NOT_FOUND, "{body}");
}

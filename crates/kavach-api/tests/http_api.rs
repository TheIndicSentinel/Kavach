use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use http_body_util::BodyExt;
use kavach_api::{router, AppState};
use kavach_domain::EvaluateRequest;
use std::path::PathBuf;
use tower::ServiceExt;

fn fixture_paths() -> (PathBuf, PathBuf) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    (
        root.join("packs/finance/v0.yaml"),
        root.join("models/finance/credit-underwriting-v1.yaml"),
    )
}

#[tokio::test]
async fn health_returns_ok() {
    let (pack, model) = fixture_paths();
    let state = Arc::new(AppState::from_paths(&pack, &model, None).expect("state"));
    let app = router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn evaluate_golden_clean_request() {
    let (pack, model) = fixture_paths();
    let state = Arc::new(AppState::from_paths(&pack, &model, None).expect("state"));
    let app = router(state);

    let body = include_str!("../../../golden/finance/v0/credit_clean.json");
    let request_json: serde_json::Value = serde_json::from_str(body).unwrap();
    let mut request: EvaluateRequest =
        serde_json::from_value(request_json["request"].clone()).unwrap();
    let now = Utc::now();
    request.decision_time = now;
    request.consent.timestamp = now;
    let payload = serde_json::to_vec(&request).unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/evaluate")
                .header("content-type", "application/json")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(parsed["returned_decision"], "PASS");
    assert_eq!(parsed["policy_decision"], "PASS");
    assert!(parsed["evidence_id"].as_str().is_some());
}

#[tokio::test]
async fn hmac_required_when_secret_configured() {
    let (pack, model) = fixture_paths();
    let state =
        Arc::new(AppState::from_paths(&pack, &model, Some("test-secret".into())).expect("state"));
    let app = router(state);

    let payload = br#"{"model_id":"x"}"#;
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/evaluate")
                .header("content-type", "application/json")
                .body(Body::from(payload.as_slice()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

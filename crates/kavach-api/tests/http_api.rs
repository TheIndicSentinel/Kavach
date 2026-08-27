use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use http_body_util::BodyExt;
use kavach_api::{router, AccessControlKind, ApiConfig, AppState, EvidenceStoreKind};
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
    let state = Arc::new(
        AppState::from_paths_for_tests(&pack, &model, None)
            .await
            .expect("state"),
    );
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
    let state = Arc::new(
        AppState::from_paths_for_tests(&pack, &model, None)
            .await
            .expect("state"),
    );
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
async fn metrics_endpoint_exposes_prometheus_text() {
    let (pack, model) = fixture_paths();
    let state = Arc::new(
        AppState::from_paths_for_tests(&pack, &model, None)
            .await
            .expect("state"),
    );
    let app = router(state.clone());

    let body = include_str!("../../../golden/finance/v0/credit_clean.json");
    let request_json: serde_json::Value = serde_json::from_str(body).unwrap();
    let mut request: EvaluateRequest =
        serde_json::from_value(request_json["request"].clone()).unwrap();
    let now = Utc::now();
    request.decision_time = now;
    request.consent.timestamp = now;
    let payload = serde_json::to_vec(&request).unwrap();

    let evaluate_response = app
        .clone()
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
    assert_eq!(evaluate_response.status(), StatusCode::OK);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(text.contains("kavach_evaluate_requests_total"));
    assert!(text.contains("kavach_evaluate_latency_ms"));
}

#[tokio::test]
async fn hmac_required_when_secret_configured() {
    let (pack, model) = fixture_paths();
    let state = Arc::new(
        AppState::from_paths_for_tests(&pack, &model, Some("test-secret".into()))
            .await
            .expect("state"),
    );
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

fn cedar_fixture_paths() -> (PathBuf, PathBuf) {
    let auth_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../kavach-auth/policies");
    (
        auth_root.join("kavach.cedar"),
        auth_root.join("entities.example.json"),
    )
}

async fn cedar_test_state() -> Arc<AppState> {
    let (pack, model) = fixture_paths();
    let (policy_path, entities_path) = cedar_fixture_paths();
    let config = ApiConfig {
        pack_path: pack,
        model_path: model,
        hmac_secret: None,
        evidence_store: EvidenceStoreKind::Memory,
        access_control: AccessControlKind::Cedar {
            policy_path,
            entities_path,
        },
        tls: None,
    };
    Arc::new(AppState::from_config(&config).await.expect("cedar state"))
}

#[tokio::test]
async fn cedar_requires_principal_header_for_evaluate() {
    let app = router(cedar_test_state().await);

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

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn cedar_operator_may_evaluate() {
    let app = router(cedar_test_state().await);

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
                .header("x-kavach-principal", "operator-1")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn cedar_viewer_cannot_evaluate() {
    let app = router(cedar_test_state().await);

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
                .header("x-kavach-principal", "viewer-1")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn governance_runtime_lists_active_pack_and_model() {
    let (pack, model) = fixture_paths();
    let state = Arc::new(
        AppState::from_paths_for_tests(&pack, &model, None)
            .await
            .expect("state"),
    );
    let app = router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/runtime")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(parsed["pack_id"], "finance-v0");
    assert_eq!(parsed["model_id"], "credit-underwriting-v1");
}

#[tokio::test]
async fn governance_lists_packs_and_models() {
    let (pack, model) = fixture_paths();
    let state = Arc::new(
        AppState::from_paths_for_tests(&pack, &model, None)
            .await
            .expect("state"),
    );
    let app = router(state.clone());

    let packs = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/packs")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(packs.status(), StatusCode::OK);
    let packs_json: serde_json::Value =
        serde_json::from_slice(&packs.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert!(packs_json.as_array().is_some_and(|items| !items.is_empty()));
    assert_eq!(packs_json[0]["active"], true);

    let models = app
        .oneshot(
            Request::builder()
                .uri("/v1/models")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(models.status(), StatusCode::OK);
    let models_json: serde_json::Value =
        serde_json::from_slice(&models.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert!(models_json
        .as_array()
        .is_some_and(|items| !items.is_empty()));
    assert_eq!(models_json[0]["active"], true);
}

#[tokio::test]
async fn governance_pack_detail_returns_rules() {
    let (pack, model) = fixture_paths();
    let state = Arc::new(
        AppState::from_paths_for_tests(&pack, &model, None)
            .await
            .expect("state"),
    );
    let app = router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/packs/finance-v0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(parsed["rules"]
        .as_array()
        .is_some_and(|rules| !rules.is_empty()));
}

#[cfg(console_embedded)]
#[tokio::test]
async fn console_serves_index_html() {
    let (pack, model) = fixture_paths();
    let state = Arc::new(
        AppState::from_paths_for_tests(&pack, &model, None)
            .await
            .expect("state"),
    );
    let app = router(state);

    let response = app
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(html.contains("Kavach"));
}

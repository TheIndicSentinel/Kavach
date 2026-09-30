mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use http_body_util::BodyExt;
use kavach_api::{router, AccessControlKind, ApiConfig, AppState, EvidenceStoreKind};
use kavach_domain::EvaluateRequest;
use std::path::PathBuf;
use tower::ServiceExt;

use common::{apply_as_admins, approve, as_principal, call, propose};
use serde_json::json;

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
        pack_sha256: None,
        bootstrap_pack: false,
        pack_signers: None,
        oidc: None,
        insecure_dev: true,
        mtls_principal_san: None,
        change_ttl_seconds: 3600,
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
    assert!(models_json[0]["origin"].is_string());
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

#[tokio::test]
async fn change_request_needs_a_distinct_approver_and_the_shown_digest() {
    let (root, v0_path, model_path) = temp_registry();
    let state = Arc::new(
        AppState::from_paths_for_tests(&v0_path, &model_path, None)
            .await
            .expect("state"),
    );
    let app = router(state.clone());
    let (status, request) = propose(
        &app,
        &as_principal("admin-1"),
        "activate_pack",
        json!({ "pack_id": "finance-v1" }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{request}");
    assert_eq!(request["status"], "pending");
    assert_eq!(request["binding"]["pointer_version"], 0);
    assert_eq!(
        state.runtime().pack_id,
        "finance-v0",
        "proposal changes nothing"
    );

    // The proposer cannot approve their own request.
    assert_eq!(
        approve(&app, &as_principal("admin-1"), &request).await.0,
        StatusCode::FORBIDDEN
    );
    // The approver must echo the digest they were shown.
    let mut tampered = request.clone();
    tampered["change_digest"] = json!("sha256:00");
    assert_eq!(
        approve(&app, &as_principal("admin-2"), &tampered).await.0,
        StatusCode::CONFLICT
    );

    let (status, applied) = approve(&app, &as_principal("admin-2"), &request).await;
    assert_eq!(status, StatusCode::OK, "{applied}");
    assert_eq!(applied["status"], "applied");
    assert_eq!(applied["decided_by"], "admin-2");
    assert_eq!(state.runtime().pack_id, "finance-v1");
    assert_eq!(state.runtime().pointer_version, 1);

    // A retry by the same approver returns the applied request; anyone else
    // gets a conflict.
    let (status, retried) = approve(&app, &as_principal("admin-2"), &request).await;
    assert_eq!(
        (status, &retried["status"]),
        (StatusCode::OK, &json!("applied"))
    );
    assert_eq!(
        approve(&app, &as_principal("approver-1"), &request).await.0,
        StatusCode::CONFLICT
    );

    let (_, audit) = call(
        &app,
        "GET",
        "/v1/admin/audit",
        &as_principal("admin-1"),
        None,
    )
    .await;
    let actions: Vec<&str> = audit
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["action"].as_str().unwrap())
        .collect();
    assert!(actions.contains(&"change_request_proposed"), "{actions:?}");
    assert!(actions.contains(&"activate_pack"), "{actions:?}");
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn approval_fails_when_the_runtime_moved_since_proposal() {
    let (root, v0_path, model_path) = temp_registry();
    let state = Arc::new(
        AppState::from_paths_for_tests(&v0_path, &model_path, None)
            .await
            .expect("state"),
    );
    let app = router(state.clone());
    let admin = as_principal("admin-1");
    let (_, first) = propose(
        &app,
        &admin,
        "activate_pack",
        json!({ "pack_id": "finance-v1" }),
    )
    .await;
    let (_, second) = propose(
        &app,
        &admin,
        "update_model",
        json!({
            "model_id": "credit-underwriting-v1", "governance_mode": "enforce"
        }),
    )
    .await;
    assert_eq!(
        approve(&app, &as_principal("admin-2"), &first).await.0,
        StatusCode::OK
    );

    // The second request was bound to pointer version 0.
    let (status, body) = approve(&app, &as_principal("admin-2"), &second).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let id = second["id"].as_str().unwrap();
    let (_, stored) = call(
        &app,
        "GET",
        &format!("/v1/change-requests/{id}"),
        &admin,
        None,
    )
    .await;
    assert_eq!(stored["status"], "failed");
    assert_eq!(
        state.runtime().governance_mode,
        kavach_domain::GovernanceMode::Shadow
    );
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn change_requests_can_be_cancelled_rejected_and_expire() {
    let (pack, model) = fixture_paths();
    let mut config = ApiConfig {
        pack_path: pack,
        model_path: model,
        hmac_secret: None,
        evidence_store: EvidenceStoreKind::Memory,
        access_control: AccessControlKind::None,
        tls: None,
        pack_sha256: None,
        bootstrap_pack: false,
        pack_signers: None,
        oidc: None,
        insecure_dev: true,
        mtls_principal_san: None,
        change_ttl_seconds: 3600,
    };
    let app = router(Arc::new(
        AppState::from_config(&config).await.expect("state"),
    ));
    let admin = as_principal("admin-1");
    let params = json!({ "evidence_retention_days": 90 });

    let (_, request) = propose(&app, &admin, "update_retention", params.clone()).await;
    let id = request["id"].as_str().unwrap();
    let uri = |action: &str| format!("/v1/change-requests/{id}/{action}");
    // Only the proposer cancels; the proposer cannot reject.
    assert_eq!(
        call(&app, "POST", &uri("cancel"), &as_principal("admin-2"), None)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(&app, "POST", &uri("reject"), &admin, None).await.0,
        StatusCode::FORBIDDEN
    );
    let (status, cancelled) = call(&app, "POST", &uri("cancel"), &admin, None).await;
    assert_eq!(
        (status, &cancelled["status"]),
        (StatusCode::OK, &json!("cancelled"))
    );
    assert_eq!(
        approve(&app, &as_principal("admin-2"), &request).await.0,
        StatusCode::CONFLICT
    );

    let (_, request) = propose(&app, &admin, "update_retention", params.clone()).await;
    let id = request["id"].as_str().unwrap();
    let (status, rejected) = call(
        &app,
        "POST",
        &format!("/v1/change-requests/{id}/reject"),
        &as_principal("admin-2"),
        Some(json!({ "reason": "not this quarter" })),
    )
    .await;
    assert_eq!(
        (status, &rejected["status"]),
        (StatusCode::OK, &json!("rejected"))
    );

    // Unknown parameters are refused.
    let (status, _) = propose(
        &app,
        &admin,
        "update_retention",
        json!({ "evidence_retention_days": 90, "extra": 1 }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Expiry is checked with server time at approval.
    config.change_ttl_seconds = 1;
    let app = router(Arc::new(
        AppState::from_config(&config).await.expect("state"),
    ));
    let (_, request) = propose(&app, &admin, "update_retention", params).await;
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let (status, body) = approve(&app, &as_principal("admin-2"), &request).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let (_, listed) = call(
        &app,
        "GET",
        "/v1/change-requests?status=expired",
        &admin,
        None,
    )
    .await;
    assert_eq!(listed.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn supplier_controls_are_checked_at_proposal() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    // The vendor model ships as a draft in enforce mode.
    let state = Arc::new(
        AppState::from_paths_for_tests(
            &root.join("packs/finance/v0.yaml"),
            &root.join("models/finance/credit-vendor-bureau-v1.yaml"),
            None,
        )
        .await
        .expect("state"),
    );
    let app = router(state);
    let admin = as_principal("admin-1");
    // Retiring it while it stays in enforce is still a vendor non-production
    // model in enforce: refused before anyone approves it.
    let (status, body) = propose(
        &app,
        &admin,
        "update_model",
        json!({
            "model_id": "credit-vendor-bureau-v1", "status": "retired"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body["error"]
        .as_str()
        .unwrap()
        .contains("supplier controls"));
    // Moving it to shadow is allowed.
    let (status, _) = propose(
        &app,
        &admin,
        "update_model",
        json!({
            "model_id": "credit-vendor-bureau-v1", "governance_mode": "shadow"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
}

#[tokio::test]
async fn admin_batch_jobs_list_and_get() {
    let (pack, model) = fixture_paths();
    let state = Arc::new(
        AppState::from_paths_for_tests(&pack, &model, None)
            .await
            .expect("state"),
    );
    state
        .batch_jobs()
        .seed_test_job(kavach_storage::BatchJobRecord {
            job_id: "job-test-1".into(),
            status: "completed".into(),
            input_path: "/data/partner/credit_batch.ndjson".into(),
            output_path: Some("/data/out/results.ndjson".into()),
            model_id: "credit-underwriting-v1".into(),
            governance_mode: "shadow".into(),
            total_rows: 10,
            processed_rows: 10,
            succeeded_rows: 9,
            failed_rows: 1,
            skipped_rows: 0,
            error_summary: None,
            created_at: Utc::now(),
            started_at: Some(Utc::now()),
            completed_at: Some(Utc::now()),
        });
    let app = router(state);

    let list = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/admin/batch-jobs?limit=10")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list.status(), StatusCode::OK);
    let listed: serde_json::Value =
        serde_json::from_slice(&list.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert!(listed.as_array().is_some_and(|rows| !rows.is_empty()));
    assert_eq!(listed[0]["input_path"], "credit_batch.ndjson");

    let detail = app
        .oneshot(
            Request::builder()
                .uri("/v1/admin/batch-jobs/job-test-1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(detail.status(), StatusCode::OK);
    let job: serde_json::Value =
        serde_json::from_slice(&detail.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(job["job_id"], "job-test-1");
    assert_eq!(job["succeeded_rows"], 9);
}

#[tokio::test]
async fn admin_incidents_list_returns_entries() {
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
                .uri("/v1/admin/incidents?limit=10")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(parsed.is_array());
}

#[tokio::test]
async fn vendor_enforce_draft_rejected_on_evaluate() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let pack = root.join("packs/finance/v0.yaml");
    let model = root.join("models/finance/credit-vendor-bureau-v1.yaml");
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
    request.model_id = "credit-vendor-bureau-v1".into();
    request.model_version = "1.0.0".into();
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

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(parsed["error"]
        .as_str()
        .is_some_and(|msg| msg.contains("vendor model cannot run in enforce mode")));
}

#[tokio::test]
async fn admin_audit_list_returns_entries() {
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
                .uri("/v1/admin/audit?limit=10")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(parsed.is_array());
}

#[tokio::test]
async fn retention_settings_default_and_update() {
    let (pack, model) = fixture_paths();
    let state = Arc::new(
        AppState::from_paths_for_tests(&pack, &model, None)
            .await
            .expect("state"),
    );
    let app = router(state);

    let get = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/admin/retention")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get.status(), StatusCode::OK);
    let settings: serde_json::Value =
        serde_json::from_slice(&get.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(settings["evidence_retention_days"], 365);

    let status = apply_as_admins(
        &app,
        "update_retention",
        json!({ "evidence_retention_days": 180 }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, updated) = call(
        &app,
        "GET",
        "/v1/admin/retention",
        &as_principal("admin-1"),
        None,
    )
    .await;
    assert_eq!(updated["evidence_retention_days"], 180);
    assert_eq!(updated["approved_by"], "admin-2");
}

#[tokio::test]
async fn erase_evidence_tombstones_memory_chain_row() {
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

    let evaluate = app
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
    assert_eq!(evaluate.status(), StatusCode::OK);
    let evaluate_json: serde_json::Value =
        serde_json::from_slice(&evaluate.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let evidence_id = evaluate_json["evidence_id"].as_str().unwrap().to_string();

    let status = apply_as_admins(
        &app,
        "erase_evidence",
        json!({ "evidence_id": evidence_id }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let tombstones = app
        .oneshot(
            Request::builder()
                .uri("/v1/admin/tombstones?limit=10")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(tombstones.status(), StatusCode::OK);
    let listed: serde_json::Value =
        serde_json::from_slice(&tombstones.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert!(listed
        .as_array()
        .is_some_and(|rows| rows.iter().any(|row| row["evidence_id"] == evidence_id)));
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

/// Copies the finance pack/model into a temp registry with a second pack
/// (`finance-v1`) so activate/rollback can be exercised without touching the repo.
fn temp_registry() -> (PathBuf, PathBuf, PathBuf) {
    let (pack, model) = fixture_paths();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("kavach-pin-{}-{nanos}", std::process::id()));
    let packs = root.join("packs/finance");
    let models = root.join("models/finance");
    std::fs::create_dir_all(&packs).unwrap();
    std::fs::create_dir_all(&models).unwrap();
    let v0 = std::fs::read_to_string(&pack).unwrap();
    std::fs::write(packs.join("v0.yaml"), &v0).unwrap();
    std::fs::write(
        packs.join("v1.yaml"),
        v0.replacen("id: finance-v0", "id: finance-v1", 1),
    )
    .unwrap();
    let model_path = models.join("credit-underwriting-v1.yaml");
    std::fs::copy(&model, &model_path).unwrap();
    (root, packs.join("v0.yaml"), model_path)
}

#[tokio::test]
async fn runtime_exposes_pack_sha256() {
    let (pack, model) = fixture_paths();
    let state = AppState::from_paths_for_tests(&pack, &model, None)
        .await
        .expect("state");
    let expected = kavach_policy::pack_digest(&std::fs::read(&pack).unwrap());
    assert_eq!(
        state.runtime().pack_sha256.as_deref(),
        Some(expected.as_str())
    );
}

#[tokio::test]
async fn rollback_refuses_tampered_previous_pack() {
    let (root, v0_path, model_path) = temp_registry();
    let state = Arc::new(
        AppState::from_paths_for_tests(&v0_path, &model_path, None)
            .await
            .expect("state"),
    );

    let status = apply_as_admins(
        &router(state.clone()),
        "activate_pack",
        json!({ "pack_id": "finance-v1" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(state.runtime().pack_id, "finance-v1");

    // Tamper with the previous pack file after it was pinned at activation.
    let original = std::fs::read_to_string(&v0_path).unwrap();
    std::fs::write(&v0_path, format!("{original}\n# tampered\n")).unwrap();
    let status = apply_as_admins(&router(state.clone()), "rollback_pack", json!({})).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        state.runtime().pack_id,
        "finance-v1",
        "runtime must not change"
    );
    let audit = router(state.clone())
        .oneshot(
            Request::builder()
                .uri("/v1/admin/audit")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let audit_body = audit.into_body().collect().await.unwrap().to_bytes();
    let audit_text = String::from_utf8_lossy(&audit_body);
    assert!(
        audit_text.contains("rollback_pack_refused") && audit_text.contains("pack_digest_mismatch"),
        "refusal must be audited: {audit_text}"
    );

    // Restoring the pinned bytes makes rollback succeed.
    std::fs::write(&v0_path, original).unwrap();
    let status = apply_as_admins(&router(state.clone()), "rollback_pack", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(state.runtime().pack_id, "finance-v0");

    let _ = std::fs::remove_dir_all(root);
}

async fn write_signature(provider: &kavach_keys::InMemoryKeyProvider, pack: &std::path::Path) {
    let sig = kavach_keys::sign_pack(provider, "pack-signer-1", pack)
        .await
        .expect("sign pack");
    std::fs::write(
        kavach_keys::signature_path(pack),
        serde_json::to_string(&sig).unwrap(),
    )
    .unwrap();
}

#[tokio::test]
async fn signed_packs_required_when_signers_configured() {
    let (root, v0_path, model_path) = temp_registry();
    let v1_path = v0_path.with_file_name("v1.yaml");

    let mut provider = kavach_keys::InMemoryKeyProvider::new();
    let public = provider.insert_seed("pack-signer-1", [3u8; 32]).unwrap();
    let signers_path = root.join("signers.json");
    std::fs::write(
        &signers_path,
        serde_json::json!({
            "signers": [{ "kid": public.kid, "public_key": hex::encode(public.bytes) }]
        })
        .to_string(),
    )
    .unwrap();

    let config = ApiConfig {
        pack_path: v0_path.clone(),
        model_path: model_path.clone(),
        hmac_secret: None,
        evidence_store: EvidenceStoreKind::Memory,
        access_control: AccessControlKind::None,
        tls: None,
        pack_sha256: None,
        bootstrap_pack: false,
        pack_signers: Some(signers_path),
        oidc: None,
        insecure_dev: true,
        mtls_principal_san: None,
        change_ttl_seconds: 3600,
    };

    // Unsigned startup pack is refused.
    assert!(AppState::from_config(&config).await.is_err());

    write_signature(&provider, &v0_path).await;
    let state = Arc::new(
        AppState::from_config(&config)
            .await
            .expect("signed startup"),
    );

    // Unsigned v1: activation refused and audited.
    let status = apply_as_admins(
        &router(state.clone()),
        "activate_pack",
        json!({ "pack_id": "finance-v1" }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(state.runtime().pack_id, "finance-v0");

    // Signed v1: activation succeeds.
    write_signature(&provider, &v1_path).await;
    let status = apply_as_admins(
        &router(state.clone()),
        "activate_pack",
        json!({ "pack_id": "finance-v1" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(state.runtime().pack_id, "finance-v1");

    let _ = std::fs::remove_dir_all(root);
}

/// ADR-001 §11: same correlation id with a different body is a conflict (409),
/// never a replay of the stored decision.
#[tokio::test]
async fn evaluate_idempotency_conflict_returns_409() {
    let (pack, model) = fixture_paths();
    let state = Arc::new(
        AppState::from_paths_for_tests(&pack, &model, None)
            .await
            .expect("state"),
    );
    let body = include_str!("../../../golden/finance/v0/credit_clean.json");
    let request_json: serde_json::Value = serde_json::from_str(body).unwrap();
    let mut request: EvaluateRequest =
        serde_json::from_value(request_json["request"].clone()).unwrap();
    let now = Utc::now();
    request.decision_time = now;
    request.consent.timestamp = now;

    let post = |payload: Vec<u8>| {
        router(state.clone()).oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/evaluate")
                .header("content-type", "application/json")
                .body(Body::from(payload))
                .unwrap(),
        )
    };
    let first = post(serde_json::to_vec(&request).unwrap()).await.unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let same = post(serde_json::to_vec(&request).unwrap()).await.unwrap();
    assert_eq!(same.status(), StatusCode::OK, "identical retry is a replay");

    request.input["debt_ratio"] = serde_json::json!(0.99);
    let changed = post(serde_json::to_vec(&request).unwrap()).await.unwrap();
    assert_eq!(changed.status(), StatusCode::CONFLICT);
}

/// HMAC v2: a valid signature is accepted once; replay and v1 body-only
/// signatures are rejected (ADR-008).
#[tokio::test]
async fn hmac_v2_accepts_once_and_rejects_replay_and_v1() {
    let (pack, model) = fixture_paths();
    let secret = "test-secret";
    let state = Arc::new(
        AppState::from_paths_for_tests(&pack, &model, Some(secret.into()))
            .await
            .expect("state"),
    );
    let body = include_str!("../../../golden/finance/v0/credit_clean.json");
    let request_json: serde_json::Value = serde_json::from_str(body).unwrap();
    let mut request: EvaluateRequest =
        serde_json::from_value(request_json["request"].clone()).unwrap();
    let now = Utc::now();
    request.decision_time = now;
    request.consent.timestamp = now;
    let payload = serde_json::to_vec(&request).unwrap();

    let ts = now.timestamp().to_string();
    let nonce = "nonce-h2a-000000000001";
    let v2 = kavach_api::hmac_auth::sign(
        secret,
        &kavach_api::hmac_auth::string_to_sign(&ts, nonce, "POST", "/v1/evaluate", &payload),
    );
    let send = |sig: String, nonce: &'static str| {
        router(state.clone()).oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/evaluate")
                .header("content-type", "application/json")
                .header("x-kavach-principal", "operator-1")
                .header("x-kavach-timestamp", ts.clone())
                .header("x-kavach-nonce", nonce)
                .header("x-kavach-signature", sig)
                .body(Body::from(payload.clone()))
                .unwrap(),
        )
    };
    assert_eq!(
        send(v2.clone(), nonce).await.unwrap().status(),
        StatusCode::OK
    );
    assert_eq!(
        send(v2, nonce).await.unwrap().status(),
        StatusCode::UNAUTHORIZED,
        "replay"
    );
    let v1 = kavach_api::hmac_auth::sign(secret, &payload);
    assert_eq!(
        send(v1, "nonce-h2a-000000000002").await.unwrap().status(),
        StatusCode::UNAUTHORIZED,
        "v1 body-only signature"
    );
}

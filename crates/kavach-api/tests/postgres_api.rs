//! Postgres mode end to end (`KAVACH_TEST_DATABASE_URL`): the governed
//! runtime pointer decides what a restarted API may load, and change
//! requests apply exactly once across replicas.

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use kavach_api::{router, AccessControlKind, ApiConfig, AppState, EvidenceStoreKind};
use kavach_storage::testing::isolated_database_url;
use tower::ServiceExt;

use common::{apply_as_admins, approve, as_principal, call, propose};
use serde_json::json;

fn repo(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

/// `<tmp>/packs/finance/{v0,v1}.yaml` and `<tmp>/models/finance/<model>.yaml`.
fn registry() -> PathBuf {
    let root = std::env::temp_dir().join(format!("kavach-pg-{}", uuid::Uuid::new_v4().simple()));
    let packs = root.join("packs/finance");
    let models = root.join("models/finance");
    std::fs::create_dir_all(&packs).unwrap();
    std::fs::create_dir_all(&models).unwrap();
    let v0 = std::fs::read_to_string(repo("packs/finance/v0.yaml")).unwrap();
    std::fs::write(packs.join("v0.yaml"), &v0).unwrap();
    std::fs::write(
        packs.join("v1.yaml"),
        v0.replacen("id: finance-v0", "id: finance-v1", 1),
    )
    .unwrap();
    std::fs::copy(
        repo("models/finance/credit-underwriting-v1.yaml"),
        models.join("credit-underwriting-v1.yaml"),
    )
    .unwrap();
    root
}

fn config(root: &Path, database_url: &str, pack: &str, bootstrap_pack: bool) -> ApiConfig {
    ApiConfig {
        pack_path: root.join("packs/finance").join(pack),
        model_path: root.join("models/finance/credit-underwriting-v1.yaml"),
        hmac_secret: None,
        evidence_store: EvidenceStoreKind::Postgres {
            database_url: database_url.into(),
        },
        access_control: AccessControlKind::None,
        tls: None,
        pack_sha256: None,
        bootstrap_pack,
        pack_signers: None,
        oidc: None,
        insecure_dev: true,
        mtls_principal_san: None,
        change_ttl_seconds: 3600,
    }
}

async fn start(root: &Path, url: &str, pack: &str) -> Result<Arc<AppState>, String> {
    AppState::from_config(&config(root, url, pack, false))
        .await
        .map(Arc::new)
        .map_err(|e| format!("{e:?}"))
}

async fn audit_actions(state: &AppState) -> Vec<String> {
    state
        .admin()
        .list_audit(50)
        .await
        .unwrap()
        .into_iter()
        .map(|entry| entry.action)
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn governed_pointer_survives_restarts_and_pins_bytes() {
    let Some(url) = isolated_database_url().await else {
        return;
    };
    let root = registry();

    // First start records the baseline.
    let state = start(&root, &url, "v0.yaml").await.expect("first start");
    assert!(audit_actions(&state)
        .await
        .contains(&"startup_baseline_recorded".into()));

    // Activation moves the pointer; a restart on the old pack is refused.
    assert_eq!(
        apply_as_admins(
            &router(state.clone()),
            "activate_pack",
            json!({ "pack_id": "finance-v1" })
        )
        .await,
        StatusCode::OK
    );
    drop(state);
    assert!(start(&root, &url, "v0.yaml").await.is_err());
    let state = start(&root, &url, "v1.yaml").await.expect("restart on v1");
    assert_eq!(state.runtime().pack_id, "finance-v1");

    // Rollback returns the pointer to v0.
    assert_eq!(
        apply_as_admins(&router(state.clone()), "rollback_pack", json!({})).await,
        StatusCode::OK
    );
    drop(state);
    let state = start(&root, &url, "v0.yaml")
        .await
        .expect("restart after rollback");
    assert_eq!(state.runtime().pack_id, "finance-v0");
    drop(state);

    // Changed bytes on the governed path are refused, unless the audited
    // bootstrap override is used.
    let v0 = root.join("packs/finance/v0.yaml");
    let mut bytes = std::fs::read_to_string(&v0).unwrap();
    bytes.push_str("\n# tampered\n");
    std::fs::write(&v0, bytes).unwrap();
    let Err(refused) = start(&root, &url, "v0.yaml").await else {
        panic!("tampered pack must be refused");
    };
    assert!(refused.contains("startup pack refused"), "{refused}");
    let state = AppState::from_config(&config(&root, &url, "v0.yaml", true))
        .await
        .expect("bootstrap override");
    assert!(audit_actions(&state)
        .await
        .contains(&"startup_bootstrap_override".into()));
}

#[tokio::test(flavor = "multi_thread")]
async fn evaluate_writes_postgres_evidence_and_replays() {
    let Some(url) = isolated_database_url().await else {
        return;
    };
    let root = registry();
    let state = start(&root, &url, "v0.yaml").await.expect("start");

    let mut body: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(repo("partner/finance/credit_underwriting_v1_request.json"))
            .unwrap(),
    )
    .unwrap();
    let now = chrono::Utc::now().to_rfc3339();
    body["decision_time"] = now.clone().into();
    body["consent"]["timestamp"] = now.into();
    body["correlation_id"] = "pg-replay-1".into();

    let mut ids = Vec::new();
    for _ in 0..2 {
        let request = Request::post("/v1/evaluate")
            .header("content-type", "application/json")
            .header("X-Kavach-Principal", "operator-1")
            .body(Body::from(body.to_string()))
            .unwrap();
        let response = router(state.clone()).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        ids.push(json["evidence_id"].as_str().unwrap().to_string());
    }
    assert_eq!(ids[0], ids[1], "retry replays the stored decision");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_approvals_on_two_replicas_apply_once() {
    let Some(url) = isolated_database_url().await else {
        return;
    };
    let root = registry();
    let replica_a = start(&root, &url, "v0.yaml").await.expect("replica a");
    let replica_b = start(&root, &url, "v0.yaml").await.expect("replica b");
    let (app_a, app_b) = (router(replica_a.clone()), router(replica_b.clone()));

    let (status, request) = propose(
        &app_a,
        &as_principal("admin-1"),
        "activate_pack",
        json!({ "pack_id": "finance-v1" }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{request}");

    let approver_a = as_principal("admin-2");
    let approver_b = as_principal("approver-1");
    let (a, b) = tokio::join!(
        approve(&app_a, &approver_a, &request),
        approve(&app_b, &approver_b, &request),
    );
    let statuses = [a.0, b.0];
    assert_eq!(
        statuses.iter().filter(|s| **s == StatusCode::OK).count(),
        1,
        "exactly one approval applies: {statuses:?} {} {}",
        a.1,
        b.1
    );
    assert!(statuses.contains(&StatusCode::CONFLICT));

    // One pointer write, one audit row for the change.
    let pointers = replica_a
        .admin()
        .get_runtime_pointers()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pointers.version, 2, "baseline + one activation");
    let activations = audit_actions(&replica_a)
        .await
        .into_iter()
        .filter(|a| a == "activate_pack")
        .count();
    assert_eq!(activations, 1);

    // The replica that did not apply reports drift until restarted.
    let lagging = if a.0 == StatusCode::OK {
        &app_b
    } else {
        &app_a
    };
    let (_, runtime) = call(
        lagging,
        "GET",
        "/v1/runtime",
        &as_principal("viewer-1"),
        None,
    )
    .await;
    assert_eq!(runtime["pointer_drift"], true, "{runtime}");
}

#[tokio::test(flavor = "multi_thread")]
async fn change_requests_are_immutable_once_decided() {
    let Some(url) = isolated_database_url().await else {
        return;
    };
    let root = registry();
    let state = start(&root, &url, "v0.yaml").await.expect("start");
    let app = router(state.clone());
    let (_, request) = propose(
        &app,
        &as_principal("admin-1"),
        "update_retention",
        json!({ "evidence_retention_days": 90 }),
    )
    .await;
    assert_eq!(
        approve(&app, &as_principal("admin-2"), &request).await.0,
        StatusCode::OK
    );

    let pool = sqlx::PgPool::connect(&url).await.unwrap();
    let id = request["id"].as_str().unwrap();
    let update = sqlx::query("UPDATE change_requests SET status = 'pending' WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await;
    assert!(update.is_err(), "decided rows cannot be reopened");
    let delete = sqlx::query("DELETE FROM change_requests WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await;
    assert!(delete.is_err(), "rows cannot be deleted");
}

#[tokio::test(flavor = "multi_thread")]
async fn retention_applies_exactly_the_approved_set() {
    use kavach_evaluate::EvidenceStore;
    let Some(url) = isolated_database_url().await else {
        return;
    };
    let root = registry();
    let state = start(&root, &url, "v0.yaml").await.expect("start");
    let app = router(state.clone());
    let pool = kavach_storage::StoragePool::connect(&url).await.unwrap();
    let mut evidence = pool.evidence_store();
    let old = |id: &str| old_event(id);
    evidence.append(old("old-1")).unwrap();

    let admin = as_principal("admin-1");
    let (status, request) = propose(&app, &admin, "apply_retention", json!({})).await;
    assert_eq!(status, StatusCode::CREATED, "{request}");
    assert_eq!(request["binding"]["candidate_count"], 1);

    // Evidence that ages past the cutoff after proposal changes the set.
    evidence.append(old("old-2")).unwrap();
    let (status, body) = approve(&app, &as_principal("admin-2"), &request).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");

    // A fresh proposal covers both and applies.
    let (_, request) = propose(&app, &admin, "apply_retention", json!({})).await;
    assert_eq!(request["binding"]["candidate_count"], 2);
    let (status, applied) = approve(&app, &as_principal("admin-2"), &request).await;
    assert_eq!(status, StatusCode::OK, "{applied}");
    assert_eq!(applied["outcome"]["tombstoned_count"], 2);
}

fn old_event(correlation_id: &str) -> kavach_evidence::AppendDecisionEvent {
    use kavach_domain::{Decision, GovernanceMode, ModelOrigin};
    let at = chrono::Utc::now() - chrono::Duration::days(400);
    kavach_evidence::AppendDecisionEvent {
        pack_id: "finance-v0".into(),
        pack_version: "0.1.0".into(),
        sector: "finance".into(),
        model_id: "credit-underwriting-v1".into(),
        model_version: "1.0.0".into(),
        model_origin: ModelOrigin::InHouse,
        governance_mode: GovernanceMode::Shadow,
        policy_decision: Decision::Pass,
        returned_decision: Decision::Pass,
        reason_codes: vec![],
        policy_hits: vec![],
        pii_tokens: vec![],
        input_digest: "d".into(),
        latency_ms: 1,
        decision_time: at,
        evaluated_at: at,
        service_identity_id: "test".into(),
        correlation_id: correlation_id.into(),
        idempotency_key: None,
    }
}

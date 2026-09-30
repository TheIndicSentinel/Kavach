//! Postgres mode end to end (`KAVACH_TEST_DATABASE_URL`): the governed
//! runtime pointer decides what a restarted API may load.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use kavach_api::{router, AccessControlKind, ApiConfig, AppState, EvidenceStoreKind};
use kavach_storage::testing::isolated_database_url;
use tower::ServiceExt;

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
    }
}

async fn start(root: &Path, url: &str, pack: &str) -> Result<Arc<AppState>, String> {
    AppState::from_config(&config(root, url, pack, false))
        .await
        .map(Arc::new)
        .map_err(|e| format!("{e:?}"))
}

async fn post(state: &Arc<AppState>, uri: &str) -> StatusCode {
    let request = Request::post(uri)
        .header("X-Kavach-Principal", "admin-1")
        .header("X-Kavach-Approver", "admin-2")
        .body(Body::empty())
        .unwrap();
    router(state.clone())
        .oneshot(request)
        .await
        .unwrap()
        .status()
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
        post(&state, "/v1/packs/finance-v1/activate").await,
        StatusCode::OK
    );
    drop(state);
    assert!(start(&root, &url, "v0.yaml").await.is_err());
    let state = start(&root, &url, "v1.yaml").await.expect("restart on v1");
    assert_eq!(state.runtime().pack_id, "finance-v1");

    // Rollback returns the pointer to v0.
    assert_eq!(post(&state, "/v1/packs/rollback").await, StatusCode::OK);
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

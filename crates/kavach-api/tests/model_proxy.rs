mod agent_fixture;
mod contract;

use std::sync::{Arc, Mutex};

use agent_fixture::{agent_token, config_for_gateway, event_at, issue_at, send, SUBJECT};
use axum::extract::Json;
use axum::routing::{get, post};
use axum::Router;
use contract::{agent_router, sor_router};
use kavach_api::AppState;
use kavach_domain::authority::{AuthorityChange, AuthorityUpdateEvent};
use kavach_domain::mandate::{ConsentArtefactSubset, ConsentRecord, ConsentStatus};
use kavach_keys::InMemoryKeyProvider;
use kavach_ports::agent_evidence::AgentEvidenceStore as _;
use serde_json::{json, Value};
use tokio::net::TcpListener;

async fn fixture(upstream: Router) -> (Arc<AppState>, String, Arc<Mutex<Vec<Value>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let capture = Arc::clone(&seen);
    let upstream = Router::new()
        .route(
            "/api/tags",
            get(|| async {
                Json(json!({
                    "models": [
                        {"name":"granite3.3:2b", "digest":kavach_api::model_proxy::ModelRole::Collections.manifest_digest()},
                        {"name":"qwen2.5:1.5b", "digest":kavach_api::model_proxy::ModelRole::Translation.manifest_digest()}
                    ]
                }))
            }),
        )
        .route(
            "/api/chat",
            post(move |Json(body): Json<Value>| {
                let capture = Arc::clone(&capture);
                async move {
                    capture.lock().unwrap().push(body);
                    Json(json!({"message": {"role": "assistant", "content": "ok"}, "done": true}))
                }
            }),
        )
        .merge(upstream);
    tokio::spawn(async move { axum::serve(listener, upstream).await.unwrap() });

    let mut config = config_for_gateway();
    config.dataplane.as_mut().unwrap().ollama_endpoint = Some(format!("http://{address}"));
    let state = Arc::new(AppState::from_config(&config).await.unwrap());
    (state, format!("http://{address}"), seen)
}

async fn fixture_with_model_mandate(
    upstream: Router,
) -> (Arc<AppState>, String, Arc<Mutex<Vec<Value>>>, String) {
    fixture_with_model_mandate_and_config(upstream, config_for_gateway()).await
}

async fn fixture_with_model_mandate_and_config(
    upstream: Router,
    mut config: kavach_api::ApiConfig,
) -> (Arc<AppState>, String, Arc<Mutex<Vec<Value>>>, String) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let capture = Arc::clone(&seen);
    let upstream = Router::new()
        .route(
            "/api/tags",
            get(|| async {
                Json(json!({ "models": [{
                    "name":"granite3.3:2b",
                    "digest":kavach_api::model_proxy::ModelRole::Collections.manifest_digest()
                }] }))
            }),
        )
        .route(
            "/api/chat",
            post(move |Json(body): Json<Value>| {
                let capture = Arc::clone(&capture);
                async move {
                    capture.lock().unwrap().push(body);
                    Json(json!({"message": {"role": "assistant", "content": "approved result"}, "done": true}))
                }
            }),
        )
        .merge(upstream);
    tokio::spawn(async move { axum::serve(listener, upstream).await.unwrap() });

    let dataplane = config.dataplane.as_mut().unwrap();
    dataplane.ollama_endpoint = Some(format!("http://{address}"));
    let mut mandate_config: Value =
        serde_json::from_slice(&std::fs::read(&dataplane.mandate_config).unwrap()).unwrap();
    mandate_config["templates"][0]["actions"]
        .as_array_mut()
        .unwrap()
        .push(json!("invoke_collections_model"));
    let passport = mandate_config["passports"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|passport| passport["agent_id"] == "collections-agent")
        .unwrap();
    passport["actions"]
        .as_array_mut()
        .unwrap()
        .push(json!("invoke_collections_model"));
    std::fs::write(&dataplane.mandate_config, mandate_config.to_string()).unwrap();

    let postgres = matches!(
        &config.evidence_store,
        kavach_api::EvidenceStoreKind::Postgres { .. }
    );
    let state = Arc::new(AppState::from_config(&config).await.unwrap());
    if postgres {
        seed_postgres_consent(&state).await;
    }
    let mandate = issue_at(&state, "evt-model-route", chrono::Utc::now()).await;
    (state, format!("http://{address}"), seen, mandate)
}

async fn seed_postgres_consent(state: &Arc<AppState>) {
    let now = chrono::Utc::now();
    let expires_at = now + chrono::Duration::days(30);
    let event = AuthorityUpdateEvent {
        update_id: "model-taint-consent-grant".into(),
        tenant_id: "default".into(),
        system: "lms".into(),
        occurred_at: now,
        nonce: "model-taint-consent-grant-nonce".into(),
        change: AuthorityChange::Consent(ConsentRecord {
            consent_id: "C-7f3a".into(),
            tenant_id: "default".into(),
            subject_ref: SUBJECT.into(),
            purposes: agent_fixture::set(&["loan_recovery"]),
            expires_at,
            active: true,
            artefact: Some(ConsentArtefactSubset {
                data_types: agent_fixture::set(&["financial_information"]),
                valid_from: now,
                data_from: now,
                data_to: expires_at,
                status: ConsentStatus::Active,
            }),
        }),
    };
    let mut issuer = InMemoryKeyProvider::new();
    issuer.insert_seed("lms-issuer-1", [2u8; 32]).unwrap();
    let signed = kavach_mandate::jws::sign(
        &issuer,
        "lms-issuer-1",
        kavach_mandate::jws::TYP_AUTHORITY_UPDATE,
        &event,
    )
    .await
    .unwrap();
    let (status, body) = send(
        sor_router(state.clone()),
        "/v1/sor/authority-updates",
        &[],
        json!({ "event": signed }),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::CREATED, "{body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn governed_model_task_taint_persists_and_escalates_through_postgres() {
    let Some((owner, runtime)) = kavach_storage::testing::isolated_database_urls().await else {
        return;
    };
    let mut config = agent_fixture::config(
        kavach_api::EvidenceStoreKind::Postgres {
            database_url: runtime,
        },
        true,
        50,
    );
    config.migration_database_url = Some(owner);
    let (state, _, _, mandate) = fixture_with_model_mandate_and_config(Router::new(), config).await;

    let (status, body) = send(
        agent_router(state.clone()),
        "/v1/models/collections/invoke",
        &[(
            "authorization",
            format!("Bearer {}", agent_token("collections-agent")),
        )],
        json!({
            "mandate_id": mandate.clone(),
            "request_id": "postgres-model-taint-source",
            "subject_ref": SUBJECT,
            "prompt": "synthetic prompt"
        }),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert!(state
        .dataplane()
        .unwrap()
        .task_tainted_for_agent("collections-agent", &mandate)
        .await
        .unwrap());

    let (status, body) = send(
        agent_router(state),
        "/v1/authorize",
        &[(
            "authorization",
            format!("Bearer {}", agent_token("collections-agent")),
        )],
        json!({
            "tool": "propose_plan",
            "mandate_id": mandate,
            "request_id": "postgres-model-taint-review",
            "params": {"subject_ref": SUBJECT, "waiver_bps": 500}
        }),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["decision"], "HUMAN_REVIEW", "{body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn governed_model_route_withholds_content_when_postgres_taint_insert_is_denied() {
    let Some((owner, runtime)) = kavach_storage::testing::isolated_database_urls().await else {
        return;
    };
    let mut config = agent_fixture::config(
        kavach_api::EvidenceStoreKind::Postgres {
            database_url: runtime,
        },
        true,
        50,
    );
    config.migration_database_url = Some(owner.clone());
    let (state, _, seen, mandate) =
        fixture_with_model_mandate_and_config(Router::new(), config).await;

    let owner_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&owner)
        .await
        .unwrap();
    sqlx::query("REVOKE INSERT ON agent_task_taint FROM kavach_runtime")
        .execute(&owner_pool)
        .await
        .unwrap();

    let (status, body) = send(
        agent_router(state),
        "/v1/models/collections/invoke",
        &[(
            "authorization",
            format!("Bearer {}", agent_token("collections-agent")),
        )],
        json!({
            "mandate_id": mandate,
            "request_id": "postgres-model-taint-insert-denied",
            "subject_ref": SUBJECT,
            "prompt": "synthetic prompt"
        }),
    )
    .await;

    sqlx::query("GRANT INSERT ON agent_task_taint TO kavach_runtime")
        .execute(&owner_pool)
        .await
        .unwrap();
    owner_pool.close().await;

    assert_eq!(
        status,
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        "{body}"
    );
    assert!(body.get("response").is_none());
    assert!(!body.to_string().contains("approved result"));
    assert_eq!(seen.lock().unwrap().len(), 1, "upstream completed once");
}

#[tokio::test(flavor = "multi_thread")]
async fn governed_model_route_refuses_postgres_taint_read_denial_before_upstream() {
    let Some((owner, runtime)) = kavach_storage::testing::isolated_database_urls().await else {
        return;
    };
    let mut config = agent_fixture::config(
        kavach_api::EvidenceStoreKind::Postgres {
            database_url: runtime,
        },
        true,
        50,
    );
    config.migration_database_url = Some(owner.clone());
    let (state, _, seen, mandate) =
        fixture_with_model_mandate_and_config(Router::new(), config).await;

    let owner_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&owner)
        .await
        .unwrap();
    sqlx::query("REVOKE SELECT ON agent_task_taint FROM kavach_runtime")
        .execute(&owner_pool)
        .await
        .unwrap();

    let (status, body) = send(
        agent_router(state),
        "/v1/models/collections/invoke",
        &[(
            "authorization",
            format!("Bearer {}", agent_token("collections-agent")),
        )],
        json!({
            "mandate_id": mandate,
            "request_id": "postgres-model-taint-select-denied",
            "subject_ref": SUBJECT,
            "prompt": "synthetic prompt"
        }),
    )
    .await;

    sqlx::query("GRANT SELECT ON agent_task_taint TO kavach_runtime")
        .execute(&owner_pool)
        .await
        .unwrap();
    owner_pool.close().await;

    assert_eq!(
        status,
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        "{body}"
    );
    assert!(body.get("response").is_none());
    assert!(
        seen.lock().unwrap().is_empty(),
        "model upstream was not called"
    );
}

#[tokio::test]
async fn local_manifest_digest_must_match_the_exact_approved_pin() {
    let (_, endpoint, _) = fixture(Router::new()).await;
    let proxy = kavach_api::model_proxy::OllamaProxy::new(&endpoint).unwrap();
    let digest = proxy
        .model_digest(kavach_api::model_proxy::ModelRole::Collections)
        .await
        .unwrap();
    assert_eq!(
        digest,
        format!(
            "sha256:{}",
            kavach_api::model_proxy::ModelRole::Collections.manifest_digest()
        )
    );
}

#[tokio::test]
async fn authenticated_model_role_is_fixed_and_forwarded_to_chat_only() {
    let (state, _, seen) = fixture(Router::new()).await;
    let (status, body) = send(
        agent_router(state),
        "/proxy/collections/api/chat",
        &[(
            "authorization",
            format!("Bearer {}", agent_token("collections-agent")),
        )],
        json!({"messages": [{"role":"user", "content":"synthetic prompt"}]}),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(body["message"]["content"], "ok");

    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0]["model"], "granite3.3:2b");
    assert_eq!(seen[0]["stream"], false);
    assert_eq!(seen[0]["options"]["num_ctx"], 4096);
    assert_eq!(seen[0]["options"]["num_predict"], 512);
}

#[tokio::test]
async fn model_proxy_requires_agent_auth_and_rejects_model_override() {
    let (state, _, seen) = fixture(Router::new()).await;
    let (status, _) = send(
        agent_router(state.clone()),
        "/proxy/collections/api/chat",
        &[],
        json!({"messages": [{"role":"user", "content":"synthetic prompt"}]}),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);

    let (status, _) = send(
        agent_router(state),
        "/proxy/collections/api/chat",
        &[(
            "authorization",
            format!("Bearer {}", agent_token("collections-agent")),
        )],
        json!({"model":"unapproved", "messages": [{"role":"user", "content":"synthetic prompt"}]}),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::UNPROCESSABLE_ENTITY);
    assert!(seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn model_proxy_is_disabled_without_an_endpoint_and_bounds_request_size() {
    let config = config_for_gateway();
    let state = Arc::new(AppState::from_config(&config).await.unwrap());
    let (status, _) = send(
        agent_router(state),
        "/proxy/collections/api/chat",
        &[(
            "authorization",
            format!("Bearer {}", agent_token("collections-agent")),
        )],
        json!({"messages": [{"role":"user", "content":"hi"}]}),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::SERVICE_UNAVAILABLE);

    let (state, _, seen) = fixture(Router::new()).await;
    let (status, _) = send(
        agent_router(state),
        "/proxy/collections/api/chat",
        &[(
            "authorization",
            format!("Bearer {}", agent_token("collections-agent")),
        )],
        json!({
            "messages": [{"role":"user", "content":"x".repeat(20_000)}]
        }),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::PAYLOAD_TOO_LARGE);
    assert!(seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn translation_role_uses_only_its_pinned_model() {
    let (state, _, seen) = fixture(Router::new()).await;
    let (status, _) = send(
        agent_router(state),
        "/proxy/translation/api/chat",
        &[(
            "authorization",
            format!("Bearer {}", agent_token("translation-agent")),
        )],
        json!({"messages": [{"role":"user", "content":"synthetic text"}]}),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(seen.lock().unwrap()[0]["model"], "qwen2.5:1.5b");
}

#[tokio::test]
async fn governed_model_route_refuses_invalid_mandates_without_forwarding() {
    let (state, _, seen) = fixture(Router::new()).await;
    let (status, _) = send(
        agent_router(state.clone()),
        "/v1/models/collections/invoke",
        &[(
            "authorization",
            format!("Bearer {}", agent_token("collections-agent")),
        )],
        json!({
            "mandate_id": "missing-mandate",
            "request_id": "model-route-invalid-mandate",
            "subject_ref": "ref:loan:loan-1",
            "prompt": "synthetic prompt"
        }),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::FORBIDDEN);
    assert!(
        seen.lock().unwrap().is_empty(),
        "refused calls never reach Ollama"
    );
    assert!(!state
        .dataplane()
        .unwrap()
        .task_tainted_for_agent("collections-agent", "missing-mandate")
        .await
        .unwrap());
}

#[tokio::test]
async fn governed_model_route_records_authorization_before_fixed_role_inference() {
    let (state, _, seen, mandate) = fixture_with_model_mandate(Router::new()).await;
    let other_event = event_at("evt-model-other-task", "lms:loan/L-2", chrono::Utc::now()).await;
    let (other_status, other_body) = send(
        sor_router(state.clone()),
        "/v1/sor/events",
        &[],
        json!({"event": other_event}),
    )
    .await;
    assert_eq!(
        other_status,
        axum::http::StatusCode::CREATED,
        "{other_body}"
    );
    let other_mandate = other_body["mandate_id"].as_str().unwrap();
    let (status, body) = send(
        agent_router(state.clone()),
        "/v1/models/collections/invoke",
        &[(
            "authorization",
            format!("Bearer {}", agent_token("collections-agent")),
        )],
        json!({
            "mandate_id": mandate.clone(),
            "request_id": "model-route-approved",
            "subject_ref": SUBJECT,
            "prompt": "synthetic prompt"
        }),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["response"]["message"]["content"], "approved result");
    assert!(body["invocation_id"].as_str().is_some());
    assert!(!state
        .dataplane()
        .unwrap()
        .task_tainted_for_agent("collections-agent", other_mandate)
        .await
        .unwrap());
    assert!(state
        .dataplane()
        .unwrap()
        .task_tainted_for_agent("collections-agent", &mandate)
        .await
        .unwrap());
    assert!(!state
        .dataplane()
        .unwrap()
        .task_tainted_for_agent("translation-agent", &mandate)
        .await
        .unwrap());

    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0]["model"],
        format!(
            "sha256:{}",
            kavach_api::model_proxy::ModelRole::Collections.manifest_digest()
        )
    );
    assert_eq!(seen[0]["messages"][0]["content"], "synthetic prompt");
    assert_eq!(seen[0]["stream"], false);
    drop(seen);

    let (status, precheck) = send(
        agent_router(state.clone()),
        "/v1/authorize",
        &[(
            "authorization",
            format!("Bearer {}", agent_token("collections-agent")),
        )],
        json!({
            "tool": "propose_plan",
            "mandate_id": mandate.clone(),
            "request_id": "tainted-critical-precheck",
            "params": {"subject_ref": SUBJECT, "waiver_bps": 500}
        }),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{precheck}");
    assert_eq!(precheck["decision"], "HUMAN_REVIEW", "{precheck}");
    assert!(precheck["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|reason| reason == "task_tainted"));

    let (status, decision) = send(
        agent_router(state.clone()),
        "/v1/tools/propose_plan",
        &[(
            "authorization",
            format!("Bearer {}", agent_token("collections-agent")),
        )],
        json!({
            "mandate_id": mandate,
            "request_id": "tainted-critical-commit",
            "params": {"subject_ref": SUBJECT, "waiver_bps": 500}
        }),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{decision}");
    assert_eq!(decision["decision"], "HUMAN_REVIEW", "{decision}");
    let record = state
        .dataplane()
        .unwrap()
        .core()
        .store()
        .get_by_request("default", "collections-agent", "tainted-critical-commit")
        .await
        .unwrap()
        .expect("critical tainted action is recorded");
    assert!(record
        .payload
        .signals
        .iter()
        .any(|signal| signal == "task_tainted"));
}

#[cfg(feature = "test-support")]
#[tokio::test]
async fn governed_model_route_withholds_completion_when_taint_write_fails() {
    let (state, _, seen, mandate) = fixture_with_model_mandate(Router::new()).await;
    assert!(state
        .dataplane()
        .unwrap()
        .fail_next_task_taint_write_for_tests());

    let (status, body) = send(
        agent_router(state.clone()),
        "/v1/models/collections/invoke",
        &[(
            "authorization",
            format!("Bearer {}", agent_token("collections-agent")),
        )],
        json!({
            "mandate_id": mandate.clone(),
            "request_id": "model-route-taint-write-failure",
            "subject_ref": SUBJECT,
            "prompt": "synthetic prompt"
        }),
    )
    .await;

    assert_eq!(
        status,
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        "{body}"
    );
    assert!(body.get("response").is_none());
    assert!(!body.to_string().contains("approved result"));
    assert_eq!(seen.lock().unwrap().len(), 1, "upstream completed once");
    assert!(!state
        .dataplane()
        .unwrap()
        .task_tainted_for_agent("collections-agent", &mandate)
        .await
        .unwrap());
}

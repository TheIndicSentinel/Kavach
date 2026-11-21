mod agent_fixture;
mod contract;

use std::sync::{Arc, Mutex};

use agent_fixture::{agent_token, config_for_gateway, issue_at, send, SUBJECT};
use axum::extract::Json;
use axum::routing::{get, post};
use axum::Router;
use contract::agent_router;
use kavach_api::AppState;
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

    let mut config = config_for_gateway();
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

    let state = Arc::new(AppState::from_config(&config).await.unwrap());
    let mandate = issue_at(&state, "evt-model-route", chrono::Utc::now()).await;
    (state, format!("http://{address}"), seen, mandate)
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
    assert!(state
        .dataplane()
        .unwrap()
        .task_taint_for_mandate("missing-mandate")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn governed_model_route_records_authorization_before_fixed_role_inference() {
    let (state, _, seen, mandate) = fixture_with_model_mandate(Router::new()).await;
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
    assert!(
        state
            .dataplane()
            .unwrap()
            .task_taint_for_mandate("different-mandate")
            .await
            .unwrap()
            .is_none(),
        "taint remains scoped to its mandate task"
    );
    let taint = state
        .dataplane()
        .unwrap()
        .task_taint_for_mandate(&mandate)
        .await
        .unwrap()
        .expect("completed governed model output taints its mandate task");
    assert_eq!(taint.mandate_id, mandate);
    assert_eq!(
        taint.source,
        kavach_ports::TaskTaintSource::GovernedModelOutput
    );

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
}

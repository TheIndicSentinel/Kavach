mod agent_fixture;
mod contract;

use std::sync::{Arc, Mutex};

use agent_fixture::{agent_token, config_for_gateway, send};
use axum::extract::Json;
use axum::routing::post;
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

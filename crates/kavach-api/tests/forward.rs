//! The gateway's HTTP forwarder is hardened (H5b step 8b): the credential
//! goes to the configured provider and nowhere else.
//!
//! Its own test binary: one test sets proxy environment variables.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{any, post};
use axum::Router;
use kavach_api::forward::{messages_url, HttpForwarder};
use kavach_dataplane::{ForwardResult, Forwarder};
use kavach_ports::TokenSecret;

/// A loopback server; returns its base URL.
async fn serve(app: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

/// A server that counts every request it receives (any path, any method).
async fn counter() -> (String, Arc<AtomicUsize>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&hits);
    let url = serve(Router::new().fallback(any(move || {
        let seen = Arc::clone(&seen);
        async move {
            seen.fetch_add(1, Ordering::SeqCst);
            StatusCode::ACCEPTED
        }
    })))
    .await;
    (url, hits)
}

fn forwarder(base: &str, timeout_ms: u64) -> HttpForwarder {
    let (url, _) = messages_url(base).unwrap();
    HttpForwarder::new(
        BTreeMap::from([("mock-messaging".to_string(), url)]),
        Duration::from_millis(200),
        Duration::from_millis(timeout_ms),
    )
    .unwrap()
}

fn credential() -> TokenSecret {
    TokenSecret::new("a.b.c.d.e")
}

#[tokio::test]
async fn redirects_are_never_followed() {
    let (elsewhere, hits) = counter().await;
    let target = format!("{elsewhere}/v1/messages");
    let provider = serve(Router::new().route(
        "/v1/messages",
        post(move || async move {
            (
                StatusCode::TEMPORARY_REDIRECT,
                [(axum::http::header::LOCATION, target)],
            )
        }),
    ))
    .await;
    let result = forwarder(&provider, 1000)
        .forward("mock-messaging", &credential())
        .await;
    assert_eq!(
        result,
        ForwardResult::Responded {
            status: 307,
            message_id: None
        }
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "the credential never went to the redirect target"
    );
    assert_eq!(
        kavach_dataplane::gateway::classify(&result).0,
        kavach_ports::agent_evidence::Outcome::Unknown
    );
}

#[tokio::test]
async fn ambient_proxies_are_ignored() {
    let (proxy, proxy_hits) = counter().await;
    let (provider, provider_hits) = counter().await;
    for var in ["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"] {
        std::env::set_var(var, &proxy);
    }
    std::env::remove_var("NO_PROXY");
    std::env::remove_var("no_proxy");

    // Control: an ordinary client honours the environment and goes through
    // the proxy, so the setting is in effect.
    reqwest::Client::new()
        .post(format!("{provider}/v1/messages"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        proxy_hits.load(Ordering::SeqCst),
        1,
        "control went via the proxy"
    );

    let result = forwarder(&provider, 1000)
        .forward("mock-messaging", &credential())
        .await;
    assert!(matches!(
        result,
        ForwardResult::Responded { status: 202, .. }
    ));
    assert_eq!(
        proxy_hits.load(Ordering::SeqCst),
        1,
        "the gateway bypassed the proxy"
    );
    assert_eq!(provider_hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn the_credential_is_sent_once_in_the_kavach_scheme_and_bodies_are_bounded() {
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let record = Arc::clone(&seen);
    let provider = serve(Router::new().route(
        "/v1/messages",
        post(move |headers: HeaderMap, body: axum::body::Bytes| {
            let record = Arc::clone(&record);
            async move {
                record.lock().unwrap().push((
                    headers
                        .get("authorization")
                        .map(|v| v.to_str().unwrap().to_string()),
                    body.len(),
                ));
                (
                    StatusCode::ACCEPTED,
                    r#"{"status":"accepted","message_id":"pm-1"}"#,
                )
                    .into_response()
            }
        }),
    ))
    .await;
    let result = forwarder(&provider, 1000)
        .forward("mock-messaging", &credential())
        .await;
    assert_eq!(
        result,
        ForwardResult::Responded {
            status: 202,
            message_id: Some("pm-1".into())
        }
    );
    assert_eq!(
        *seen.lock().unwrap(),
        vec![(Some("Kavach-Credential a.b.c.d.e".to_string()), 0)],
        "one request, no body"
    );

    // An oversized response keeps its status and drops the body.
    let big = serve(Router::new().route(
        "/v1/messages",
        post(|| async {
            (
                StatusCode::ACCEPTED,
                format!(r#"{{"message_id":"pm-2","pad":"{}"}}"#, "x".repeat(10_000)),
            )
        }),
    ))
    .await;
    assert_eq!(
        forwarder(&big, 1000)
            .forward("mock-messaging", &credential())
            .await,
        ForwardResult::Responded {
            status: 202,
            message_id: None
        }
    );
}

#[tokio::test]
async fn nothing_sent_and_lost_responses_are_told_apart() {
    // Connection refused: nothing was sent.
    assert_eq!(
        forwarder("http://127.0.0.1:9", 1000)
            .forward("mock-messaging", &credential())
            .await,
        ForwardResult::NotSent
    );
    // Sent, then no response within the timeout.
    let slow = serve(Router::new().route(
        "/v1/messages",
        post(|| async {
            tokio::time::sleep(Duration::from_secs(3)).await;
            StatusCode::ACCEPTED
        }),
    ))
    .await;
    assert_eq!(
        forwarder(&slow, 300)
            .forward("mock-messaging", &credential())
            .await,
        ForwardResult::Lost
    );
    // An unknown provider never gets anything.
    assert_eq!(
        forwarder("http://127.0.0.1:9", 1000)
            .forward("other-provider", &credential())
            .await,
        ForwardResult::NotSent
    );
}

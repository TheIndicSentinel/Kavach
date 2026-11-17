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
use kavach_dataplane::{
    CredentialAcceptingRequest, ForwardResult, Forwarder, ProviderStatus, StatusAsker,
};
use kavach_ports::{Destination, TokenSecret};

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
        &[],
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
async fn adapter_context_keeps_the_credential_accepting_wire_contract() {
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
    let destination = Destination::new("+919876543210");
    let token = credential();
    let result = forwarder(&provider, 1000)
        .forward_request(
            "mock-messaging",
            &CredentialAcceptingRequest {
                credential_id: "record-1",
                destination: &destination,
                channel: "whatsapp",
                template_id: "reminder-v1",
                credential: &token,
            },
        )
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
        "the default adapter sends one credential-authenticated request, with no body or resolved destination/template fields"
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

/// Provider TLS is verified against the configured CA (`--provider-ca`): a
/// private-CA provider is reachable only when its CA is trusted, and a
/// failed handshake sends nothing (`NotSent`, i.e. outcome `failed`).
#[tokio::test]
async fn provider_tls_is_verified_against_the_configured_ca() {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose};
    let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_key = KeyPair::generate().unwrap();
    let ca_pem = ca.self_signed(&ca_key).unwrap().pem();
    let issuer = Issuer::new(ca, ca_key);
    let leaf = CertificateParams::new(vec!["127.0.0.1".to_string()]).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let cert = leaf.signed_by(&leaf_key, &issuer).unwrap();

    let dir = std::env::temp_dir().join(format!("kavach-provider-tls-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("cert.pem"), cert.pem()).unwrap();
    std::fs::write(dir.join("key.pem"), leaf_key.serialize_pem()).unwrap();
    let tls = kavach_api::TlsConfig::from_paths(dir.join("cert.pem"), dir.join("key.pem"), None);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = Router::new().route("/v1/messages", post(|| async { StatusCode::ACCEPTED }));
    tokio::spawn(async move {
        kavach_api::serve_http_on(app, listener, Some(&tls))
            .await
            .unwrap();
    });
    let base = format!("https://127.0.0.1:{port}");
    let (url, plain) = messages_url(&base).unwrap();
    assert!(!plain);
    let with_ca = |roots: &[u8]| {
        HttpForwarder::new(
            BTreeMap::from([("mock-messaging".to_string(), url.clone())]),
            Duration::from_millis(1000),
            Duration::from_millis(2000),
            roots,
        )
        .unwrap()
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(matches!(
        with_ca(ca_pem.as_bytes())
            .forward("mock-messaging", &credential())
            .await,
        ForwardResult::Responded { status: 202, .. }
    ));
    assert_eq!(
        with_ca(&[]).forward("mock-messaging", &credential()).await,
        ForwardResult::NotSent,
        "an untrusted certificate fails the handshake; nothing is sent"
    );
    // A file without certificates is refused at startup.
    assert!(HttpForwarder::new(
        BTreeMap::new(),
        Duration::from_millis(1),
        Duration::from_millis(2),
        b"not a pem"
    )
    .is_err());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A provider whose status endpoint answers `body` with `status` and counts
/// the questions; returns its base URL.
async fn status_server(status: u16, body: &'static str) -> (String, Arc<AtomicUsize>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&hits);
    let app = Router::new().route(
        "/v1/messages/{jti}",
        axum::routing::get(move |headers: HeaderMap| {
            let seen = Arc::clone(&seen);
            async move {
                seen.fetch_add(1, Ordering::SeqCst);
                assert!(headers["authorization"]
                    .to_str()
                    .unwrap()
                    .starts_with("Kavach-Status "));
                (StatusCode::from_u16(status).unwrap(), body)
            }
        }),
    );
    (serve(app).await, hits)
}

fn question() -> TokenSecret {
    TokenSecret::new("a.b.c")
}

/// The status contract: exactly one member, one of three words. Anything
/// else is no answer, and no answer is never a confirmed state.
#[tokio::test]
async fn a_status_answer_is_one_of_three_words_or_nothing() {
    for (body, expected) in [
        (r#"{"status":"delivered"}"#, Some(ProviderStatus::Delivered)),
        (
            r#"{"status":"not_delivered"}"#,
            Some(ProviderStatus::NotDelivered),
        ),
        (r#"{"status":"unknown"}"#, Some(ProviderStatus::Unknown)),
        // Outside the contract.
        (
            r#"{"status":"delivered","destination":"+910000000001"}"#,
            None,
        ),
        (r#"{"status":"sent"}"#, None),
        (r#"{"status":1}"#, None),
        (r"{}", None),
        ("delivered", None),
        ("", None),
    ] {
        let (base, hits) = status_server(200, body).await;
        let answer = forwarder(&base, 500)
            .status("mock-messaging", "cred-1", &question())
            .await;
        assert_eq!(answer.as_ref().map(|a| a.status), expected, "{body}");
        if let Some(answer) = answer {
            // The evidence is the digest of the answer, never the answer.
            use sha2::Digest;
            assert_eq!(answer.digest, hex::encode(sha2::Sha256::digest(body)));
        }
        assert_eq!(hits.load(Ordering::SeqCst), 1, "asked once, never retried");
    }
}

#[tokio::test]
async fn a_refused_or_unreachable_status_question_is_no_answer() {
    for status in [400, 401, 403, 404, 429, 500, 503] {
        let (base, hits) = status_server(status, r#"{"status":"delivered"}"#).await;
        let answer = forwarder(&base, 500)
            .status("mock-messaging", "cred-1", &question())
            .await;
        assert_eq!(answer, None, "{status}");
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }
    // A provider that is not registered, and one that is not there.
    let (base, hits) = status_server(200, r#"{"status":"delivered"}"#).await;
    assert_eq!(
        forwarder(&base, 500)
            .status("other-provider", "cred-1", &question())
            .await,
        None
    );
    assert_eq!(hits.load(Ordering::SeqCst), 0, "nothing was sent");
    assert_eq!(
        forwarder("http://127.0.0.1:1", 200)
            .status("mock-messaging", "cred-1", &question())
            .await,
        None
    );
}

/// A redirect is never followed, so the question cannot be carried to
/// another host.
#[tokio::test]
async fn a_status_question_does_not_follow_redirects() {
    let (elsewhere, hits) = counter().await;
    let target = format!("{elsewhere}/v1/messages/cred-1");
    let app = Router::new().route(
        "/v1/messages/{jti}",
        axum::routing::get(move || {
            let target = target.clone();
            async move { (StatusCode::TEMPORARY_REDIRECT, [("location", target)]) }
        }),
    );
    let base = serve(app).await;
    let answer = forwarder(&base, 500)
        .status("mock-messaging", "cred-1", &question())
        .await;
    assert_eq!(answer, None);
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

/// The jti is one path segment: nothing in it can add a segment or a query.
#[tokio::test]
async fn a_jti_cannot_change_the_path_of_a_status_question() {
    let seen = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let log = Arc::clone(&seen);
    let app = Router::new().fallback(any(move |uri: axum::http::Uri| {
        let log = Arc::clone(&log);
        async move {
            log.lock().unwrap().push(uri.to_string());
            (StatusCode::OK, r#"{"status":"delivered"}"#)
        }
    }));
    let base = serve(app).await;
    let answer = forwarder(&base, 500)
        .status("mock-messaging", "a/b?x=1#y", &question())
        .await;
    assert!(answer.is_some());
    let uris = seen.lock().unwrap();
    let [uri] = uris.as_slice() else {
        panic!("one request, got {uris:?}");
    };
    let rest = uri.strip_prefix("/v1/messages/").expect(uri);
    assert!(!rest.contains(['/', '?', '#']), "{uri}");
}

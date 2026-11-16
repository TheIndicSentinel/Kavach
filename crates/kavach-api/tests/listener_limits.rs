//! Listener limits (roadmap 1.2) over real sockets: a client that never
//! finishes its request head, or its TLS handshake, is cut off; a handler
//! slower than the request timeout is answered with a 503 problem, never
//! its late result; a request over the in-flight cap is refused at once;
//! a value outside its bounds is refused at startup.
//!
//! The HSM call deadline is tested in `kavach-keys-pkcs11` (a hung call
//! fails closed within its deadline).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::routing::get;
use axum::Router;
use chrono::Utc;
use kavach_api::proto::kavach::v1::evaluate_service_client::EvaluateServiceClient;
use kavach_api::proto::kavach::v1::{Consent, EvaluateRequest};
use kavach_api::{
    serve_grpc_until, serve_http_on_with_limits, AppState, GrpcEvaluateService, ListenerLimits,
    TlsConfig,
};
use prost_types::{value::Kind, Struct, Timestamp, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Notify;

/// Every check gives up after this long, so a missing limit fails the test
/// instead of hanging it.
const GUARD: Duration = Duration::from_secs(5);

fn limits(request: u64, header: u64, handshake: u64, in_flight: usize) -> ListenerLimits {
    ListenerLimits {
        request_timeout: Duration::from_secs(request),
        header_read_timeout: Duration::from_secs(header),
        tls_handshake_timeout: Duration::from_secs(handshake),
        max_in_flight: in_flight,
    }
}

fn repo(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

/// `/ok` answers at once; `/slow` after `slow`, with a body that must
/// never reach a caller whose request timed out.
fn app(slow: Duration) -> Router {
    Router::new().route("/ok", get(|| async { "ok" })).route(
        "/slow",
        get(move || async move {
            tokio::time::sleep(slow).await;
            "ALLOW"
        }),
    )
}

async fn spawn_http(app: Router, tls: Option<TlsConfig>, limits: ListenerLimits) -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        serve_http_on_with_limits(app, listener, tls.as_ref(), limits)
            .await
            .expect("server");
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    addr
}

/// Reads (and discards) until the server closes the connection; how long
/// that took, or `None` if it was still open after [`GUARD`].
async fn closed_after(reader: &mut (impl AsyncReadExt + Unpin)) -> Option<Duration> {
    let started = Instant::now();
    let mut buf = [0u8; 1024];
    let read_to_close = async {
        loop {
            match reader.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
        }
    };
    tokio::time::timeout(GUARD, read_to_close)
        .await
        .ok()
        .map(|()| started.elapsed())
}

/// The connection was closed before [`GUARD`] (every timeout under test is
/// well below it). No tighter wall-clock bound: on a loaded machine the test
/// thread itself can be starved.
fn assert_cut_off(what: &str, after: Option<Duration>) {
    assert!(after.is_some(), "{what}: still open after {GUARD:?}");
}

#[tokio::test]
async fn a_client_that_never_finishes_its_request_head_is_cut_off() {
    let addr = spawn_http(app(Duration::ZERO), None, limits(30, 1, 10, 16)).await;

    // Half a request head, then nothing.
    let mut partial = TcpStream::connect(addr).await.unwrap();
    partial
        .write_all(b"GET /ok HTTP/1.1\r\nHost: localhost\r\n")
        .await
        .unwrap();
    let after = closed_after(&mut partial).await;
    assert_cut_off("partial head", after);
    assert!(
        after.unwrap() >= Duration::from_millis(800),
        "closed before the timeout: {after:?}"
    );

    // A byte every 200 ms: each byte arrives in time, the head never does.
    let (mut reader, mut writer) = TcpStream::connect(addr).await.unwrap().into_split();
    let drip = tokio::spawn(async move {
        let _ = writer.write_all(b"GET /ok HTTP/1.1\r\nX-Slow: ").await;
        for _ in 0..50 {
            if writer.write_all(b"a").await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    });
    assert_cut_off("drip-fed head", closed_after(&mut reader).await);
    drip.abort();

    // A connection kept alive after its response, with no next request.
    let mut idle = TcpStream::connect(addr).await.unwrap();
    idle.write_all(b"GET /ok HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    let mut buf = [0u8; 1024];
    while !response.ends_with(b"\r\n\r\nok") {
        let n = tokio::time::timeout(GUARD, idle.read(&mut buf))
            .await
            .expect("response in time")
            .unwrap();
        assert!(n > 0, "closed before the response");
        response.extend_from_slice(&buf[..n]);
    }
    assert!(response.starts_with(b"HTTP/1.1 200"));
    assert_cut_off("idle keep-alive", closed_after(&mut idle).await);

    // A client that sends its request in time is served.
    let status = reqwest::get(format!("http://{addr}/ok"))
        .await
        .unwrap()
        .status();
    assert_eq!(status, 200);
}

#[tokio::test]
async fn a_request_in_progress_is_not_cut_off_by_the_header_deadline() {
    // The handler takes twice the header read timeout but stays within the
    // request timeout: the idle deadline is paused while it runs.
    let addr = spawn_http(app(Duration::from_secs(2)), None, limits(10, 1, 10, 16)).await;
    let response = reqwest::get(format!("http://{addr}/slow")).await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), "ALLOW");
}

#[tokio::test]
async fn a_handler_slower_than_the_request_timeout_gets_a_problem() {
    // The handler would answer 200 "ALLOW" after 3 s; a 503 problem without
    // that body proves the 1 s request timeout answered first. No wall-clock
    // bound: on a loaded machine the test thread itself can be starved.
    let addr = spawn_http(app(Duration::from_secs(3)), None, limits(1, 10, 10, 16)).await;
    let response = reqwest::Client::new()
        .get(format!("http://{addr}/slow"))
        .header("x-request-id", "rid-timeout-1")
        .send()
        .await
        .expect("answered");
    assert_eq!(response.status(), 503);
    let headers = response.headers().clone();
    assert_eq!(headers["retry-after"], "5");
    assert_eq!(headers["x-request-id"], "rid-timeout-1");
    assert!(headers["content-type"]
        .to_str()
        .unwrap()
        .starts_with("application/problem+json"));
    let body = response.text().await.unwrap();
    assert!(!body.contains("ALLOW"), "the late result leaked: {body}");
    let problem: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(problem["status"], 503);
    assert_eq!(problem["code"], "unavailable");
    assert_eq!(problem["request_id"], "rid-timeout-1");
}

#[tokio::test]
async fn a_request_over_the_in_flight_cap_is_refused_at_once() {
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let (on_enter, on_release) = (Arc::clone(&entered), Arc::clone(&release));
    let app = app(Duration::ZERO).route(
        "/block",
        get(move || {
            let (on_enter, on_release) = (Arc::clone(&on_enter), Arc::clone(&on_release));
            async move {
                on_enter.notify_one();
                on_release.notified().await;
                "done"
            }
        }),
    );
    let addr = spawn_http(app, None, limits(30, 10, 10, 1)).await;
    let client = reqwest::Client::builder().timeout(GUARD).build().unwrap();

    let first = tokio::spawn({
        let client = client.clone();
        async move { client.get(format!("http://{addr}/block")).send().await }
    });
    tokio::time::timeout(GUARD, entered.notified())
        .await
        .expect("first request reached its handler");

    let refused = client
        .get(format!("http://{addr}/ok"))
        .header("x-request-id", "rid-busy-1")
        .send()
        .await
        .expect("refused before the guard");
    // Queued instead of refused, it would wait for `release` (sent below)
    // and hit the client guard rather than answer 503.
    assert_eq!(refused.status(), 503);
    assert_eq!(refused.headers()["retry-after"], "5");
    let problem: serde_json::Value = refused.json().await.unwrap();
    assert_eq!(problem["code"], "unavailable");
    assert_eq!(problem["request_id"], "rid-busy-1");

    release.notify_one();
    let first = first.await.unwrap().expect("first request answered");
    assert_eq!(first.status(), 200);
    // The finished request freed its place.
    let after = client
        .get(format!("http://{addr}/ok"))
        .send()
        .await
        .unwrap();
    assert_eq!(after.status(), 200);
}

#[tokio::test]
async fn limits_outside_their_bounds_are_refused_at_startup() {
    for bad in [
        limits(0, 10, 10, 16),
        limits(30, 0, 10, 16),
        limits(30, 10, 0, 16),
        limits(30, 10, 10, 0),
        limits(301, 10, 10, 16),
    ] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let served = tokio::time::timeout(
            GUARD,
            serve_http_on_with_limits(app(Duration::ZERO), listener, None, bad),
        )
        .await
        .expect("refused at once, not served");
        assert!(served.is_err(), "{bad:?} was accepted");
    }

    for (flag, value) in [
        ("--request-timeout-seconds", "0"),
        ("--request-timeout-seconds", "301"),
        ("--header-read-timeout-seconds", "0"),
        ("--tls-handshake-timeout-seconds", "0"),
        ("--max-in-flight-requests", "0"),
        ("--hsm-timeout-ms", "0"),
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_kavach-api"))
            .args([flag, value])
            .env("NO_COLOR", "1")
            .output()
            .expect("kavach-api runs");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{flag} {value} was accepted");
        assert!(stderr.contains(flag), "{flag} {value}: {stderr}");
    }
}

// ---------------------------------------------------------------------------
// TLS

struct ServerCert {
    dir: PathBuf,
    ca_pem: String,
}

impl ServerCert {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "kavach-limits-{}-{}-{n}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        std::fs::write(dir.join("server.pem"), cert.pem()).unwrap();
        std::fs::write(dir.join("server-key.pem"), key.serialize_pem()).unwrap();
        Self {
            ca_pem: cert.pem(),
            dir,
        }
    }

    fn tls_config(&self) -> TlsConfig {
        TlsConfig::from_paths(
            self.dir.join("server.pem"),
            self.dir.join("server-key.pem"),
            None,
        )
    }
}

impl Drop for ServerCert {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[tokio::test]
async fn a_stalled_tls_handshake_is_cut_off() {
    // The header read timeout is far longer, so only the handshake timeout
    // can close the connection in time.
    let cert = ServerCert::new();
    let addr = spawn_http(
        app(Duration::ZERO),
        Some(cert.tls_config()),
        limits(30, 120, 1, 16),
    )
    .await;

    let mut silent = TcpStream::connect(addr).await.unwrap();
    assert_cut_off("silent TLS client", closed_after(&mut silent).await);

    // A client that completes its handshake is served.
    let client = reqwest::Client::builder()
        .tls_built_in_root_certs(false)
        .add_root_certificate(reqwest::Certificate::from_pem(cert.ca_pem.as_bytes()).unwrap())
        .resolve("localhost", addr)
        .timeout(GUARD)
        .build()
        .unwrap();
    let status = client
        .get(format!("https://localhost:{}/ok", addr.port()))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(status, 200);
}

// ---------------------------------------------------------------------------
// gRPC

fn evaluate_request() -> EvaluateRequest {
    let now = Utc::now();
    let ts = Timestamp {
        seconds: now.timestamp(),
        nanos: now.timestamp_subsec_nanos().cast_signed(),
    };
    let mut input = Struct::default();
    for (field, value) in [("debt_ratio", 0.32), ("credit_score", 740.0)] {
        input.fields.insert(
            field.into(),
            Value {
                kind: Some(Kind::NumberValue(value)),
            },
        );
    }
    EvaluateRequest {
        model_id: "credit-underwriting-v1".into(),
        model_version: "1.0.0".into(),
        purpose: "credit_decision".into(),
        consent: Some(Consent {
            purpose_id: "credit_decision".into(),
            timestamp: Some(ts),
            valid: None,
        }),
        input: Some(input),
        confidence: Some(0.89),
        decision_time: Some(ts),
        correlation_id: "grpc-limits-001".into(),
        ..Default::default()
    }
}

async fn spawn_grpc(tls: Option<TlsConfig>, limits: ListenerLimits) -> SocketAddr {
    let state = Arc::new(
        AppState::from_paths_for_tests(
            &repo("packs/finance/v0.yaml"),
            &repo("models/finance/credit-underwriting-v1.yaml"),
            None,
        )
        .await
        .expect("state"),
    );
    let service = GrpcEvaluateService::with_limits(state, &limits);
    let addr = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    tokio::spawn(async move {
        serve_grpc_until(service, addr, tls.as_ref(), std::future::pending(), limits)
            .await
            .expect("grpc server");
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    addr
}

#[tokio::test]
async fn grpc_serves_calls_and_cuts_off_silent_connections() {
    let addr = spawn_grpc(None, limits(30, 1, 10, 16)).await;

    let mut client = EvaluateServiceClient::connect(format!("http://{addr}"))
        .await
        .expect("connect");
    client
        .evaluate(evaluate_request())
        .await
        .expect("evaluate within the limits");

    let mut silent = TcpStream::connect(addr).await.unwrap();
    assert_cut_off("silent gRPC client", closed_after(&mut silent).await);
}

#[tokio::test]
async fn grpc_cuts_off_a_stalled_tls_handshake() {
    let cert = ServerCert::new();
    let addr = spawn_grpc(Some(cert.tls_config()), limits(30, 120, 1, 16)).await;

    let mut silent = TcpStream::connect(addr).await.unwrap();
    assert_cut_off("silent gRPC TLS client", closed_after(&mut silent).await);

    let tls = tonic::transport::ClientTlsConfig::new()
        .ca_certificate(tonic::transport::Certificate::from_pem(&cert.ca_pem))
        .domain_name("localhost");
    let channel =
        tonic::transport::Channel::from_shared(format!("https://127.0.0.1:{}", addr.port()))
            .unwrap()
            .tls_config(tls)
            .unwrap()
            .connect()
            .await
            .expect("TLS connect");
    EvaluateServiceClient::new(channel)
        .evaluate(evaluate_request())
        .await
        .expect("evaluate over TLS");
}

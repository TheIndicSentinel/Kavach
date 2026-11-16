//! A startup error about an endpoint never carries the endpoint's
//! credential-bearing parts. `AppState::from_config` errors reach stderr
//! (the binary prints them with Debug), so a provider endpoint or a JWKS URL
//! is named by scheme, host and port only: never userinfo, path, query or
//! fragment.
//!
//! The secrets have no digits, so the log redactor (which masks digit runs)
//! cannot hide a leak and let a test pass without the fix.

mod agent_fixture;
mod contract;

use std::sync::Arc;

use kavach_api::{ApiConfig, AppState, EvidenceStoreKind, JwksSource};
use serde_json::json;

use agent_fixture::*;

const SECRETS: [&str; 4] = ["opsuser", "topsecretpw", "letmeinplease", "hiddenpath"];

/// Every log line written by this test binary, through the real redacting
/// subscriber (as `tests/gateway.rs` does).
#[derive(Clone, Default)]
struct Capture(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn logs() -> &'static Capture {
    static LOGS: std::sync::OnceLock<Capture> = std::sync::OnceLock::new();
    LOGS.get_or_init(|| {
        let capture = Capture::default();
        let writer = capture.clone();
        kavach_telemetry::init_with(kavach_telemetry::LogFormat::Json, move || writer.clone())
            .expect("subscriber");
        capture
    })
}

fn log_text() -> String {
    String::from_utf8_lossy(&logs().0.lock().unwrap()).into_owned()
}

/// A gateway configuration whose messaging provider has `endpoint`.
fn config_with_provider(endpoint: &str) -> ApiConfig {
    let api = config(EvidenceStoreKind::Memory, true, 50);
    let dp = api.dataplane.as_ref().unwrap();
    write_providers(&dp.providers, endpoint, CLOSED_PORT);
    std::fs::write(
        &dp.references,
        json!({ "references": [{ "tenant_id": "default", "subject_ref": SUBJECT,
            "destinations": { "whatsapp": "+910000000001" } }] })
        .to_string(),
    )
    .unwrap();
    api
}

/// Starts from `api`, expects a refusal, and returns its Display and Debug
/// after checking that neither, nor any log line, carries a secret.
async fn refusal(api: &ApiConfig) -> String {
    logs();
    let Err(err) = AppState::from_config(api).await else {
        panic!("the configuration was accepted");
    };
    let (display, debug) = (err.to_string(), format!("{err:?}"));
    let logged = log_text();
    for secret in SECRETS {
        assert!(!display.contains(secret), "{secret} in Display: {display}");
        assert!(!debug.contains(secret), "{secret} in Debug: {debug}");
        assert!(!logged.contains(secret), "{secret} in the log: {logged}");
    }
    display
}

#[tokio::test]
async fn a_provider_endpoint_with_a_path_and_query_is_refused_by_origin_only() {
    let api = config_with_provider(
        "https://opsuser:topsecretpw@provider.internal:8443/hiddenpath?token=letmeinplease",
    );
    let shown = refusal(&api).await;
    assert!(
        shown.contains(
            "provider mock-messaging: endpoint https://provider.internal:8443 must be a plain \
             base URL"
        ),
        "{shown}"
    );
}

#[tokio::test]
async fn a_provider_endpoint_with_only_a_query_token_is_refused_by_origin_only() {
    let api = config_with_provider("https://provider.internal/hiddenpath?token=letmeinplease");
    let shown = refusal(&api).await;
    assert!(
        shown.contains("endpoint https://provider.internal must be a plain base URL"),
        "{shown}"
    );
}

#[tokio::test]
async fn an_unparseable_provider_endpoint_with_userinfo_is_not_echoed() {
    // The port is not a number, so the endpoint does not parse.
    let api = config_with_provider(
        "https://opsuser:topsecretpw@provider.internal:hiddenpath/?token=letmeinplease",
    );
    let shown = refusal(&api).await;
    assert!(
        shown.contains("provider mock-messaging: endpoint does not parse: invalid port number"),
        "{shown}"
    );
}

#[tokio::test]
async fn an_unreachable_jwks_url_is_named_by_origin_only() {
    let mut api = config_with_provider(CLOSED_PORT);
    // Nothing listens on port 1: the fetch fails with a connection error.
    api.oidc.as_mut().unwrap().jwks = JwksSource::Url(
        "https://opsuser:topsecretpw@127.0.0.1:1/hiddenpath?token=letmeinplease".into(),
    );
    let shown = refusal(&api).await;
    assert!(shown.contains("fetch JWKS https://127.0.0.1:1:"), "{shown}");
}

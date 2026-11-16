//! `--require-hardening` (`kavach_api::hardening`): each condition fails
//! closed, every failure is reported, and a refusal prints no secret.
//!
//! The conditions are checked on `violations`, the function the binary calls
//! before it builds anything; the process-level tests at the end run the real
//! `kavach-api` binary.

mod agent_fixture;
mod contract;

use std::collections::BTreeSet;
use std::path::PathBuf;

use agent_fixture::{config, owner_only, write_providers};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use kavach_api::dataplane::TestClock;
use kavach_api::hardening::{origin_of, refusal, violations, Violation};
use kavach_api::relaxations::Relaxation;
use kavach_api::signing::{HsmConfig, HsmRole};
use kavach_api::{ApiConfig, AppState, EvidenceStoreKind, TlsConfig};
use kavach_ports_testkit::FakeClock;
use tower::ServiceExt;

const MESSAGING: &str = "mock-messaging";

/// A configuration every condition holds for: Postgres, TLS with an
/// owner-only key, HTTPS providers, no relaxation.
fn hardened() -> ApiConfig {
    let mut api = config(
        EvidenceStoreKind::Postgres {
            database_url: "postgres://kavach_runtime@db.internal/kavach".into(),
        },
        false,
        50,
    );
    let dir = api
        .dataplane
        .as_ref()
        .unwrap()
        .providers
        .parent()
        .unwrap()
        .to_path_buf();
    owner_only(&dir.join("tls.key"), "not a key");
    std::fs::write(dir.join("tls.crt"), "not a certificate").unwrap();
    api.tls = Some(TlsConfig::from_paths(
        dir.join("tls.crt"),
        dir.join("tls.key"),
        None,
    ));
    write_providers(
        &api.dataplane.as_ref().unwrap().providers,
        "https://messaging.example:8443",
        "https://voice.example",
    );
    api
}

fn providers_path(api: &ApiConfig) -> PathBuf {
    api.dataplane.as_ref().unwrap().providers.clone()
}

fn set_mode(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

#[test]
fn a_hardened_configuration_has_no_violation() {
    assert_eq!(violations(&hardened(), &[]), vec![]);
}

#[test]
fn plain_http_listeners_are_refused() {
    let mut api = hardened();
    api.tls = None;
    assert_eq!(violations(&api, &[]), vec![Violation::PlainListener]);
}

#[test]
fn a_plain_http_provider_is_refused_even_on_loopback() {
    for endpoint in ["http://provider.internal:8080", "http://127.0.0.1:9000"] {
        let api = hardened();
        write_providers(&providers_path(&api), endpoint, "https://voice.example");
        let found = violations(&api, &[]);
        assert_eq!(found.len(), 1, "{endpoint}: {found:?}");
        assert!(
            matches!(&found[0], Violation::PlainProvider { audience, .. } if audience == MESSAGING),
            "{endpoint}: {found:?}"
        );
    }
}

#[test]
fn a_provider_endpoint_with_userinfo_query_or_garbage_is_refused() {
    for endpoint in [
        "https://user:secret@provider.example/path?key=abc",
        "https://user@provider.example/",
        "https://:secret@provider.example/",
        "https://provider.example/?key=abc",
        "https://provider.example/#fragment",
        "not a url at all",
    ] {
        let api = hardened();
        write_providers(&providers_path(&api), endpoint, "https://voice.example");
        assert_eq!(
            violations(&api, &[]),
            vec![Violation::ProviderEndpointForm {
                audience: MESSAGING.into()
            }],
            "{endpoint}"
        );
    }
}

#[test]
fn an_unreadable_providers_file_is_refused() {
    let api = hardened();
    std::fs::remove_file(providers_path(&api)).unwrap();
    assert_eq!(violations(&api, &[]), vec![Violation::ProvidersUnreadable]);
    let api = hardened();
    std::fs::write(providers_path(&api), "{ not json").unwrap();
    assert_eq!(violations(&api, &[]), vec![Violation::ProvidersUnreadable]);
}

#[cfg(unix)]
#[test]
fn a_secret_file_open_to_group_or_others_is_refused() {
    // The TLS key.
    for mode in [0o640, 0o604, 0o644, 0o666] {
        let api = hardened();
        set_mode(&api.tls.as_ref().unwrap().key_path, mode);
        assert_eq!(
            violations(&api, &[]),
            vec![Violation::SecretFileMode {
                flag: "--tls-key",
                mode
            }]
        );
    }
    // The subject-pseudonym key.
    let api = hardened();
    set_mode(
        &api.dataplane.as_ref().unwrap().subject_pseudonym_key,
        0o640,
    );
    assert_eq!(
        violations(&api, &[]),
        vec![Violation::SecretFileMode {
            flag: "--subject-pseudonym-key",
            mode: 0o640
        }]
    );
    // The HSM PIN file.
    let mut api = hardened();
    let pin = api.tls.as_ref().unwrap().key_path.with_file_name("pin");
    owner_only(&pin, "1234");
    api.dataplane.as_mut().unwrap().hsm = Some(HsmConfig {
        module: "/nonexistent/module.so".into(),
        token_label: "kavach".into(),
        pin_file: pin.clone(),
        roles: BTreeSet::from([HsmRole::Evidence]),
        max_sessions: 2,
        call_timeout: kavach_keys_pkcs11::DEFAULT_CALL_TIMEOUT,
    });
    assert_eq!(violations(&api, &[]), vec![]);
    set_mode(&pin, 0o644);
    assert_eq!(
        violations(&api, &[]),
        vec![Violation::SecretFileMode {
            flag: "--hsm-pin-file",
            mode: 0o644
        }]
    );
}

#[test]
fn a_missing_secret_file_is_refused() {
    let api = hardened();
    std::fs::remove_file(&api.tls.as_ref().unwrap().key_path).unwrap();
    assert_eq!(
        violations(&api, &[]),
        vec![Violation::SecretFileUnreadable { flag: "--tls-key" }]
    );
}

#[cfg(not(unix))]
#[test]
fn where_the_mode_cannot_be_read_a_secret_file_is_refused() {
    let found = violations(&hardened(), &[]);
    assert!(found.contains(&Violation::SecretFileUnverifiable { flag: "--tls-key" }));
    assert!(found[0]
        .message()
        .contains("cannot be verified on this platform"));
}

/// How each relaxation is switched on, as a `match` with no wildcard: a new
/// `Relaxation` does not compile until it is placed here, and the loop below
/// then checks that the flag refuses it.
fn dp(api: &mut ApiConfig) -> &mut kavach_api::dataplane::DataplaneConfig {
    api.dataplane.as_mut().unwrap()
}

fn switch_on(r: Relaxation, api: &mut ApiConfig) -> Vec<Relaxation> {
    match r {
        Relaxation::InsecureDev | Relaxation::PrincipalHeader => api.insecure_dev = true,
        Relaxation::AccessControlNone => api.access_control = kavach_api::AccessControlKind::None,
        Relaxation::WeakerDatabaseTls => {
            api.database_tls = kavach_api::DatabaseTls::development();
            api.evidence_store = EvidenceStoreKind::Postgres {
                database_url: "postgres://u@db.internal/kavach?sslmode=disable".into(),
            };
        }
        Relaxation::MemoryEvidenceStore | Relaxation::MemoryAgentStores => {
            api.evidence_store = EvidenceStoreKind::Memory;
        }
        Relaxation::TestClock => {
            dp(api).test_clock = Some(TestClock(std::sync::Arc::new(FakeClock::synced_at(
                chrono::Utc::now(),
            ))));
        }
        Relaxation::DevClock => {
            dp(api).dev_clock = Some(kavach_api::dev_clock::DevClock::fixed(chrono::Utc::now()));
        }
        Relaxation::SystemClockDeclaredSynced | Relaxation::UnsignedToolRegistry => {
            api.insecure_dev = true;
            dp(api).tool_signers = None;
        }
        Relaxation::DevKeys => dp(api).evidence_key_id = "dev-evidence-1".into(),
        // Known only once the agent surfaces are built (`Dataplane::relaxations`).
        Relaxation::TestDoubleBroker => return vec![r],
    }
    vec![]
}

#[test]
fn every_relaxation_is_refused() {
    for r in Relaxation::ALL {
        let mut api = hardened();
        let built = switch_on(r, &mut api);
        let found = violations(&api, &built);
        assert!(
            found.contains(&Violation::Relaxed(r)),
            "{}: not refused: {found:?}",
            r.as_str()
        );
    }
}

#[test]
fn the_memory_evidence_store_is_a_relaxation_in_its_own_right() {
    let mut api = hardened();
    api.evidence_store = EvidenceStoreKind::Memory;
    let found = violations(&api, &[]);
    assert!(found.contains(&Violation::Relaxed(Relaxation::MemoryEvidenceStore)));
    assert!(found.contains(&Violation::Relaxed(Relaxation::MemoryAgentStores)));
}

#[test]
fn every_failing_condition_is_reported_at_once() {
    let mut api = hardened();
    api.tls = None;
    api.insecure_dev = true;
    write_providers(
        &providers_path(&api),
        "http://p.example:80",
        "https://v.example",
    );
    set_mode(
        &api.dataplane.as_ref().unwrap().subject_pseudonym_key,
        0o644,
    );
    let found = violations(&api, &[]);
    let names: Vec<&str> = found.iter().map(Violation::name).collect();
    for expected in ["relaxation", "tls", "provider_https", "secret_file_mode"] {
        assert!(names.contains(&expected), "{expected} missing: {names:?}");
    }
    let text = refusal("kavach-api", &found);
    assert!(text.contains(&format!("{} conditions failed", found.len())));
    for v in &found {
        assert!(text.contains(&v.message()), "{text}");
    }
}

#[test]
fn a_refusal_prints_scheme_host_and_port_and_nothing_else() {
    let api = hardened();
    write_providers(
        &providers_path(&api),
        "http://user:secret@provider.example:8080/path?key=abc#frag",
        "http://other.example:81/v2/segment",
    );
    let found = violations(&api, &[]);
    let text = refusal("kavach-api", &found);
    // The endpoint with userinfo is refused by form, the other by transport.
    assert!(text.contains("provider_endpoint_form"), "{text}");
    assert!(text.contains("http://other.example:81"), "{text}");
    for leaked in [
        "user:", "@", "secret", "path", "key=abc", "abc", "#frag", "segment", "v2",
    ] {
        assert!(!text.contains(leaked), "{leaked:?} appears in:\n{text}");
    }
    // Paths of secret files are not printed either.
    let dir = providers_path(&api).parent().unwrap().to_path_buf();
    assert!(!text.contains(dir.to_str().unwrap()), "{text}");
}

#[test]
fn the_origin_of_an_endpoint_is_scheme_host_and_port() {
    assert_eq!(
        origin_of("http://user:secret@host.example:8080/path?key=abc").as_deref(),
        Some("http://host.example:8080")
    );
    assert_eq!(
        origin_of("https://host.example/x").as_deref(),
        Some("https://host.example")
    );
    assert_eq!(origin_of("nonsense"), None);
}

#[tokio::test]
async fn the_dev_clock_route_is_not_mounted_under_the_flag() {
    /// The status and body of `POST /v1/dev/clock`.
    async fn answer(require: bool) -> (StatusCode, Vec<u8>) {
        let mut api = config(EvidenceStoreKind::Memory, true, 50);
        api.require_hardening = require;
        let state = std::sync::Arc::new(AppState::from_config(&api).await.expect("state"));
        let response = kavach_api::router(state)
            .oneshot(
                Request::post("/v1/dev/clock")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = http_body_util::BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes();
        (status, body.to_vec())
    }
    // Mounted, the handler answers 404 with a problem that says why.
    let (status, body) = answer(false).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(
        String::from_utf8_lossy(&body).contains("no fixed development clock"),
        "the route should be mounted without the flag"
    );
    // Under the flag the route does not exist: the router's own 404.
    let (status, body) = answer(true).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("no such path"), "{text}");
    assert!(!text.contains("development clock"), "{text}");
}

#[tokio::test]
async fn runtime_says_whether_the_flag_was_on() {
    let mut api = config(EvidenceStoreKind::Memory, true, 50);
    api.require_hardening = true;
    let state = std::sync::Arc::new(AppState::from_config(&api).await.expect("state"));
    let response = kavach_api::router(state)
        .oneshot(
            Request::get("/v1/runtime")
                .header(
                    "authorization",
                    format!("Bearer {}", agent_fixture::operator_token()),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = http_body_util::BodyExt::collect(response.into_body())
        .await
        .unwrap()
        .to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["require_hardening"], true, "{body}");
}

#[cfg(unix)]
mod process {
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::path::Path;
    use std::process::{Command, Output, Stdio};
    use std::time::Duration;

    fn free_port() -> u16 {
        TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn run(extra: &[&str], http: u16) -> Output {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let grpc = free_port();
        Command::new(env!("CARGO_BIN_EXE_kavach-api"))
            .args([
                "--insecure-dev",
                "--access-control",
                "none",
                "--require-hardening",
                "--pack",
                root.join("packs/finance/v0.yaml").to_str().unwrap(),
                "--model",
                root.join("models/finance/credit-underwriting-v1.yaml")
                    .to_str()
                    .unwrap(),
                "--listen",
                &format!("127.0.0.1:{http}"),
                "--grpc-listen",
                &format!("127.0.0.1:{grpc}"),
            ])
            .args(extra)
            .env("NO_COLOR", "1")
            .stdin(Stdio::null())
            .output()
            .expect("run kavach-api")
    }

    fn listening(port: u16) -> bool {
        TcpStream::connect_timeout(
            &SocketAddr::from(([127, 0, 0, 1], port)),
            Duration::from_millis(300),
        )
        .is_ok()
    }

    #[test]
    fn the_process_refuses_to_start_lists_every_failure_and_binds_nothing() {
        let http = free_port();
        let out = run(&[], http);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(78), "{stderr}");
        for name in ["relaxation", "tls"] {
            assert!(stderr.contains(name), "{name}: {stderr}");
        }
        for relaxation in [
            "insecure_dev",
            "access_control_none",
            "principal_header",
            "memory_evidence_store",
        ] {
            assert!(stderr.contains(relaxation), "{relaxation}: {stderr}");
        }
        assert!(!listening(http), "a listener is bound after a refusal");
    }

    #[test]
    fn the_process_refuses_a_tls_key_open_to_others_without_printing_its_path() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("kh-{}", uuid::Uuid::new_v4().simple()));
        let secret_dir = dir.join("s3cret-dir");
        std::fs::create_dir_all(&secret_dir).unwrap();
        let (cert, key) = (secret_dir.join("tls.crt"), secret_dir.join("tls.key"));
        std::fs::write(&cert, "c").unwrap();
        std::fs::write(&key, "k").unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        let out = run(
            &[
                "--tls-cert",
                cert.to_str().unwrap(),
                "--tls-key",
                key.to_str().unwrap(),
            ],
            free_port(),
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(78), "{stderr}");
        assert!(stderr.contains("secret_file_mode"), "{stderr}");
        assert!(stderr.contains("--tls-key"), "{stderr}");
        assert!(stderr.contains("644"), "{stderr}");
        assert!(
            !stderr.contains("tls: "),
            "TLS is on, so no tls failure: {stderr}"
        );
        assert!(
            !stderr.contains("s3cret-dir"),
            "a path is printed: {stderr}"
        );
    }
}

//! Agent surfaces over HTTP (H5a-5): `/v1/sor/events` issues mandates
//! idempotently and within limits; `/v1/authorize` is an agent-only
//! pre-check; startup refuses unsafe configurations.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use kavach_api::dataplane::{agent_router, sor_router, DataplaneConfig};
use kavach_api::{
    router, AccessControlKind, ApiConfig, AppState, EvidenceStoreKind, JwksSource, OidcConfig,
};
use kavach_domain::mandate::{
    AgentPassport, ConsentRecord, ContactWindow, DelegationRules, MandateTemplate, SorEvent,
    TimeZoneId,
};
use kavach_keys::InMemoryKeyProvider;
use kavach_ports::agent_evidence::AgentEvidenceStore;
use serde_json::{json, Value};
use tower::ServiceExt;

const ISSUER: &str = "https://idp.test/realms/kavach";
const KID: &str = "test-key-1";
const IDP_SEED: [u8; 32] = [42u8; 32];
const SUBJECT: &str = "ref:borrower:B-9382";

fn repo(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(ToString::to_string).collect()
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn token(audience: &str, claims: Value) -> String {
    let mut der = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    der.extend_from_slice(&IDP_SEED);
    let mut claims = claims;
    claims["iss"] = ISSUER.into();
    claims["aud"] = audience.into();
    claims["iat"] = now().into();
    claims["exp"] = (now() + 300).into();
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(KID.into());
    encode(&header, &claims, &EncodingKey::from_ed_der(&der)).unwrap()
}

fn agent_token(agent: &str) -> String {
    token(
        "kavach-agents",
        json!({ "sub": format!("svc-{agent}"), "azp": agent }),
    )
}

fn operator_token() -> String {
    token(
        "kavach-api",
        json!({ "sub": "ops-1", "groups": ["admins"] }),
    )
}

#[cfg(unix)]
fn owner_only(path: &Path, contents: &str) {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    f.write_all(contents.as_bytes()).unwrap();
}

#[cfg(not(unix))]
fn owner_only(path: &Path, contents: &str) {
    std::fs::write(path, contents).unwrap();
}

fn template() -> MandateTemplate {
    MandateTemplate {
        tenant_id: "default".into(),
        event_type: "loan.dpd30".into(),
        purpose: "loan_recovery".into(),
        actions: set(&["read_fields", "send_reminder", "place_call"]),
        data_fields: set(&["name", "overdue_amount", "loan_ref"]),
        channels: set(&["whatsapp", "voice"]),
        window: Some(ContactWindow {
            tz: TimeZoneId::AsiaKolkata,
            from_min: 8 * 60,
            to_min: 19 * 60,
            max_per_day: 3,
        }),
        ceilings: BTreeMap::new(),
        ttl_seconds: 7 * 24 * 3600,
        delegation: DelegationRules {
            max_depth: 1,
            allowed_agents: BTreeSet::new(),
        },
        eligible_agents: set(&["collections-agent"]),
    }
}

/// Writes keys, mandate config, consents and JWKS; returns the dataplane
/// and operator OIDC configuration.
fn files(rate: u32) -> (DataplaneConfig, OidcConfig) {
    let dir = std::env::temp_dir().join(format!("kavach-dp-{}", uuid::Uuid::new_v4().simple()));
    let keys = dir.join("keys");
    std::fs::create_dir_all(&keys).unwrap();
    owner_only(
        &keys.join("kavach-mandate-1.ed25519"),
        &hex::encode([1u8; 32]),
    );
    owner_only(
        &keys.join("kavach-evidence-1.ed25519"),
        &hex::encode([3u8; 32]),
    );
    owner_only(&dir.join("pseudonym.key"), &hex::encode([6u8; 32]));

    let lms = SigningKey::from_bytes(&[2u8; 32])
        .verifying_key()
        .to_bytes();
    let passport = |agent: &str| AgentPassport {
        agent_id: agent.into(),
        tenant_id: "default".into(),
        owner: "collections-ops".into(),
        allowed_purposes: set(&["loan_recovery"]),
        actions: set(&["read_fields", "send_reminder", "place_call"]),
        data_fields: set(&["name", "overdue_amount", "loan_ref"]),
        ceilings: BTreeMap::new(),
    };
    std::fs::write(
        dir.join("mandates.json"),
        json!({
            "issuer_id": "kavach-test",
            "signing_kid": "kavach-mandate-1",
            "sor_issuers": [{ "system": "lms", "kid": "lms-issuer-1", "public_key": hex::encode(lms) }],
            "templates": [template()],
            "passports": [passport("collections-agent")],
            "event_freshness_seconds": 300,
            "replay_window_seconds": 86400
        })
        .to_string(),
    )
    .unwrap();
    let consents = vec![ConsentRecord {
        consent_id: "C-7f3a".into(),
        tenant_id: "default".into(),
        subject_ref: SUBJECT.into(),
        purposes: set(&["loan_recovery"]),
        expires_at: chrono::Utc::now() + chrono::Duration::days(30),
        active: true,
    }];
    std::fs::write(
        dir.join("consents.json"),
        serde_json::to_string(&consents).unwrap(),
    )
    .unwrap();
    let public = SigningKey::from_bytes(&IDP_SEED).verifying_key().to_bytes();
    std::fs::write(
        dir.join("jwks.json"),
        json!({ "keys": [{ "kty": "OKP", "crv": "Ed25519", "x": URL_SAFE_NO_PAD.encode(public),
                           "kid": KID, "alg": "EdDSA", "use": "sig" }] })
        .to_string(),
    )
    .unwrap();
    let operator = OidcConfig {
        issuer: ISSUER.into(),
        audience: "kavach-api".into(),
        jwks: JwksSource::File(dir.join("jwks.json")),
        principal_claim: "sub".into(),
        groups_claim: "groups".into(),
        leeway_seconds: 30,
    };
    let dataplane = DataplaneConfig {
        agent_oidc: OidcConfig {
            audience: "kavach-agents".into(),
            principal_claim: "azp".into(),
            ..operator.clone()
        },
        mandate_config: dir.join("mandates.json"),
        mandate_keys_dir: keys.clone(),
        evidence_keys_dir: keys,
        evidence_key_id: "kavach-evidence-1".into(),
        subject_pseudonym_key: dir.join("pseudonym.key"),
        consents: dir.join("consents.json"),
        tenant_id: "default".into(),
        sor_rate_per_second: rate,
    };
    (dataplane, operator)
}

fn config(store: EvidenceStoreKind, insecure_dev: bool, rate: u32) -> ApiConfig {
    let (dataplane, operator) = files(rate);
    ApiConfig {
        pack_path: repo("packs/finance/v0.yaml"),
        model_path: repo("models/finance/credit-underwriting-v1.yaml"),
        hmac_secret: None,
        evidence_store: store,
        access_control: AccessControlKind::Cedar {
            policy_path: repo("crates/kavach-auth/policies/kavach.cedar"),
            entities_path: repo("crates/kavach-auth/policies/entities.example.json"),
        },
        tls: None,
        pack_sha256: None,
        bootstrap_pack: false,
        bootstrap_model: false,
        pack_signers: None,
        oidc: Some(operator),
        insecure_dev,
        mtls_principal_san: None,
        change_ttl_seconds: 3600,
        migration_database_url: None,
        dataplane: Some(dataplane),
    }
}

async fn state(rate: u32) -> Arc<AppState> {
    Arc::new(
        AppState::from_config(&config(EvidenceStoreKind::Memory, true, rate))
            .await
            .expect("state"),
    )
}

async fn event(event_id: &str, record_ref: &str) -> String {
    let mut sor = InMemoryKeyProvider::new();
    sor.insert_seed("lms-issuer-1", [2u8; 32]).unwrap();
    let event = SorEvent {
        event_id: event_id.into(),
        tenant_id: "default".into(),
        system: "lms".into(),
        event_type: "loan.dpd30".into(),
        record_ref: record_ref.into(),
        subject_ref: SUBJECT.into(),
        principal: "nbfc-collections-system".into(),
        consent_refs: set(&["C-7f3a"]),
        assigned_agent: "collections-agent".into(),
        occurred_at: chrono::Utc::now(),
        nonce: format!("n-{event_id}-{record_ref}"),
    };
    kavach_mandate::jws::sign(
        &sor,
        "lms-issuer-1",
        kavach_mandate::jws::TYP_SOR_EVENT,
        &event,
    )
    .await
    .unwrap()
}

async fn send(
    app: axum::Router,
    uri: &str,
    headers: &[(&str, String)],
    body: Value,
) -> (StatusCode, Value) {
    let mut req = Request::post(uri).header("content-type", "application/json");
    for (k, v) in headers {
        req = req.header(*k, v);
    }
    let response = app
        .oneshot(req.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn issue(state: &Arc<AppState>, event_id: &str) -> String {
    let (status, body) = send(
        sor_router(state.clone()),
        "/v1/sor/events",
        &[],
        json!({ "event": event(event_id, "lms:loan/L-1").await }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    body["mandate_id"].as_str().unwrap().to_string()
}

fn read_fields(mandate_id: &str, request_id: &str) -> Value {
    json!({
        "mandate_id": mandate_id,
        "action": "read_fields",
        "request_id": request_id,
        "subject_ref": SUBJECT,
        "requested_fields": ["name", "overdue_amount"]
    })
}

#[tokio::test]
async fn sor_events_issue_once_and_retries_are_idempotent() {
    let s = state(50).await;
    let token = event("evt-1", "lms:loan/L-1").await;
    let post = |token: String| {
        send(
            sor_router(s.clone()),
            "/v1/sor/events",
            &[],
            json!({ "event": token }),
        )
    };
    let (status, first) = post(token.clone()).await;
    assert_eq!(status, StatusCode::CREATED, "{first}");
    assert_eq!(first["replayed"], false);

    // The LMS retries the same event: the existing mandate, not an error.
    let (status, again) = post(token).await;
    assert_eq!(status, StatusCode::OK, "{again}");
    assert_eq!(
        (again["mandate_id"].clone(), again["replayed"].clone()),
        (first["mandate_id"].clone(), json!(true))
    );

    // The same event id with other content is a conflict.
    let (status, body) = post(event("evt-1", "lms:loan/L-2").await).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");

    // A tampered event (signature no longer matches) is refused.
    let tampered = event("evt-2", "lms:loan/L-3").await;
    let (head, sig) = tampered.rsplit_once('.').unwrap();
    let flipped = if sig.starts_with('A') { "B" } else { "A" };
    let (status, body) = post(format!("{head}.{flipped}{}", &sig[1..])).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

    // Oversized bodies are refused before parsing.
    let huge = json!({ "event": "x".repeat(kavach_api::dataplane::SOR_BODY_LIMIT + 1) });
    let (status, _) = send(sor_router(s.clone()), "/v1/sor/events", &[], huge).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn sor_events_are_rate_limited() {
    let s = state(2).await;
    let mut statuses = Vec::new();
    for i in 0..4 {
        let (status, _) = send(
            sor_router(s.clone()),
            "/v1/sor/events",
            &[],
            json!({ "event": event(&format!("rl-{i}"), "lms:loan/L-1").await }),
        )
        .await;
        statuses.push(status);
    }
    assert!(
        statuses.contains(&StatusCode::TOO_MANY_REQUESTS),
        "{statuses:?}"
    );
}

#[tokio::test]
async fn authorize_is_an_agent_only_precheck() {
    let s = state(50).await;
    let mandate = issue(&s, "evt-a").await;
    let bearer = |t: String| ("authorization", format!("Bearer {t}"));

    let (status, body) = send(
        agent_router(s.clone()),
        "/v1/authorize",
        &[bearer(agent_token("collections-agent"))],
        read_fields(&mandate, "q-1"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["decision"], "PASS", "{body}");
    assert_eq!(body["precheck"], true);
    let dp = s.dataplane().unwrap();
    assert!(
        dp.core()
            .store()
            .records("default", 0)
            .await
            .unwrap()
            .is_empty(),
        "nothing recorded"
    );
    assert_eq!(dp.core().prechecks(), 1);

    // Another agent's token on the holder's mandate: a decision, BLOCK.
    // (No passport at all: refused before deciding.)
    let (status, _) = send(
        agent_router(s.clone()),
        "/v1/authorize",
        &[bearer(agent_token("rogue-agent"))],
        read_fields(&mandate, "q-2"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Unknown mandate: BLOCK-shaped, not an error.
    let (status, body) = send(
        agent_router(s.clone()),
        "/v1/authorize",
        &[bearer(agent_token("collections-agent"))],
        read_fields("no-such-mandate", "q-3"),
    )
    .await;
    assert_eq!(
        (status, body["decision"].clone()),
        (StatusCode::OK, json!("BLOCK"))
    );
}

#[tokio::test]
async fn operator_and_agent_credentials_do_not_cross() {
    let s = state(50).await;
    let mandate = issue(&s, "evt-x").await;
    let bearer = |t: String| ("authorization", format!("Bearer {t}"));
    let authorize = |headers: Vec<(&'static str, String)>| {
        let s = s.clone();
        let body = read_fields(&mandate, "x-1");
        async move {
            send(agent_router(s), "/v1/authorize", &headers, body)
                .await
                .0
        }
    };
    assert_eq!(authorize(vec![]).await, StatusCode::UNAUTHORIZED);
    assert_eq!(
        authorize(vec![bearer(operator_token())]).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        authorize(vec![("x-kavach-principal", "collections-agent".into())]).await,
        StatusCode::UNAUTHORIZED,
        "the operator header is never accepted on agent surfaces, even in --insecure-dev"
    );

    // An agent token is not an operator credential.
    let runtime = |t: String| {
        let s = s.clone();
        async move {
            router(s)
                .oneshot(
                    Request::get("/v1/runtime")
                        .header("authorization", format!("Bearer {t}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
                .status()
        }
    };
    assert_eq!(
        runtime(agent_token("collections-agent")).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(runtime(operator_token()).await, StatusCode::OK);
}

#[tokio::test]
async fn startup_refuses_unsafe_agent_configurations() {
    // Memory stores without --insecure-dev.
    let err = AppState::from_config(&config(EvidenceStoreKind::Memory, false, 50))
        .await
        .err()
        .expect("refused");
    let message = format!("{err:?}");
    assert!(
        message.contains("Postgres") || message.contains("clock"),
        "{message}"
    );
    // One audience for operators and agents.
    let mut same = config(EvidenceStoreKind::Memory, true, 50);
    same.dataplane.as_mut().unwrap().agent_oidc.audience = "kavach-api".into();
    let err = AppState::from_config(&same).await.err().expect("refused");
    assert!(format!("{err:?}").contains("audience"), "{err:?}");
}

/// Postgres, no development stand-ins (kernel clock), as in production.
#[tokio::test(flavor = "multi_thread")]
async fn agent_surfaces_on_postgres() {
    let Some((owner, runtime)) = kavach_storage::testing::isolated_database_urls().await else {
        return;
    };
    let mut config = config(
        EvidenceStoreKind::Postgres {
            database_url: runtime,
        },
        false,
        50,
    );
    config.migration_database_url = Some(owner);
    let s = Arc::new(
        AppState::from_config(&config)
            .await
            .expect("production-shaped start"),
    );
    let mandate = issue(&s, "evt-pg").await;
    let (status, body) = send(
        agent_router(s.clone()),
        "/v1/authorize",
        &[(
            "authorization",
            format!("Bearer {}", agent_token("collections-agent")),
        )],
        read_fields(&mandate, "pg-1"),
    )
    .await;
    assert_eq!(
        (status, body["decision"].clone()),
        (StatusCode::OK, json!("PASS")),
        "{body}"
    );
}

/// The agent listener serves agent routes only; the operator listener does
/// not serve agent routes (ADR-007).
#[tokio::test]
async fn agent_and_operator_listeners_are_separate() {
    let s = state(50).await;
    let status = |app: axum::Router, method: &'static str, uri: &'static str| async move {
        app.oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
    };
    for (method, uri) in [
        ("GET", "/v1/runtime"),
        ("GET", "/metrics"),
        ("GET", "/v1/admin/audit"),
        ("GET", "/v1/change-requests"),
        ("POST", "/v1/change-requests"),
        ("POST", "/v1/sor/events"),
        ("POST", "/v1/evaluate"),
    ] {
        assert_eq!(
            status(agent_router(s.clone()), method, uri).await,
            StatusCode::NOT_FOUND,
            "{method} {uri} must not be served to agents"
        );
    }
    assert_eq!(
        status(agent_router(s.clone()), "GET", "/health").await,
        StatusCode::OK
    );
    assert_eq!(
        status(router(s.clone()), "POST", "/v1/authorize").await,
        StatusCode::NOT_FOUND,
        "the operator listener does not serve agent routes"
    );
}

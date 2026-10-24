//! H2a: API principals come from verified OIDC JWT access tokens; the
//! self-asserted header is refused unless `--insecure-dev`.

use contract::router;
use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::SigningKey;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use kavach_api::{
    AccessControlKind, ApiConfig, AppState, EvidenceStoreKind, JwksSource, OidcConfig,
};
use serde_json::{json, Value};
use tower::ServiceExt;

mod common;
mod contract;

const ISSUER: &str = "https://idp.test/realms/kavach";
const AUDIENCE: &str = "kavach-api";
const KID: &str = "test-key-1";
const SEED: [u8; 32] = [42u8; 32];

fn repo(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

/// PKCS#8 v1 DER for an Ed25519 private key (RFC 8410).
fn pkcs8(seed: &[u8; 32]) -> Vec<u8> {
    let mut der = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    der.extend_from_slice(seed);
    der
}

fn jwks_json() -> Value {
    let public = SigningKey::from_bytes(&SEED).verifying_key().to_bytes();
    json!({ "keys": [{
        "kty": "OKP", "crv": "Ed25519", "x": URL_SAFE_NO_PAD.encode(public),
        "kid": KID, "alg": "EdDSA", "use": "sig"
    }]})
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn claims(sub: &str, groups: &[&str]) -> Value {
    json!({ "iss": ISSUER, "aud": AUDIENCE, "sub": sub, "groups": groups,
            "iat": now(), "nbf": now() - 5, "exp": now() + 300 })
}

fn token_with(claims: &Value, kid: &str) -> String {
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(kid.into());
    encode(&header, claims, &EncodingKey::from_ed_der(&pkcs8(&SEED))).unwrap()
}

fn token(sub: &str, groups: &[&str]) -> String {
    token_with(&claims(sub, groups), KID)
}

async fn state() -> Arc<AppState> {
    state_with(false).await
}

async fn state_with(insecure_dev: bool) -> Arc<AppState> {
    let dir = std::env::temp_dir().join(format!("kavach-oidc-{}-{}", std::process::id(), now()));
    std::fs::create_dir_all(&dir).unwrap();
    let jwks = dir.join(format!("jwks-{}.json", rand_suffix()));
    std::fs::write(&jwks, jwks_json().to_string()).unwrap();
    let config = ApiConfig {
        pack_path: repo("packs/finance/v0.yaml"),
        model_path: repo("models/finance/credit-underwriting-v1.yaml"),
        hmac_secret: None,
        evidence_store: EvidenceStoreKind::Memory,
        access_control: AccessControlKind::Cedar {
            policy_path: repo("crates/kavach-auth/policies/kavach.cedar"),
            entities_path: repo("crates/kavach-auth/policies/entities.example.json"),
        },
        tls: None,
        pack_sha256: None,
        bootstrap_pack: false,
        bootstrap_model: false,
        pack_signers: None,
        oidc: Some(OidcConfig {
            issuer: ISSUER.into(),
            audience: AUDIENCE.into(),
            jwks: JwksSource::File(jwks),
            principal_claim: "sub".into(),
            groups_claim: "groups".into(),
            leeway_seconds: 30,
        }),
        insecure_dev,
        mtls_principal_san: None,
        change_ttl_seconds: 3600,
        migration_database_url: None,
        database_tls: kavach_api::DatabaseTls::development(),
        database_pool_size: kavach_api::DEFAULT_POOL_SIZE,
        dataplane: None,
    };
    Arc::new(AppState::from_config(&config).await.expect("state"))
}

fn rand_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

async fn get(state: &Arc<AppState>, uri: &str, headers: &[(&str, String)]) -> StatusCode {
    let mut req = Request::builder().uri(uri);
    for (k, v) in headers {
        req = req.header(*k, v);
    }
    router(state.clone())
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap()
        .status()
}

fn bearer(t: &str) -> (&'static str, String) {
    ("authorization", format!("Bearer {t}"))
}

#[tokio::test]
async fn valid_token_with_group_is_authorized() {
    let s = state().await;
    let t = token("sso-user-7", &["viewers"]);
    assert_eq!(get(&s, "/v1/runtime", &[bearer(&t)]).await, StatusCode::OK);
}

#[tokio::test]
async fn token_without_granting_group_is_forbidden() {
    let s = state().await;
    let t = token("sso-user-7", &["unrelated"]);
    assert_eq!(
        get(&s, "/v1/runtime", &[bearer(&t)]).await,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn self_asserted_header_is_refused_without_insecure_dev() {
    let s = state().await;
    assert_eq!(
        get(
            &s,
            "/v1/runtime",
            &[("x-kavach-principal", "admin-1".into())]
        )
        .await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(get(&s, "/v1/runtime", &[]).await, StatusCode::UNAUTHORIZED);
    // Token and header together are ambiguous.
    let t = token("sso-user-7", &["viewers"]);
    assert_eq!(
        get(
            &s,
            "/v1/runtime",
            &[bearer(&t), ("x-kavach-principal", "admin-1".into())]
        )
        .await,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn invalid_tokens_are_rejected() {
    let s = state().await;
    let mut wrong_iss = claims("u", &["viewers"]);
    wrong_iss["iss"] = json!("https://evil.example");
    let mut wrong_aud = claims("u", &["viewers"]);
    wrong_aud["aud"] = json!("someone-else");
    let mut expired = claims("u", &["viewers"]);
    expired["exp"] = json!(now() - 3600);
    let mut future = claims("u", &["viewers"]);
    future["nbf"] = json!(now() + 3600);
    let mut no_sub = claims("u", &["viewers"]);
    no_sub.as_object_mut().unwrap().remove("sub");
    let mut bad_groups = claims("u", &["viewers"]);
    bad_groups["groups"] = json!("viewers");

    let mut hs256 = Header::new(Algorithm::HS256);
    hs256.kid = Some(KID.into());
    let hmac_token = encode(
        &hs256,
        &claims("u", &["viewers"]),
        &EncodingKey::from_secret(b"k"),
    )
    .unwrap();

    let valid = token("u", &["viewers"]);
    let mut parts: Vec<String> = valid.split('.').map(String::from).collect();
    parts[1] = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims("admin-1", &["admins"])).unwrap());
    let tampered = parts.join(".");
    let none_alg = format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims("u", &["viewers"])).unwrap())
    );

    for (label, t) in [
        ("wrong issuer", token_with(&wrong_iss, KID)),
        ("wrong audience", token_with(&wrong_aud, KID)),
        ("expired", token_with(&expired, KID)),
        ("not yet valid", token_with(&future, KID)),
        (
            "unknown kid",
            token_with(&claims("u", &["viewers"]), "other-key"),
        ),
        ("missing sub", token_with(&no_sub, KID)),
        ("groups not array", token_with(&bad_groups, KID)),
        ("HS256", hmac_token),
        ("tampered payload", tampered),
        ("alg none", none_alg),
        ("not a jwt", "abc".into()),
    ] {
        assert_eq!(
            get(&s, "/v1/runtime", &[bearer(&t)]).await,
            StatusCode::UNAUTHORIZED,
            "{label}"
        );
    }
    // Wrong scheme.
    assert_eq!(
        get(
            &s,
            "/v1/runtime",
            &[("authorization", format!("Basic {valid}"))]
        )
        .await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn change_requests_use_token_identities() {
    let s = state().await;
    let app = router(s.clone());
    let admin = vec![bearer(&token("sso-admin-1", &["admins"]))];
    let params = json!({ "evidence_retention_days": 30 });

    let (status, request) = common::propose(&app, &admin, "update_retention", params.clone()).await;
    assert_eq!(status, StatusCode::CREATED, "{request}");
    assert_eq!(request["proposer"], "sso-admin-1");
    assert_eq!(
        request["proposer_key"],
        format!("oidc:{ISSUER}#sso-admin-1")
    );

    // Header principals are refused without --insecure-dev.
    let (status, _) = common::propose(
        &app,
        &common::as_principal("admin-1"),
        "update_retention",
        params,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // The proposer cannot approve; an admin without the approver group
    // cannot either (separation of duties).
    assert_eq!(
        common::approve(&app, &admin, &request).await.0,
        StatusCode::FORBIDDEN
    );
    let other_admin = vec![bearer(&token("sso-admin-2", &["admins"]))];
    assert_eq!(
        common::approve(&app, &other_admin, &request).await.0,
        StatusCode::FORBIDDEN
    );

    let approver = vec![bearer(&token("sso-approver", &["change-approvers"]))];
    let (status, applied) = common::approve(&app, &approver, &request).await;
    assert_eq!(status, StatusCode::OK, "{applied}");
    assert_eq!(applied["decided_by"], "sso-approver");
}

#[test]
fn cedar_without_an_authenticated_source_is_refused() {
    let cedar = AccessControlKind::Cedar {
        policy_path: "p".into(),
        entities_path: "e".into(),
    };
    let mut config = ApiConfig {
        pack_path: "p".into(),
        model_path: "m".into(),
        hmac_secret: None,
        evidence_store: EvidenceStoreKind::Memory,
        access_control: cedar,
        tls: None,
        pack_sha256: None,
        bootstrap_pack: false,
        bootstrap_model: false,
        pack_signers: None,
        oidc: None,
        insecure_dev: false,
        mtls_principal_san: None,
        change_ttl_seconds: 3600,
        migration_database_url: None,
        database_tls: kavach_api::DatabaseTls::development(),
        database_pool_size: kavach_api::DEFAULT_POOL_SIZE,
        dataplane: None,
    };
    assert!(kavach_api::validate_principal_sources(&config).is_err());
    config.insecure_dev = true;
    assert!(kavach_api::validate_principal_sources(&config).is_ok());
    config.insecure_dev = false;
    config.oidc = Some(OidcConfig {
        issuer: ISSUER.into(),
        audience: AUDIENCE.into(),
        jwks: JwksSource::File("jwks.json".into()),
        principal_claim: "sub".into(),
        groups_claim: "groups".into(),
        leeway_seconds: 30,
    });
    assert!(kavach_api::validate_principal_sources(&config).is_ok());
}

/// The body of a GET as JSON.
async fn get_json(state: &Arc<AppState>, uri: &str, headers: &[(&str, String)]) -> Value {
    let mut req = Request::builder().uri(uri);
    for (k, v) in headers {
        req = req.header(*k, v);
    }
    let response = router(state.clone())
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// The value of one series in the metrics text.
fn series(state: &Arc<AppState>, name: &str) -> i64 {
    let text = state.metrics().gather_text().unwrap();
    text.lines()
        .find_map(|l| l.strip_prefix(name)?.strip_prefix(' ')?.trim().parse().ok())
        .unwrap_or_else(|| panic!("no series {name} in the metrics"))
}

fn relaxation(state: &Arc<AppState>, name: &str) -> i64 {
    series(
        state,
        &format!("kavach_relaxation_active{{relaxation=\"{name}\"}}"),
    )
}

/// Production mode (OIDC, Cedar, no `--insecure-dev`): nothing is relaxed, and
/// the process says so in `/v1/runtime` and in every relaxation series.
#[tokio::test]
async fn a_production_start_shows_no_relaxation() {
    let s = state().await;
    let t = token("sso-user-7", &["viewers"]);
    let runtime = get_json(&s, "/v1/runtime", &[bearer(&t)]).await;
    assert_eq!(runtime["insecure_dev"], false, "{runtime}");
    assert_eq!(runtime["relaxations"], json!([]), "{runtime}");
    assert_eq!(series(&s, "kavach_insecure_dev"), 0);
    for name in kavach_api::relaxations::Relaxation::ALL {
        assert_eq!(relaxation(&s, name.as_str()), 0, "{}", name.as_str());
    }
}

/// `--insecure-dev` with access control on: the header principal is accepted,
/// and the process says that, and only that.
#[tokio::test]
async fn insecure_dev_shows_in_runtime_and_metrics() {
    let s = state_with(true).await;
    let runtime = get_json(
        &s,
        "/v1/runtime",
        &[("x-kavach-principal", "viewer-1".into())],
    )
    .await;
    assert_eq!(runtime["insecure_dev"], true, "{runtime}");
    assert_eq!(
        runtime["relaxations"],
        json!(["insecure_dev", "principal_header"]),
        "{runtime}"
    );
    assert_eq!(series(&s, "kavach_insecure_dev"), 1);
    for (name, expected) in [
        ("insecure_dev", 1),
        ("principal_header", 1),
        ("access_control_none", 0),
    ] {
        assert_eq!(relaxation(&s, name), expected, "{name}");
    }
}

/// `--insecure-dev` with access control off: every request is allowed.
#[tokio::test]
async fn access_control_off_shows_too() {
    let s = Arc::new(
        AppState::from_paths_for_tests(
            &repo("packs/finance/v0.yaml"),
            &repo("models/finance/credit-underwriting-v1.yaml"),
            None,
        )
        .await
        .expect("state"),
    );
    let runtime = get_json(&s, "/v1/runtime", &[]).await;
    assert_eq!(
        runtime["relaxations"],
        json!(["insecure_dev", "access_control_none", "principal_header"]),
        "{runtime}"
    );
    assert_eq!(relaxation(&s, "access_control_none"), 1);
}

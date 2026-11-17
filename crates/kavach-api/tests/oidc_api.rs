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
    state_with_roles(insecure_dev, kavach_api::RolesConfig::default()).await
}

async fn state_with_roles(insecure_dev: bool, roles: kavach_api::RolesConfig) -> Arc<AppState> {
    let dir = std::env::temp_dir().join(format!("kavach-oidc-{}-{}", std::process::id(), now()));
    std::fs::create_dir_all(&dir).unwrap();
    let jwks = dir.join(format!("jwks-{}.json", rand_suffix()));
    std::fs::write(&jwks, jwks_json().to_string()).unwrap();
    let config = ApiConfig {
        require_hardening: false,
        review_snapshot_key_file: None,
        review_snapshot_previous_keys: Vec::new(),
        review_snapshot_key_id: kavach_api::config::DEFAULT_REVIEW_SNAPSHOT_KEY_ID.into(),
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
        roles,
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
        require_hardening: false,
        review_snapshot_key_file: None,
        review_snapshot_previous_keys: Vec::new(),
        review_snapshot_key_id: kavach_api::config::DEFAULT_REVIEW_SNAPSHOT_KEY_ID.into(),
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
        roles: kavach_api::RolesConfig::default(),
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
/// the process says so in `/v1/runtime` and in every relaxation series. These
/// tests build on the in-memory evidence store, so `memory_evidence_store` is
/// the one relaxation that is (truthfully) reported.
#[tokio::test]
async fn a_production_start_shows_no_relaxation() {
    let s = state().await;
    let t = token("sso-user-7", &["viewers"]);
    let runtime = get_json(&s, "/v1/runtime", &[bearer(&t)]).await;
    assert_eq!(runtime["insecure_dev"], false, "{runtime}");
    assert_eq!(
        runtime["relaxations"],
        json!(["memory_evidence_store"]),
        "{runtime}"
    );
    assert_eq!(series(&s, "kavach_insecure_dev"), 0);
    for name in kavach_api::relaxations::Relaxation::ALL {
        let expected = i64::from(name.as_str() == "memory_evidence_store");
        assert_eq!(relaxation(&s, name.as_str()), expected, "{}", name.as_str());
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
        json!(["insecure_dev", "principal_header", "memory_evidence_store"]),
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
        json!([
            "insecure_dev",
            "access_control_none",
            "principal_header",
            "memory_evidence_store"
        ]),
        "{runtime}"
    );
    assert_eq!(relaxation(&s, "access_control_none"), 1);
}

// ---- ADR-019: bound roles decide; superadmin-only decisions are flagged ----

/// A stack whose two bootstrap superadmins are the OIDC subjects `subs`.
async fn with_superadmins(subs: [&str; 2]) -> Arc<AppState> {
    let people = subs
        .iter()
        .map(|sub| kavach_storage::BindingSubject {
            kind: kavach_storage::SubjectKind::Principal,
            issuer: ISSUER.into(),
            value: (*sub).into(),
        })
        .collect();
    state_with_roles(
        false,
        kavach_api::RolesConfig {
            bootstrap_superadmins: people,
            ..kavach_api::RolesConfig::default()
        },
    )
    .await
}

#[tokio::test]
async fn a_role_bound_to_the_person_decides_without_any_group() {
    let s = with_superadmins(["root-a", "root-b"]).await;
    assert_eq!(
        get(&s, "/v1/runtime", &[bearer(&token("root-a", &[]))]).await,
        StatusCode::OK
    );
    assert_eq!(
        get(&s, "/v1/runtime", &[bearer(&token("nobody", &[]))]).await,
        StatusCode::FORBIDDEN
    );
    // A token group named like a role is only a group.
    assert_eq!(
        get(
            &s,
            "/v1/runtime",
            &[bearer(&token("nobody", &["superadmin"]))]
        )
        .await,
        StatusCode::FORBIDDEN
    );
}

/// The flag on the audit row of `action` about change request `id`.
async fn flag(s: &AppState, action: &str, id: &str) -> bool {
    let entries = s.admin().list_audit(200).await.unwrap();
    let entry = entries
        .iter()
        .find(|e| {
            e.action == action
                && (e.resource_id == id || e.payload["change_request_id"] == json!(id))
        })
        .unwrap_or_else(|| panic!("no {action} row for {id}"));
    entry.acting_as_superadmin
}

#[tokio::test]
async fn only_a_decision_no_other_policy_allows_is_flagged_superadmin() {
    let s = with_superadmins(["root-a", "root-b"]).await;
    let app = router(s.clone());
    let root_a = vec![bearer(&token("root-a", &[]))];
    let root_b_approver = vec![bearer(&token("root-b", &["change-approvers"]))];

    // Proposed on the superadmin role alone: flagged. Approved by someone the
    // change-approvers group also allows: not flagged.
    let params = json!({ "evidence_retention_days": 30 });
    let (status, request) = common::propose(&app, &root_a, "update_retention", params).await;
    assert_eq!(status, StatusCode::CREATED, "{request}");
    let id = request["id"].as_str().unwrap();
    assert!(flag(&s, "change_request_proposed", id).await);
    let (status, applied) = common::approve(&app, &root_b_approver, &request).await;
    assert_eq!(status, StatusCode::OK, "{applied}");
    assert!(!flag(&s, "update_retention", id).await);

    // And the other way round.
    let admin = vec![bearer(&token("sso-admin-1", &["admins"]))];
    let params = json!({ "evidence_retention_days": 31 });
    let (status, request) = common::propose(&app, &admin, "update_retention", params).await;
    assert_eq!(status, StatusCode::CREATED, "{request}");
    let id = request["id"].as_str().unwrap();
    assert!(!flag(&s, "change_request_proposed", id).await);
    let (status, applied) = common::approve(&app, &root_a, &request).await;
    assert_eq!(status, StatusCode::OK, "{applied}");
    assert!(flag(&s, "update_retention", id).await);
}

// ---- ADR-019 §4: roles change only through approved change requests ----

fn person_subject(sub: &str) -> Value {
    json!({ "kind": "principal", "issuer": ISSUER, "value": sub })
}

fn grant_params(role: &str, subject: Value) -> Value {
    let mut params = json!({ "role": role });
    params["subject"] = subject;
    params
}

/// The active binding of `role` held by person `sub`.
async fn binding_of(s: &AppState, role: &str, sub: &str) -> Option<String> {
    s.roles()
        .list_bindings(s.tenant_id(), false)
        .await
        .unwrap()
        .into_iter()
        .find(|b| b.role.as_str() == role && b.subject.value == sub)
        .map(|b| b.id)
}

async fn status_of(app: &axum::Router, creds: &common::Creds, request: &Value) -> Value {
    let id = request["id"].as_str().unwrap();
    let (status, body) = common::call(
        app,
        "GET",
        &format!("/v1/change-requests/{id}"),
        creds,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["status"].clone()
}

#[tokio::test]
async fn a_granted_role_decides_only_after_a_second_person_approves() {
    let s = with_superadmins(["root-a", "root-b"]).await;
    let app = router(s.clone());
    let root_a = vec![bearer(&token("root-a", &[]))];
    let root_b = vec![bearer(&token("root-b", &[]))];
    let op = [bearer(&token("op-1", &[]))];

    let (status, request) = common::propose(
        &app,
        &root_a,
        "grant_role",
        grant_params("operator", person_subject("op-1")),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{request}");
    assert_eq!(get(&s, "/v1/runtime", &op).await, StatusCode::FORBIDDEN);
    assert_eq!(binding_of(&s, "operator", "op-1").await, None);
    // The proposer cannot approve their own grant.
    assert_eq!(
        common::approve(&app, &root_a, &request).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(get(&s, "/v1/runtime", &op).await, StatusCode::FORBIDDEN);

    let (status, applied) = common::approve(&app, &root_b, &request).await;
    assert_eq!(status, StatusCode::OK, "{applied}");
    assert_eq!(applied["outcome"]["role"], "operator");
    assert_eq!(
        applied["outcome"]["binding_id"].as_str(),
        binding_of(&s, "operator", "op-1").await.as_deref()
    );
    assert_eq!(get(&s, "/v1/runtime", &op).await, StatusCode::OK);

    // The same grant again is a conflict at proposal.
    let (status, body) = common::propose(
        &app,
        &root_a,
        "grant_role",
        grant_params("operator", person_subject("op-1")),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");

    // A revoke stops the role on the next request, again only once approved.
    let binding = binding_of(&s, "operator", "op-1").await.unwrap();
    let (status, request) = common::propose(
        &app,
        &root_b,
        "revoke_role",
        json!({ "binding_id": binding }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{request}");
    assert_eq!(get(&s, "/v1/runtime", &op).await, StatusCode::OK);
    let (status, applied) = common::approve(&app, &root_a, &request).await;
    assert_eq!(status, StatusCode::OK, "{applied}");
    assert_eq!(applied["outcome"]["ended"], true);
    assert_eq!(get(&s, "/v1/runtime", &op).await, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_user_admin_cannot_grant_approve_or_revoke_superadmin() {
    let s = with_superadmins(["root-a", "root-b"]).await;
    let app = router(s.clone());
    let root_a = vec![bearer(&token("root-a", &[]))];
    let root_b = vec![bearer(&token("root-b", &[]))];
    for who in ["ua-1", "ua-2"] {
        assert_eq!(
            common::apply_change(
                &app,
                "grant_role",
                grant_params("user_admin", person_subject(who)),
                &root_a,
                &root_b,
            )
            .await,
            StatusCode::OK
        );
    }
    let ua_1 = vec![bearer(&token("ua-1", &[]))];
    let ua_2 = vec![bearer(&token("ua-2", &[]))];

    // Proposing superadmin: refused.
    let (status, body) = common::propose(
        &app,
        &ua_1,
        "grant_role",
        grant_params("superadmin", person_subject("someone")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    // Approving a superadmin grant a superadmin proposed: refused, and the
    // request stays pending for a superadmin.
    let (status, request) = common::propose(
        &app,
        &root_a,
        "grant_role",
        grant_params("superadmin", person_subject("root-c")),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{request}");
    assert_eq!(
        common::approve(&app, &ua_1, &request).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(status_of(&app, &root_a, &request).await, "pending");
    // Revoking a superadmin: refused.
    let root_b_binding = binding_of(&s, "superadmin", "root-b").await.unwrap();
    let (status, body) = common::propose(
        &app,
        &ua_1,
        "revoke_role",
        json!({ "binding_id": root_b_binding }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // Any other role: allowed, with a second user admin approving.
    assert_eq!(
        common::apply_change(
            &app,
            "grant_role",
            grant_params("approver", person_subject("ap-1")),
            &ua_1,
            &ua_2,
        )
        .await,
        StatusCode::OK
    );
    // The superadmin request is still approvable by a superadmin.
    let (status, applied) = common::approve(&app, &root_b, &request).await;
    assert_eq!(status, StatusCode::OK, "{applied}");
}

#[tokio::test]
async fn nobody_grants_a_role_to_themselves_or_their_group() {
    let s = with_superadmins(["root-a", "root-b"]).await;
    let app = router(s.clone());
    let root_a = vec![bearer(&token("root-a", &["ops"]))];
    let root_b = vec![bearer(&token("root-b", &[]))];

    // The proposer, by person and by a group in their token.
    let (status, body) = common::propose(
        &app,
        &root_a,
        "grant_role",
        grant_params("operator", person_subject("root-a")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let group = json!({ "kind": "group", "issuer": ISSUER, "value": "ops" });
    let (status, body) =
        common::propose(&app, &root_a, "grant_role", grant_params("operator", group)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // The approver: refused, and the request stays pending for someone else.
    let (status, request) = common::propose(
        &app,
        &root_a,
        "grant_role",
        grant_params("auditor", person_subject("root-b")),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{request}");
    let (status, body) = common::approve(&app, &root_b, &request).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(status_of(&app, &root_a, &request).await, "pending");
    assert_eq!(binding_of(&s, "auditor", "root-b").await, None);

    // A subject from another issuer, or with control characters, is refused.
    let foreign = json!({ "kind": "principal", "issuer": "https://evil.test", "value": "x" });
    let (status, body) = common::propose(
        &app,
        &root_a,
        "grant_role",
        grant_params("operator", foreign),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let (status, body) = common::propose(
        &app,
        &root_a,
        "grant_role",
        grant_params("operator", person_subject("a\u{7}b")),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

#[tokio::test]
async fn the_last_person_superadmin_cannot_be_revoked() {
    let s = with_superadmins(["root-a", "root-b"]).await;
    let app = router(s.clone());
    let root_a = vec![bearer(&token("root-a", &[]))];
    let root_b = vec![bearer(&token("root-b", &[]))];
    let a = binding_of(&s, "superadmin", "root-a").await.unwrap();
    let b = binding_of(&s, "superadmin", "root-b").await.unwrap();

    // Two pending revokes, one for each: the second to be approved fails.
    let (status, first) =
        common::propose(&app, &root_a, "revoke_role", json!({ "binding_id": b })).await;
    assert_eq!(status, StatusCode::CREATED, "{first}");
    let (status, second) =
        common::propose(&app, &root_b, "revoke_role", json!({ "binding_id": a })).await;
    assert_eq!(status, StatusCode::CREATED, "{second}");
    let (status, applied) = common::approve(&app, &root_b, &first).await;
    assert_eq!(status, StatusCode::OK, "{applied}");
    let (status, body) = common::approve(&app, &root_a, &second).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(
        binding_of(&s, "superadmin", "root-a").await,
        Some(a.clone())
    );

    // And a new revoke of the last one is refused at proposal.
    let (status, body) =
        common::propose(&app, &root_a, "revoke_role", json!({ "binding_id": a })).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    // An unknown binding is not found, for someone allowed to revoke.
    let (status, _) = common::propose(
        &app,
        &root_a,
        "revoke_role",
        json!({ "binding_id": "rb_missing" }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // And for someone who is not, the answer does not say whether it exists.
    let nobody = vec![bearer(&token("nobody", &[]))];
    let (status, _) =
        common::propose(&app, &nobody, "revoke_role", json!({ "binding_id": a })).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = common::propose(
        &app,
        &nobody,
        "revoke_role",
        json!({ "binding_id": "rb_missing" }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

// ---- ADR-019 §8 and §9: the directory, the bindings, the access review ----

const ROLES: [&str; 7] = [
    "superadmin",
    "user_admin",
    "policy_admin",
    "approver",
    "operator",
    "auditor",
    "viewer",
];

/// Grants `role` to `subject`: proposed by root-a, approved by root-b.
/// Returns the change request.
async fn grant(app: &axum::Router, role: &str, subject: Value) -> Value {
    let root_a = vec![bearer(&token("root-a", &[]))];
    let root_b = vec![bearer(&token("root-b", &[]))];
    let (status, request) =
        common::propose(app, &root_a, "grant_role", grant_params(role, subject)).await;
    assert_eq!(status, StatusCode::CREATED, "{request}");
    let (status, applied) = common::approve(app, &root_b, &request).await;
    assert_eq!(status, StatusCode::OK, "{applied}");
    request
}

const ROLE_READS: [&str; 4] = [
    "/v1/principals",
    "/v1/role-bindings",
    "/v1/access-review",
    "/v1/access-review?format=csv",
];

#[tokio::test]
async fn only_superadmin_user_admin_and_auditor_read_the_directory_and_the_review() {
    let s = with_superadmins(["root-a", "root-b"]).await;
    let app = router(s.clone());
    for role in &ROLES[1..] {
        grant(&app, role, person_subject(&format!("{role}-1"))).await;
    }
    for role in ROLES {
        let who = if role == "superadmin" {
            "root-a".to_string()
        } else {
            format!("{role}-1")
        };
        let creds = vec![bearer(&token(&who, &[]))];
        let want = if matches!(role, "superadmin" | "user_admin" | "auditor") {
            StatusCode::OK
        } else {
            StatusCode::FORBIDDEN
        };
        for uri in ROLE_READS {
            let (status, _) = common::call(&app, "GET", uri, &creds, None).await;
            assert_eq!(status, want, "{role} {uri}");
        }
        let (status, me) = common::call(&app, "GET", "/v1/me", &creds, None).await;
        assert_eq!(status, StatusCode::OK, "{me}");
        assert_eq!(me, json!({ "principal": who, "roles": [role] }));
    }
    // A group, even an alias group, reads none of them: only roles do.
    let admin = vec![bearer(&token("sso-admin-1", &["admins", "viewers"]))];
    for uri in ROLE_READS {
        let (status, _) = common::call(&app, "GET", uri, &admin, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "admins {uri}");
    }
    let (_, me) = common::call(&app, "GET", "/v1/me", &admin, None).await;
    assert_eq!(me, json!({ "principal": "sso-admin-1", "roles": [] }));
    let (status, _) = common::call(&app, "GET", "/v1/me", &vec![], None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn principals_page_by_issuer_and_subject_and_match_on_name() {
    let s = with_superadmins(["root-a", "root-b"]).await;
    let app = router(s.clone());
    // Any authenticated request puts the person in the directory, even a
    // refused one.
    for who in ["asha-1", "ravi-2", "ASHA-3"] {
        get(&s, "/v1/runtime", &[bearer(&token(who, &[]))]).await;
    }
    let root = vec![bearer(&token("root-a", &[]))];
    let mut seen = Vec::new();
    let mut uri = "/v1/principals?limit=2".to_string();
    loop {
        let (status, page) = common::call(&app, "GET", &uri, &root, None).await;
        assert_eq!(status, StatusCode::OK, "{page}");
        let items = page["items"].as_array().unwrap();
        assert!(items.len() <= 2);
        seen.extend(
            items
                .iter()
                .map(|p| p["subject"].as_str().unwrap().to_string()),
        );
        match page["next_cursor"].as_str() {
            Some(cursor) => uri = format!("/v1/principals?limit=2&cursor={cursor}"),
            None => break,
        }
    }
    // root-b never signed in, so is not in the directory.
    assert_eq!(seen, ["ASHA-3", "asha-1", "ravi-2", "root-a"]);

    let (_, page) = common::call(&app, "GET", "/v1/principals?q=asha", &root, None).await;
    let found: Vec<&str> = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["display_name"].as_str().unwrap())
        .collect();
    assert_eq!(found, ["ASHA-3", "asha-1"]);
    assert_eq!(page["next_cursor"], Value::Null);

    let long = "a".repeat(201);
    for bad in [
        format!("/v1/principals?q={long}"),
        "/v1/principals?q=%01".into(),
        "/v1/principals?cursor=@@".into(),
        "/v1/principals?cursor=bm90IGpzb24".into(),
        "/v1/principals?limit=many".into(),
        "/v1/principals?unknown=1".into(),
    ] {
        let (status, body) = common::call(&app, "GET", &bad, &root, None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}: {body}");
    }
}

#[tokio::test]
async fn ended_role_bindings_are_listed_only_when_asked() {
    let s = with_superadmins(["root-a", "root-b"]).await;
    let app = router(s.clone());
    let root_a = vec![bearer(&token("root-a", &[]))];
    let root_b = vec![bearer(&token("root-b", &[]))];
    let granted = grant(&app, "operator", person_subject("op-1")).await;
    let binding = binding_of(&s, "operator", "op-1").await.unwrap();
    let (status, revoke) = common::propose(
        &app,
        &root_b,
        "revoke_role",
        json!({ "binding_id": binding }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{revoke}");
    assert_eq!(
        common::approve(&app, &root_a, &revoke).await.0,
        StatusCode::OK
    );

    let (_, active) = common::call(&app, "GET", "/v1/role-bindings", &root_a, None).await;
    let active = active["items"].as_array().unwrap();
    assert_eq!(active.len(), 2);
    assert!(active
        .iter()
        .all(|b| b["role"] == "superadmin" && b["granted_by_change_request"].is_null()));

    let (_, all) = common::call(
        &app,
        "GET",
        "/v1/role-bindings?include=ended",
        &root_a,
        None,
    )
    .await;
    let all = all["items"].as_array().unwrap();
    assert_eq!(all.len(), 3);
    let ended = all.iter().find(|b| b["id"] == json!(binding)).unwrap();
    assert_eq!(ended["granted_by_change_request"], granted["id"]);
    assert_eq!(ended["ended_by_change_request"], revoke["id"]);
    assert!(ended["ended_at"].is_string());

    let (status, _) =
        common::call(&app, "GET", "/v1/role-bindings?include=all", &root_a, None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// The status, headers and text of one GET.
async fn get_text(
    app: &axum::Router,
    uri: &str,
    creds: &common::Creds,
) -> (StatusCode, axum::http::HeaderMap, String) {
    let mut req = Request::builder().uri(uri);
    for (k, v) in creds {
        req = req.header(*k, v);
    }
    let response = app
        .clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let (parts, body) = response.into_parts();
    let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
    (
        parts.status,
        parts.headers,
        String::from_utf8(bytes.to_vec()).unwrap(),
    )
}

async fn exports(s: &AppState) -> Vec<kavach_storage::AuditEntry> {
    s.admin()
        .list_audit(200)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.action == kavach_api::roles_api::ACCESS_REVIEW_AUDIT_ACTION)
        .collect()
}

#[tokio::test]
async fn the_access_review_names_who_granted_each_role_and_every_export_is_audited() {
    let s = with_superadmins(["root-a", "root-b"]).await;
    let app = router(s.clone());
    let root_a = vec![bearer(&token("root-a", &[]))];
    // aud-1 never signs in; the group's members are in the IdP.
    let granted = grant(&app, "auditor", person_subject("aud-1")).await;
    let group = json!({ "kind": "group", "issuer": ISSUER, "value": "=cmd|' /C calc'!A0" });
    grant(&app, "viewer", group).await;

    let (status, review) = common::call(&app, "GET", "/v1/access-review", &root_a, None).await;
    assert_eq!(status, StatusCode::OK, "{review}");
    assert_eq!(
        review["alias_groups"],
        json!(["admins", "change-approvers", "operators", "viewers"])
    );
    assert_eq!(review["stale_after_days"], 90);
    let rows = review["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 4, "{review}");
    let row = |subject: &str| rows.iter().find(|r| r["subject"] == subject).unwrap();

    let root = row("root-a");
    assert_eq!(root["proposer"], kavach_storage::BOOTSTRAP_ACTOR);
    assert_eq!(root["approver"], "");
    assert!(root["change_request_id"].is_null());
    assert_eq!(root["stale"], false, "root-a signed in just now");
    assert_eq!(root["display_name"], "root-a");
    assert_eq!(row("root-b")["stale"], false, "root-b approved the grants");

    let auditor = row("aud-1");
    assert_eq!(auditor["role"], "auditor");
    assert_eq!(auditor["proposer"], "root-a");
    assert_eq!(auditor["approver"], "root-b");
    assert_eq!(auditor["change_request_id"], granted["id"]);
    assert_eq!(auditor["stale"], true, "never seen");
    assert!(auditor["last_seen_at"].is_null());
    assert_eq!(auditor["display_name"], "");

    let viewers = row("=cmd|' /C calc'!A0");
    assert_eq!(viewers["subject_kind"], "group");
    assert!(viewers["stale"].is_null());

    let (status, headers, csv) = get_text(&app, "/v1/access-review?format=csv", &root_a).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["content-type"], "text/csv; charset=utf-8");
    assert_eq!(headers["cache-control"], "no-store");
    assert!(headers["content-disposition"]
        .to_str()
        .unwrap()
        .starts_with("attachment;"));
    assert!(csv.contains("admins, change-approvers, operators, viewers"));
    assert!(csv.contains("\"'=cmd|' /C calc'!A0\""), "{csv}");
    assert!(!csv.contains(",\"=cmd"), "{csv}");
    // Four rows after the title, the note, a blank line and the header.
    assert_eq!(csv.split("\r\n").filter(|l| !l.is_empty()).count(), 3 + 4);

    let audited = exports(&s).await;
    assert_eq!(audited.len(), 2);
    let mut formats: Vec<&str> = audited
        .iter()
        .map(|e| e.payload["format"].as_str().unwrap())
        .collect();
    formats.sort_unstable();
    assert_eq!(formats, ["csv", "json"]);
    for entry in &audited {
        assert_eq!(entry.actor_principal, "root-a");
        assert_eq!(entry.resource_id, "default");
        assert_eq!(entry.payload["rows"], 4);
        assert!(
            entry.acting_as_superadmin,
            "only the superadmin role allowed it"
        );
    }

    let (status, _) =
        common::call(&app, "GET", "/v1/access-review?format=xml", &root_a, None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(exports(&s).await.len(), 2, "a refused export is not one");
}

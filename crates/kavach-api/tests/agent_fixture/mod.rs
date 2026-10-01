//! Production-shaped agent-surface fixtures shared by the API tests:
//! keys, a signed tool registry, providers, references, mandates, tokens.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use kavach_api::dataplane::{sor_router, DataplaneConfig};
use kavach_api::{
    AccessControlKind, ApiConfig, AppState, EvidenceStoreKind, JwksSource, OidcConfig,
};
use kavach_credential::DecryptionKey;
use kavach_domain::mandate::{
    AgentPassport, ConsentRecord, ContactWindow, DelegationRules, MandateTemplate, SorEvent,
    TimeZoneId,
};
use kavach_keys::InMemoryKeyProvider;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

pub const ISSUER: &str = "https://idp.test/realms/kavach";
pub const KID: &str = "test-key-1";
pub const IDP_SEED: [u8; 32] = [42u8; 32];
pub const TOOL_SEED: [u8; 32] = [7u8; 32];
pub const SUBJECT: &str = "ref:borrower:B-9382";

pub fn repo(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

pub fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(ToString::to_string).collect()
}

pub fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

pub fn token(audience: &str, claims: Value) -> String {
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

pub fn agent_token(agent: &str) -> String {
    token(
        "kavach-agents",
        json!({ "sub": format!("svc-{agent}"), "azp": agent }),
    )
}

pub fn operator_token() -> String {
    token(
        "kavach-api",
        json!({ "sub": "ops-1", "groups": ["admins"] }),
    )
}

#[cfg(unix)]
pub fn owner_only(path: &Path, contents: &str) {
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
pub fn owner_only(path: &Path, contents: &str) {
    std::fs::write(path, contents).unwrap();
}

pub fn template() -> MandateTemplate {
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
/// The mock messaging provider's encryption key (synthetic).
pub fn messaging_key() -> DecryptionKey {
    DecryptionKey::from_bytes("mock-messaging-enc-1", [11u8; 32])
}

/// A copy of the reference tool registry in `dir`, signed by a tool signer
/// listed in `dir/tool-signers.json`; returns its path and digest.
pub fn signed_registry(dir: &Path) -> (PathBuf, String) {
    let registry = dir.join("agent-tools.yaml");
    let registry_bytes = std::fs::read(repo("tools/agent-tools.yaml")).unwrap();
    std::fs::write(&registry, &registry_bytes).unwrap();
    let tool_signer = SigningKey::from_bytes(&TOOL_SEED);
    let digest = format!("sha256:{:x}", Sha256::digest(&registry_bytes));
    let signature = tool_signer.sign(
        &[
            b"kavach-tool-registry-signature-v1:".as_slice(),
            digest.as_bytes(),
        ]
        .concat(),
    );
    std::fs::write(
        dir.join("agent-tools.yaml.sig"),
        json!({ "version": 1, "alg": "EdDSA", "kid": "tool-signer-1",
                "registry_sha256": digest, "signature": hex::encode(signature.to_bytes()) })
        .to_string(),
    )
    .unwrap();
    std::fs::write(
        dir.join("tool-signers.json"),
        json!({ "signers": [{ "kid": "tool-signer-1", "roles": ["tool"],
                              "public_key": hex::encode(tool_signer.verifying_key().to_bytes()) }] })
        .to_string(),
    )
    .unwrap();
    (registry, digest)
}

/// The credential signing key, the providers' encryption keys and the
/// (synthetic) reference fixture.
pub fn credential_files(dir: &Path, keys: &Path) {
    std::fs::write(
        dir.join("references.json"),
        json!({ "references": [{ "tenant_id": "default", "subject_ref": SUBJECT,
            "destinations": { "whatsapp": "+910000000001", "sms": "+910000000001", "voice": "+910000000002" } }] })
        .to_string(),
    )
    .unwrap();
    owner_only(
        &keys.join("kavach-credential-1.ed25519"),
        &hex::encode([5u8; 32]),
    );
    // Nothing listens on the discard port: "provider down" by default.
    write_providers(&dir.join("providers.json"), CLOSED_PORT, CLOSED_PORT);
}

/// A loopback endpoint nothing listens on (connection refused).
pub const CLOSED_PORT: &str = "http://127.0.0.1:9";

/// The voice provider's encryption key (synthetic).
pub fn voice_key() -> DecryptionKey {
    DecryptionKey::from_bytes("mock-voice-enc-1", [13u8; 32])
}

/// The providers file: encryption keys and endpoints.
pub fn write_providers(path: &Path, messaging: &str, voice: &str) {
    std::fs::write(
        path,
        json!({ "providers": [
            { "audience": "mock-messaging", "kid": "mock-messaging-enc-1",
              "x25519_public_key": hex::encode(messaging_key().recipient().public),
              "endpoint": messaging },
            { "audience": "mock-voice", "kid": "mock-voice-enc-1",
              "x25519_public_key": hex::encode(voice_key().recipient().public),
              "endpoint": voice },
        ]})
        .to_string(),
    )
    .unwrap();
}

pub fn files(rate: u32) -> (DataplaneConfig, OidcConfig) {
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
    credential_files(&dir, &keys);

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
    let (registry, digest) = signed_registry(&dir);

    let dataplane = DataplaneConfig {
        agent_oidc: OidcConfig {
            audience: "kavach-agents".into(),
            principal_claim: "azp".into(),
            ..operator.clone()
        },
        mandate_config: dir.join("mandates.json"),
        mandate_keys_dir: keys.clone(),
        evidence_keys_dir: keys.clone(),
        evidence_key_id: "kavach-evidence-1".into(),
        subject_pseudonym_key: dir.join("pseudonym.key"),
        consents: dir.join("consents.json"),
        tenant_id: "default".into(),
        sor_rate_per_second: rate,
        tool_registry: registry,
        tool_registry_sha256: Some(digest),
        tool_signers: Some(dir.join("tool-signers.json")),
        credential_keys_dir: keys,
        credential_key_id: "kavach-credential-1".into(),
        providers: dir.join("providers.json"),
        references: dir.join("references.json"),
        provider_connect_timeout_ms: 500,
        provider_timeout_ms: 1500,
        test_clock: None,
    };
    (dataplane, operator)
}

pub fn config(store: EvidenceStoreKind, insecure_dev: bool, rate: u32) -> ApiConfig {
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

pub async fn state(rate: u32) -> Arc<AppState> {
    Arc::new(
        AppState::from_config(&config(EvidenceStoreKind::Memory, true, rate))
            .await
            .expect("state"),
    )
}

pub async fn event(event_id: &str, record_ref: &str) -> String {
    event_at(event_id, record_ref, chrono::Utc::now()).await
}

/// A signed SoR event that occurred at `at` (tests with a test clock).
pub async fn event_at(
    event_id: &str,
    record_ref: &str,
    at: chrono::DateTime<chrono::Utc>,
) -> String {
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
        occurred_at: at,
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

pub async fn send(
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

pub async fn issue(state: &Arc<AppState>, event_id: &str) -> String {
    issue_at(state, event_id, chrono::Utc::now()).await
}

pub async fn issue_at(
    state: &Arc<AppState>,
    event_id: &str,
    at: chrono::DateTime<chrono::Utc>,
) -> String {
    let (status, body) = send(
        sor_router(state.clone()),
        "/v1/sor/events",
        &[],
        json!({ "event": event_at(event_id, "lms:loan/L-1", at).await }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    body["mandate_id"].as_str().unwrap().to_string()
}

pub fn read_fields(mandate_id: &str, request_id: &str) -> Value {
    json!({
        "tool": "read_fields",
        "mandate_id": mandate_id,
        "request_id": request_id,
        "params": {
            "subject_ref": SUBJECT,
            "requested_fields": ["name", "overdue_amount"]
        }
    })
}

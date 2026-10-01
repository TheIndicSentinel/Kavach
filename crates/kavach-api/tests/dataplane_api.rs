//! Agent surfaces over HTTP (H5a-5): `/v1/sor/events` issues mandates
//! idempotently and within limits; `/v1/authorize` is an agent-only
//! pre-check; startup refuses unsafe configurations.

mod agent_fixture;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::SigningKey;
use kavach_api::dataplane::{agent_router, sor_router};
use kavach_api::{router, ApiConfig, AppState, EvidenceStoreKind};
use kavach_credential::{open_credential, DecryptionKey};
use kavach_ports::agent_evidence::AgentEvidenceStore;
use serde_json::{json, Value};
use tower::ServiceExt;

use agent_fixture::*;

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

/// The tool registry is security-critical configuration: refused when
/// unsigned (outside --insecure-dev), tampered after signing, or off-pin.
#[tokio::test]
async fn startup_refuses_unsigned_tampered_or_unpinned_tool_registries() {
    let refused = |config: ApiConfig| async move {
        format!(
            "{:?}",
            AppState::from_config(&config).await.err().expect("refused")
        )
    };
    // Without --insecure-dev the registry is checked before the clock and
    // stores, so memory stores do not mask the refusal.
    let mut unsigned = config(EvidenceStoreKind::Memory, true, 50);
    unsigned.insecure_dev = false;
    let dp = unsigned.dataplane.as_mut().unwrap();
    dp.tool_signers = None;
    let message = refused(unsigned).await;
    assert!(message.contains("must be signed"), "{message}");

    let tampered = config(EvidenceStoreKind::Memory, true, 50);
    let path = tampered.dataplane.as_ref().unwrap().tool_registry.clone();
    let widened = std::fs::read_to_string(&path)
        .unwrap()
        .replace("values: [whatsapp, sms]", "values: [whatsapp, sms, email]");
    std::fs::write(&path, widened).unwrap();
    let mut unpinned = tampered.clone();
    unpinned.dataplane.as_mut().unwrap().tool_registry_sha256 = None;
    let message = refused(tampered).await;
    assert!(message.contains("pinned"), "{message}");
    let message = refused(unpinned).await;
    assert!(message.contains("signature covers"), "{message}");

    // A signer trusted for packs only cannot vouch for tools.
    let pack_only = config(EvidenceStoreKind::Memory, true, 50);
    let signers = pack_only
        .dataplane
        .as_ref()
        .unwrap()
        .tool_signers
        .clone()
        .unwrap();
    let text = std::fs::read_to_string(&signers)
        .unwrap()
        .replace("[\"tool\"]", "[\"pack\"]");
    std::fs::write(&signers, text).unwrap();
    let message = refused(pack_only).await;
    assert!(
        message.contains("not trusted to sign tool registries"),
        "{message}"
    );
}

/// The pre-check runs the same registry extraction as the gateway: malformed
/// requests are 400 (nothing recorded), policy violations are a BLOCK.
#[tokio::test]
async fn precheck_uses_the_tool_registry() {
    let s = state(50).await;
    let mandate = issue(&s, "evt-reg").await;
    let auth = [(
        "authorization",
        format!("Bearer {}", agent_token("collections-agent")),
    )];
    let post = |body: Value| send(agent_router(s.clone()), "/v1/authorize", &auth, body);
    let reminder = |channel: &str| {
        json!({
            "tool": "send_reminder",
            "mandate_id": mandate,
            "request_id": "reg-1",
            "params": {
                "subject_ref": SUBJECT,
                "channel": channel,
                "template_id": "emi_reminder_v1"
            }
        })
    };
    let (status, body) = post(reminder("whatsapp")).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Off-allowlist channel: a decision (BLOCK), not an error.
    let (status, body) = post(reminder("+919876543210")).await;
    assert_eq!(
        (status, body["decision"].clone()),
        (StatusCode::OK, json!("BLOCK")),
        "{body}"
    );
    assert!(!body.to_string().contains("9876543210"), "{body}");

    // Malformed: 400, and the error never quotes the offending value.
    let mut timestamp = reminder("whatsapp");
    timestamp["params"]["timestamp"] = json!("2026-10-01T05:00:00Z");
    let mut free_text = reminder("whatsapp");
    free_text["params"]["message"] = json!("call +91 98765 43210 now");
    let mut wrong_type = reminder("whatsapp");
    wrong_type["params"]["channel"] = json!(9_876_543_210_u64);
    let mut old_shape = reminder("whatsapp");
    old_shape["action"] = json!("send_reminder");
    for bad in [
        timestamp,
        free_text,
        wrong_type,
        old_shape,
        json!({ "tool": "update_status", "mandate_id": mandate, "request_id": "r", "params": {} }),
    ] {
        let (status, body) = post(bad.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad} -> {body}");
        assert!(!body.to_string().contains("98765"), "{body}");
    }
    assert!(
        s.dataplane()
            .unwrap()
            .core()
            .store()
            .records("default", 0)
            .await
            .unwrap()
            .is_empty(),
        "pre-checks record nothing"
    );
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

/// The broker is wired at startup: credentials are signed by the credential
/// key and readable only by the provider they are addressed to.
#[tokio::test]
async fn the_broker_issues_credentials_only_the_provider_can_open() {
    use kavach_ports::{CredentialBroker, CredentialRequest, Destination};
    let s = state(50).await;
    let dp = s.dataplane().unwrap();
    let destination = Destination::new("+910000000001");
    let now = chrono::Utc::now();
    let request = CredentialRequest {
        tenant_id: "default",
        agent_id: "collections-agent",
        mandate_id: "m-1",
        record_id: "rec-1",
        credential_id: "cred-api-1",
        audience: "mock-messaging",
        action: "send_reminder",
        destination: &destination,
        channel: "whatsapp",
        template_id: "emi_reminder_v1",
        expires_at: now + chrono::Duration::seconds(15),
        send_by: None,
        now,
    };
    let issued = dp.broker().issue(&request).await.unwrap();
    let credential_public = SigningKey::from_bytes(&[5u8; 32])
        .verifying_key()
        .to_bytes();
    let keys = kavach_jws::KeySet::new([kavach_ports::PublicKey {
        kid: "kavach-credential-1".into(),
        algorithm: kavach_ports::KeyAlgorithm::Ed25519,
        bytes: credential_public,
    }]);
    let claims = open_credential(
        issued.token.expose(),
        &keys,
        &messaging_key(),
        "mock-messaging",
        now,
    )
    .unwrap();
    assert_eq!(claims.req.destination.expose(), "+910000000001");
    assert_eq!(claims.jti, "cred-api-1");
    // The voice provider cannot read a messaging credential.
    let voice = DecryptionKey::from_bytes("mock-voice-enc-1", [13u8; 32]);
    assert!(open_credential(issued.token.expose(), &keys, &voice, "mock-messaging", now).is_err());
}

/// Key separation and provider keys are checked before anything is served.
#[tokio::test]
async fn startup_refuses_shared_credential_keys_and_missing_provider_keys() {
    let refused = |config: ApiConfig| async move {
        format!(
            "{:?}",
            AppState::from_config(&config).await.err().expect("refused")
        )
    };
    // The credential key id is the evidence key id.
    let mut shared_id = config(EvidenceStoreKind::Memory, true, 50);
    shared_id.dataplane.as_mut().unwrap().credential_key_id = "kavach-evidence-1".into();
    let message = refused(shared_id).await;
    assert!(message.contains("separate key"), "{message}");

    // A different id holding the mandate key's material.
    let copied = config(EvidenceStoreKind::Memory, true, 50);
    let dp = copied.dataplane.as_ref().unwrap();
    owner_only(
        &dp.credential_keys_dir.join("copied-1.ed25519"),
        &hex::encode([1u8; 32]),
    );
    let mut copied = copied.clone();
    copied.dataplane.as_mut().unwrap().credential_key_id = "copied-1".into();
    let message = refused(copied).await;
    assert!(
        message.contains("reuses the mandate or evidence key"),
        "{message}"
    );

    // The registry forwards to mock-voice, which has no encryption key.
    let missing = config(EvidenceStoreKind::Memory, true, 50);
    let path = missing.dataplane.as_ref().unwrap().providers.clone();
    std::fs::write(
        &path,
        json!({ "providers": [{ "audience": "mock-messaging", "kid": "mock-messaging-enc-1",
            "x25519_public_key": hex::encode(messaging_key().recipient().public),
            "endpoint": CLOSED_PORT }] })
        .to_string(),
    )
    .unwrap();
    let message = refused(missing).await;
    assert!(message.contains("mock-voice"), "{message}");

    // A low-order (all-zero) encryption key.
    let weak = config(EvidenceStoreKind::Memory, true, 50);
    let path = weak.dataplane.as_ref().unwrap().providers.clone();
    std::fs::write(
        &path,
        json!({ "providers": [
            { "audience": "mock-messaging", "kid": "k1", "x25519_public_key": hex::encode([0u8; 32]),
              "endpoint": CLOSED_PORT },
            { "audience": "mock-voice", "kid": "k2", "x25519_public_key": hex::encode([0u8; 32]),
              "endpoint": CLOSED_PORT },
        ]})
        .to_string(),
    )
    .unwrap();
    let message = refused(weak).await;
    assert!(message.contains("low-order"), "{message}");
}

/// The resolver is wired at startup, resolves only within the tenant, and
/// refuses a fixture holding a real-shaped number.
#[tokio::test]
async fn references_resolve_in_the_gateway_and_fixtures_hold_only_synthetic_numbers() {
    use kavach_ports::ReferenceResolver;
    let s = state(50).await;
    let resolver = s.dataplane().unwrap().resolver();
    let d = resolver
        .resolve("default", SUBJECT, "whatsapp")
        .await
        .unwrap();
    assert_eq!(d.expose(), "+910000000001");
    assert!(resolver
        .resolve("other", SUBJECT, "whatsapp")
        .await
        .is_err());
    assert!(!resolver.describe().contains("+910"));

    let real = config(EvidenceStoreKind::Memory, true, 50);
    let path = real.dataplane.as_ref().unwrap().references.clone();
    std::fs::write(
        &path,
        json!({ "references": [{ "tenant_id": "default", "subject_ref": SUBJECT,
            "destinations": { "whatsapp": "+919876543210" } }] })
        .to_string(),
    )
    .unwrap();
    let message = format!(
        "{:?}",
        AppState::from_config(&real).await.err().expect("refused")
    );
    assert!(message.contains("synthetic"), "{message}");
    assert!(!message.contains("9876543210"), "{message}");
}

/// Development keys (`dev-…`) never sign production evidence or credentials.
#[tokio::test]
async fn startup_refuses_development_keys_outside_insecure_dev() {
    let mut cfg = config(EvidenceStoreKind::Memory, false, 50);
    let dp = cfg.dataplane.as_mut().unwrap();
    owner_only(
        &dp.credential_keys_dir.join("dev-credential-1.ed25519"),
        &hex::encode([8u8; 32]),
    );
    dp.credential_key_id = "dev-credential-1".into();
    let message = format!(
        "{:?}",
        AppState::from_config(&cfg).await.err().expect("refused")
    );
    assert!(message.contains("development key"), "{message}");
    // The same key is accepted by a development stack.
    cfg.insecure_dev = true;
    AppState::from_config(&cfg).await.expect("dev stack starts");
}

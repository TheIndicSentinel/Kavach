//! KMS milestone K2: the API with its signing keys in an HSM (SoftHSM2).
//!
//! Runs when `KAVACH_TEST_PKCS11_MODULE` and `SOFTHSM2_CONF` point at a
//! prepared token (`scripts/softhsm-test-token.sh`; CI does this); skipped
//! otherwise. Each test makes its own keys, with labels unique to the run.

mod agent_fixture;

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use agent_fixture::{config_for_gateway, gateway_with, operator_token};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error as CkError, RvError};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use kavach_api::signing::{HsmConfig, HsmRole};
use kavach_api::{router, AppState};
use kavach_dataplane::Tick;
use kavach_ports::{KeyAlgorithm, PublicKey};
use serde_json::Value;
use tower::ServiceExt;

const TOKEN: &str = "kavach-test";
const PIN: &str = "1234";
const ED25519_OID: [u8; 5] = [0x06, 0x03, 0x2B, 0x65, 0x70];

fn module() -> Option<PathBuf> {
    std::env::var_os("SOFTHSM2_CONF")?;
    Some(PathBuf::from(std::env::var_os(
        "KAVACH_TEST_PKCS11_MODULE",
    )?))
}

/// One module context for the process, never dropped (loading and
/// unloading the module concurrently is not safe).
fn context(module: &PathBuf) -> Pkcs11 {
    static CONTEXT: std::sync::OnceLock<Pkcs11> = std::sync::OnceLock::new();
    CONTEXT
        .get_or_init(|| {
            let pkcs11 = Pkcs11::new(module).unwrap();
            match pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
                Ok(()) | Err(CkError::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => {}
                Err(e) => panic!("initialise: {e}"),
            }
            pkcs11
        })
        .clone()
}

/// One test at a time against the token.
async fn serial() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    LOCK.lock().await
}

/// Generates an Ed25519 key in the token and returns its public half.
fn generate(module: &PathBuf, label: &str) -> PublicKey {
    let pkcs11 = context(module);
    let slot = pkcs11
        .get_slots_with_token()
        .unwrap()
        .into_iter()
        .find(|s| pkcs11.get_token_info(*s).unwrap().label().trim_end() == TOKEN)
        .expect("prepared token");
    let session = pkcs11.open_rw_session(slot).unwrap();
    match session.login(UserType::User, Some(&AuthPin::new(PIN.into()))) {
        Ok(()) | Err(CkError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => {}
        Err(e) => panic!("login: {e}"),
    }
    let (public, _) = session
        .generate_key_pair(
            &Mechanism::EccEdwardsKeyPairGen,
            &[
                Attribute::Token(true),
                Attribute::Label(label.as_bytes().to_vec()),
                Attribute::EcParams(ED25519_OID.to_vec()),
                Attribute::Verify(true),
            ],
            &[
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Label(label.as_bytes().to_vec()),
                Attribute::Sign(true),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
            ],
        )
        .unwrap();
    let point = session
        .get_attributes(public, &[AttributeType::EcPoint])
        .unwrap()
        .into_iter()
        .find_map(|a| match a {
            Attribute::EcPoint(p) => Some(p),
            _ => None,
        })
        .unwrap();
    let bytes: [u8; 32] = match point.as_slice() {
        [0x04, 0x20, rest @ ..] => rest.try_into().unwrap(),
        raw => raw.try_into().unwrap(),
    };
    PublicKey {
        kid: label.into(),
        algorithm: KeyAlgorithm::Ed25519,
        bytes,
    }
}

fn pin_file() -> PathBuf {
    let path =
        std::env::temp_dir().join(format!("kavach-hsm-pin-{}", uuid::Uuid::new_v4().simple()));
    agent_fixture::owner_only(&path, PIN);
    path
}

/// The gateway fixture with every signing key in the HSM, labelled
/// uniquely for this run.
fn hsm_config(module: PathBuf, run: &str) -> (kavach_api::ApiConfig, PublicKey) {
    let mut api = config_for_gateway();
    let dp = api.dataplane.as_mut().unwrap();
    let kid = |role: &str| format!("hsm-{role}-{run}");
    for role in ["mandate", "evidence", "checkpoint"] {
        generate(&module, &kid(role));
    }
    let credential = generate(&module, &kid("credential"));
    dp.evidence_key_id = kid("evidence");
    dp.checkpoint_key_id = kid("checkpoint");
    dp.credential_key_id = kid("credential");
    let mut mandates: Value =
        serde_json::from_str(&std::fs::read_to_string(&dp.mandate_config).unwrap()).unwrap();
    mandates["signing_kid"] = Value::String(kid("mandate"));
    std::fs::write(&dp.mandate_config, mandates.to_string()).unwrap();
    dp.hsm = Some(HsmConfig {
        module,
        token_label: TOKEN.into(),
        pin_file: pin_file(),
        roles: HsmRole::ALL.into_iter().collect::<BTreeSet<_>>(),
        max_sessions: 4,
    });
    (api, credential)
}

async fn runtime(state: &std::sync::Arc<AppState>) -> Value {
    let response = router(state.clone())
        .oneshot(
            Request::get("/v1/runtime")
                .header("authorization", format!("Bearer {}", operator_token()))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// Mandate, evidence record, credential and checkpoint are all signed in
/// the HSM on a real delivered call, and `/v1/runtime` says so.
#[tokio::test(flavor = "multi_thread")]
async fn a_delivered_call_is_signed_in_the_hsm_end_to_end() {
    let Some(module) = module() else {
        eprintln!("skipped: set KAVACH_TEST_PKCS11_MODULE and SOFTHSM2_CONF");
        return;
    };
    let _serial = serial().await;
    let run = uuid::Uuid::new_v4().simple().to_string()[..8].to_string();
    let (api, credential) = hsm_config(module, &run);
    // The provider trusts the HSM's credential key: it only accepts
    // credentials that key signed.
    let gw = gateway_with(api, Some("+910000000001"), true, Some(credential)).await;

    let (status, reply) = gw.remind("hsm-1").await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["outcome"], "delivered", "{reply}");

    let dp = gw.state.dataplane().unwrap();
    let written = dp
        .checkpointer()
        .tick(Instant::now() + Duration::from_secs(3600))
        .await;
    assert!(
        matches!(written.tick, Tick::Written { .. }),
        "{:?}",
        written.tick
    );

    let view = runtime(&gw.state).await;
    assert_eq!(view["hsm"]["healthy"], true, "{view}");
    assert_eq!(
        view["hsm"]["roles"],
        serde_json::json!(["mandate", "evidence", "checkpoint", "credential"]),
        "{view}"
    );
}

/// The key-separation rules hold for HSM keys too.
#[tokio::test(flavor = "multi_thread")]
async fn an_hsm_key_shared_between_roles_is_refused() {
    let Some(module) = module() else {
        eprintln!("skipped: set KAVACH_TEST_PKCS11_MODULE and SOFTHSM2_CONF");
        return;
    };
    let _serial = serial().await;
    let run = uuid::Uuid::new_v4().simple().to_string()[..8].to_string();
    let (mut api, _) = hsm_config(module, &run);
    let dp = api.dataplane.as_mut().unwrap();
    dp.checkpoint_key_id = dp.evidence_key_id.clone();
    let err = AppState::from_config(&api).await.err().expect("refused");
    assert!(err.to_string().contains("separate key"), "{err}");
}

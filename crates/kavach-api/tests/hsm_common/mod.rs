//! Shared set-up for the SoftHSM API tests: keys made in the prepared
//! token, the gateway fixture with keys in the HSM, `/v1/runtime`.
#![allow(dead_code)]

use std::collections::BTreeSet;
use std::path::PathBuf;

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
use kavach_ports::{KeyAlgorithm, PublicKey};
use serde_json::Value;
use tower::ServiceExt;

use crate::agent_fixture::{config_for_gateway, operator_token, owner_only};

pub const TOKEN: &str = "kavach-test";
pub const PIN: &str = "1234";
pub const ED25519_OID: [u8; 5] = [0x06, 0x03, 0x2B, 0x65, 0x70];

pub fn module() -> Option<PathBuf> {
    std::env::var_os("SOFTHSM2_CONF")?;
    Some(PathBuf::from(std::env::var_os(
        "KAVACH_TEST_PKCS11_MODULE",
    )?))
}

/// One module context for the process, never dropped (loading and
/// unloading the module concurrently is not safe).
pub fn context(module: &PathBuf) -> Pkcs11 {
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
pub async fn serial() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    LOCK.lock().await
}

/// Generates an Ed25519 key in the token and returns its public half.
pub fn generate(module: &PathBuf, label: &str) -> PublicKey {
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

pub fn pin_file() -> PathBuf {
    let path =
        std::env::temp_dir().join(format!("kavach-hsm-pin-{}", uuid::Uuid::new_v4().simple()));
    owner_only(&path, PIN);
    path
}

/// The gateway fixture with every signing key in the HSM, labelled
/// uniquely for this run.
pub fn hsm_config(module: PathBuf, run: &str) -> (kavach_api::ApiConfig, PublicKey) {
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

pub async fn runtime(state: &std::sync::Arc<AppState>) -> Value {
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

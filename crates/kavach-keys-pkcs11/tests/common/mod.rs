//! Shared set-up for the SoftHSM tests.
//!
//! The token is prepared before the tests start (CI: the "Prepare a SoftHSM
//! token" step; locally: `scripts/softhsm-test-token.sh`), and the tests
//! find it through the environment. Nothing here changes the environment:
//! setting a variable while other test threads read it can crash the
//! process. One module context stays loaded for the whole process, and the
//! tests run one at a time ([`serial`]).
#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::OnceLock;

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error as CkError, RvError};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, KeyType, ObjectClass};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;
use kavach_keys_pkcs11::Pkcs11Config;

/// Must match the token the preparation step made.
pub const TOKEN: &str = "kavach-test";
pub const PIN: &str = "1234";
pub const ED25519_OID: [u8; 5] = [0x06, 0x03, 0x2B, 0x65, 0x70];

/// The module path when a prepared token is available; `None` skips.
pub fn module() -> Option<PathBuf> {
    let module = PathBuf::from(std::env::var_os("KAVACH_TEST_PKCS11_MODULE")?);
    std::env::var_os("SOFTHSM2_CONF")?;
    Some(module)
}

/// The process-wide context: loaded once and never dropped, so the module
/// is not unloaded and reloaded between tests.
pub fn context(module: &PathBuf) -> Pkcs11 {
    static CONTEXT: OnceLock<Pkcs11> = OnceLock::new();
    CONTEXT
        .get_or_init(|| {
            let pkcs11 = Pkcs11::new(module).expect("load module");
            initialize(&pkcs11);
            pkcs11
        })
        .clone()
}

pub fn initialize(pkcs11: &Pkcs11) {
    match pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
        Ok(()) | Err(CkError::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => {}
        Err(e) => panic!("initialise: {e}"),
    }
}

/// One test at a time against the token (an async lock: tests await while
/// holding it).
pub async fn serial() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    LOCK.lock().await
}

#[macro_export]
macro_rules! require_hsm {
    () => {
        match common::module() {
            Some(module) => (module, common::serial().await),
            None => {
                eprintln!(
                    "skipped: set KAVACH_TEST_PKCS11_MODULE and SOFTHSM2_CONF \
                     (scripts/softhsm-test-token.sh) to run against SoftHSM2"
                );
                return;
            }
        }
    };
}

/// A read-write session for making test keys, on the shared context.
pub fn admin(module: &PathBuf) -> (Pkcs11, Session) {
    let pkcs11 = context(module);
    let slot = pkcs11
        .get_slots_with_token()
        .unwrap()
        .into_iter()
        .find(|s| pkcs11.get_token_info(*s).unwrap().label().trim_end() == TOKEN)
        .unwrap();
    let session = pkcs11.open_rw_session(slot).unwrap();
    match session.login(UserType::User, Some(&AuthPin::new(PIN.into()))) {
        Ok(()) | Err(CkError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => {}
        Err(e) => panic!("login: {e}"),
    }
    (pkcs11, session)
}

/// Generates an Ed25519 key pair inside the token.
pub fn generate(module: &PathBuf, label: &str, extractable: bool) {
    let (_ctx, session) = admin(module);
    session
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
                Attribute::Sensitive(!extractable),
                Attribute::Extractable(extractable),
            ],
        )
        .expect("generate Ed25519 key pair");
}

/// Imports an Ed25519 key pair from known bytes: the HSM did not make it.
pub fn import(module: &PathBuf, label: &str) {
    let (_ctx, session) = admin(module);
    let secret = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
    let mut point = vec![0x04, 0x20];
    point.extend_from_slice(secret.verifying_key().as_bytes());
    let common = |class| {
        vec![
            Attribute::Class(class),
            Attribute::KeyType(KeyType::EC_EDWARDS),
            Attribute::Token(true),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::EcParams(ED25519_OID.to_vec()),
        ]
    };
    let mut private = common(ObjectClass::PRIVATE_KEY);
    private.extend([
        Attribute::Private(true),
        Attribute::Sign(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Value(secret.to_bytes().to_vec()),
    ]);
    let mut public = common(ObjectClass::PUBLIC_KEY);
    public.extend([Attribute::Verify(true), Attribute::EcPoint(point)]);
    session.create_object(&private).expect("import private key");
    session.create_object(&public).expect("import public key");
}

pub fn config(module: PathBuf, keys: &[&str], strict: bool) -> Pkcs11Config {
    Pkcs11Config {
        module,
        token_label: TOKEN.into(),
        pin: AuthPin::new(PIN.into()),
        key_ids: keys.iter().map(ToString::to_string).collect(),
        max_sessions: 4,
        require_hsm_generated: strict,
    }
}

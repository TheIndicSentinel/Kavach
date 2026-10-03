//! Shared set-up for the SoftHSM tests: one throw-away token per test
//! process, and helpers that make keys in it.
#![allow(dead_code)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error as CkError, RvError};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, KeyType, ObjectClass};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;
use kavach_keys_pkcs11::Pkcs11Config;

pub const TOKEN: &str = "kavach-test";
pub const PIN: &str = "1234";
pub const ED25519_OID: [u8; 5] = [0x06, 0x03, 0x2B, 0x65, 0x70];

/// The module path, after creating the token once; `None` skips the test.
pub fn module() -> Option<PathBuf> {
    static MODULE: OnceLock<Option<PathBuf>> = OnceLock::new();
    MODULE
        .get_or_init(|| {
            let module = PathBuf::from(std::env::var_os("KAVACH_TEST_PKCS11_MODULE")?);
            let dir = std::env::temp_dir().join(format!("kavach-softhsm-{}", std::process::id()));
            std::fs::create_dir_all(dir.join("tokens")).unwrap();
            let conf = dir.join("softhsm2.conf");
            std::fs::write(
                &conf,
                format!(
                    "directories.tokendir = {}\nobjectstore.backend = file\n",
                    dir.join("tokens").display()
                ),
            )
            .unwrap();
            // Read by SoftHSM when the module initialises; set before that.
            std::env::set_var("SOFTHSM2_CONF", &conf);
            let status = Command::new("softhsm2-util")
                .args([
                    "--init-token",
                    "--free",
                    "--label",
                    TOKEN,
                    "--so-pin",
                    "0000",
                    "--pin",
                    PIN,
                ])
                .status()
                .expect("softhsm2-util");
            assert!(status.success(), "init token");
            Some(module)
        })
        .clone()
}

#[macro_export]
macro_rules! require_hsm {
    () => {
        match common::module() {
            Some(module) => module,
            None => {
                eprintln!("skipped: set KAVACH_TEST_PKCS11_MODULE to run against SoftHSM2");
                return;
            }
        }
    };
}

/// A read-write session for making test keys (a second context in the same
/// process: the module is already initialised, which is fine).
pub fn admin(module: &PathBuf) -> (Pkcs11, Session) {
    let pkcs11 = Pkcs11::new(module).unwrap();
    match pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
        Ok(()) | Err(CkError::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => {}
        Err(e) => panic!("initialise: {e}"),
    }
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

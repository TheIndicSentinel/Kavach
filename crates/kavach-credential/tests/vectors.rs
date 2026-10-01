//! Known-answer vectors for the credential format.
//!
//! `tests/vectors/credential-v1.json` is a credential Kavach issued once,
//! with test-only keys, plus the expected claims. It is checked in, so:
//! - this test pins the decrypt/verify path to fixed bytes (a change to the
//!   format or the crypto shows up as a failure, not as two sides agreeing);
//! - CI decrypts and verifies the same token with an independent JOSE
//!   implementation (`scripts/jose-crosscheck`, Node `jose`), which checks
//!   that what Kavach emits is standard JWE/JWS.
//!
//! Regenerate only on a deliberate format change:
//! `cargo test -p kavach-credential --test vectors -- --ignored generate`.

use std::collections::BTreeMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Duration, TimeZone, Utc};
use ed25519_dalek::SigningKey;
use kavach_credential::{
    check_time, claims_digest, decrypt_and_verify, DecryptionKey, JoseCredentialBroker,
};
use kavach_jws::KeySet;
use kavach_keys::InMemoryKeyProvider;
use kavach_ports::{CredentialBroker, ErrorClass, KeyAlgorithm, PublicKey};
use kavach_ports_testkit::credential_broker::{self, DESTINATION};
use serde_json::{json, Value};

const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/credential-v1.json"
);
const SIGNING_SEED: [u8; 32] = [21u8; 32];
const SIGNING_KID: &str = "kavach-credential-kat";
const PROVIDER_SEED: [u8; 32] = [22u8; 32];
const PROVIDER_KID: &str = "mock-messaging-kat";
const AUDIENCE: &str = "mock-messaging";

fn issued_at() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 1, 5, 30, 0).unwrap()
}

fn signing_public() -> [u8; 32] {
    SigningKey::from_bytes(&SIGNING_SEED)
        .verifying_key()
        .to_bytes()
}

fn keys() -> KeySet {
    KeySet::new([PublicKey {
        kid: SIGNING_KID.into(),
        algorithm: KeyAlgorithm::Ed25519,
        bytes: signing_public(),
    }])
}

fn provider() -> DecryptionKey {
    DecryptionKey::from_bytes(PROVIDER_KID, PROVIDER_SEED)
}

fn vector() -> Value {
    serde_json::from_str(&std::fs::read_to_string(PATH).expect("vector file")).unwrap()
}

#[tokio::test]
#[ignore = "regenerates the checked-in vector; run only on a deliberate format change"]
async fn generate() {
    let mut signer = InMemoryKeyProvider::new();
    signer.insert_seed(SIGNING_KID, SIGNING_SEED).unwrap();
    let broker = JoseCredentialBroker::new(
        signer,
        SIGNING_KID,
        "kavach",
        BTreeMap::from([(AUDIENCE.to_string(), provider().recipient())]),
    );
    let destination = kavach_ports::Destination::new(DESTINATION);
    let mut request = credential_broker::request(&destination, "cred-kat-1");
    request.now = issued_at();
    request.expires_at = issued_at() + Duration::seconds(15);
    let issued = broker.issue(&request).await.unwrap();
    let claims = decrypt_and_verify(issued.token.expose(), &keys(), &provider(), AUDIENCE).unwrap();
    let file = json!({
        "description": "Kavach resource credential v1: JWS (EdDSA, kavach-credential+jws) nested in JWE (ECDH-ES, X25519, A256GCM, kavach-credential+jwe). Test keys only.",
        "credential_signing_jwk": {
            "kty": "OKP", "crv": "Ed25519", "kid": SIGNING_KID,
            "x": URL_SAFE_NO_PAD.encode(signing_public()),
        },
        "provider_jwk": {
            "kty": "OKP", "crv": "X25519", "kid": PROVIDER_KID,
            "x": URL_SAFE_NO_PAD.encode(provider().recipient().public),
            "d": URL_SAFE_NO_PAD.encode(PROVIDER_SEED),
        },
        "audience": AUDIENCE,
        "verify_at": issued_at().timestamp(),
        "token": issued.token.expose(),
        "claims": serde_json::to_value(&claims).unwrap(),
        "claims_sha256": claims_digest(&claims).unwrap(),
    });
    std::fs::create_dir_all(std::path::Path::new(PATH).parent().unwrap()).unwrap();
    std::fs::write(PATH, serde_json::to_string_pretty(&file).unwrap() + "\n").unwrap();
}

#[test]
fn the_checked_in_credential_opens_to_the_expected_claims() {
    let v = vector();
    // The file's keys are the ones these tests derive.
    assert_eq!(
        v["credential_signing_jwk"]["x"],
        URL_SAFE_NO_PAD.encode(signing_public())
    );
    assert_eq!(
        v["provider_jwk"]["x"],
        URL_SAFE_NO_PAD.encode(provider().recipient().public)
    );
    let token = v["token"].as_str().unwrap();
    let claims = decrypt_and_verify(token, &keys(), &provider(), AUDIENCE).unwrap();
    assert_eq!(serde_json::to_value(&claims).unwrap(), v["claims"]);
    assert_eq!(claims_digest(&claims).unwrap(), v["claims_sha256"]);
    assert_eq!(claims.req.destination.expose(), DESTINATION);
    let at = DateTime::from_timestamp(v["verify_at"].as_i64().unwrap(), 0).unwrap();
    check_time(&claims, at, 0).unwrap();
}

#[test]
fn negative_vectors_are_refused() {
    let v = vector();
    let token = v["token"].as_str().unwrap();
    let at = DateTime::from_timestamp(v["verify_at"].as_i64().unwrap(), 0).unwrap();
    let parts: Vec<&str> = token.split('.').collect();
    let with = |i: usize, value: &str| {
        let mut p: Vec<String> = parts.iter().map(|s| (*s).to_string()).collect();
        p[i] = value.to_string();
        p.join(".")
    };
    let flip = |part: &str| {
        let mut bytes = URL_SAFE_NO_PAD.decode(part).unwrap();
        bytes[0] ^= 1;
        URL_SAFE_NO_PAD.encode(bytes)
    };
    for (what, bad) in [
        ("tag", with(4, &flip(parts[4]))),
        ("ciphertext", with(3, &flip(parts[3]))),
        ("iv", with(2, &flip(parts[2]))),
        ("truncated", parts[..4].join(".")),
    ] {
        assert!(
            decrypt_and_verify(&bad, &keys(), &provider(), AUDIENCE).is_err(),
            "{what}"
        );
    }
    // Another audience, another provider key, an untrusted signer.
    assert_eq!(
        decrypt_and_verify(token, &keys(), &provider(), "mock-voice")
            .unwrap_err()
            .class,
        ErrorClass::Rejected
    );
    let other = DecryptionKey::from_bytes(PROVIDER_KID, [23u8; 32]);
    assert!(decrypt_and_verify(token, &keys(), &other, AUDIENCE).is_err());
    let untrusted = KeySet::new([PublicKey {
        kid: SIGNING_KID.into(),
        algorithm: KeyAlgorithm::Ed25519,
        bytes: SigningKey::from_bytes(&[24u8; 32])
            .verifying_key()
            .to_bytes(),
    }]);
    assert!(decrypt_and_verify(token, &untrusted, &provider(), AUDIENCE).is_err());
    // Expired, and a leeway that would reach past send_by never does.
    let claims = decrypt_and_verify(token, &keys(), &provider(), AUDIENCE).unwrap();
    assert!(check_time(&claims, at + Duration::seconds(15), 0).is_err());
    let send_by = DateTime::from_timestamp(claims.send_by.unwrap(), 0).unwrap();
    assert!(check_time(&claims, send_by - Duration::seconds(1), 5).is_err());
}

//! Resource credentials as a provider opens them (`open_credential`): a
//! JWE to the provider's X25519 key around a JWS from the credential key.
//! Keys and time come from the checked-in vector
//! (crates/kavach-credential/tests/vectors/credential-v1.json).
//!
//! First byte selects the mode:
//! - 0: the rest is any string, presented as the credential.
//! - 1: the rest is the claims, signed with the credential key and
//!   encrypted to the provider, so the claim and time checks are reached.
//!   (Encryption uses a fresh ephemeral key, which never changes whether a
//!   credential opens.)
//! - 2: the rest is a list of (position, byte) edits to the vector's token.
//!
//! Invariants: an opened credential is addressed to this provider, lives at
//! most 15 s, is not expired at the verification time, and ends no later
//! than its `send_by`; its claims are the canonical form of what was
//! signed; and any change to the vector's token is refused.

#![no_main]

use std::sync::OnceLock;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use kavach_credential::jwe::{encrypt, DecryptionKey};
use kavach_credential::{open_credential, TYP_CREDENTIAL, TYP_CREDENTIAL_JWE};
use kavach_fuzz::sign_raw;
use kavach_jws::KeySet;
use kavach_ports::{KeyAlgorithm, PublicKey};
use libfuzzer_sys::fuzz_target;
use serde_json::Value;

struct Fixture {
    token: String,
    audience: String,
    now: DateTime<Utc>,
    signing: KeySet,
    provider: DecryptionKey,
}

/// The vector's credential key is public only, so mode 1 signs with a key
/// of its own, registered under its own kid next to the vector's.
const SIGNING_SEED: [u8; 32] = [9u8; 32];
const SIGNING_KID: &str = "fuzz-credential";

fn b64(value: &Value) -> Vec<u8> {
    URL_SAFE_NO_PAD
        .decode(value.as_str().expect("base64url string"))
        .expect("base64url")
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let v: Value = serde_json::from_str(include_str!(
            "../../crates/kavach-credential/tests/vectors/credential-v1.json"
        ))
        .unwrap();
        let key = |kid: &str, x: Vec<u8>| PublicKey {
            kid: kid.into(),
            algorithm: KeyAlgorithm::Ed25519,
            bytes: x.try_into().expect("32-byte Ed25519 key"),
        };
        let ours = ed25519_dalek::SigningKey::from_bytes(&SIGNING_SEED)
            .verifying_key()
            .to_bytes()
            .to_vec();
        let secret: [u8; 32] = b64(&v["provider_jwk"]["d"]).try_into().unwrap();
        Fixture {
            token: v["token"].as_str().unwrap().into(),
            audience: v["audience"].as_str().unwrap().into(),
            now: DateTime::from_timestamp(v["verify_at"].as_i64().unwrap(), 0).unwrap(),
            signing: KeySet::new([
                key(
                    v["credential_signing_jwk"]["kid"].as_str().unwrap(),
                    b64(&v["credential_signing_jwk"]["x"]),
                ),
                key(SIGNING_KID, ours),
            ]),
            provider: DecryptionKey::from_bytes(
                v["provider_jwk"]["kid"].as_str().unwrap(),
                secret,
            ),
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let f = fixture();
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let (token, signed_claims) = match mode % 3 {
        0 => {
            let Ok(token) = std::str::from_utf8(rest) else {
                return;
            };
            (token.to_string(), None)
        }
        1 => {
            let header = format!(r#"{{"alg":"EdDSA","kid":"{SIGNING_KID}","typ":"{TYP_CREDENTIAL}"}}"#);
            let jws = sign_raw(&SIGNING_SEED, header.as_bytes(), rest);
            let Ok(token) = encrypt(
                jws.as_bytes(),
                &f.provider.recipient(),
                TYP_CREDENTIAL_JWE,
                TYP_CREDENTIAL,
            ) else {
                return;
            };
            (token, Some(rest))
        }
        _ => {
            let mut bytes = f.token.clone().into_bytes();
            for edit in rest.chunks_exact(3) {
                let at = usize::from(u16::from_le_bytes([edit[0], edit[1]])) % bytes.len();
                bytes[at] = edit[2];
            }
            let Ok(token) = String::from_utf8(bytes) else {
                return;
            };
            if token != f.token {
                assert!(
                    open_credential(&token, &f.signing, &f.provider, &f.audience, f.now).is_err(),
                    "a changed credential opened"
                );
                return;
            }
            (token, None)
        }
    };
    let Ok(claims) = open_credential(&token, &f.signing, &f.provider, &f.audience, f.now) else {
        return;
    };
    let now = f.now.timestamp();
    assert_eq!(claims.aud, f.audience, "opened for another audience");
    assert!(claims.exp > claims.iat && claims.exp - claims.iat <= 15, "lifetime");
    assert!(now < claims.exp, "expired credential opened");
    if let Some(send_by) = claims.send_by {
        assert!(now < send_by && claims.exp <= send_by, "past send_by");
    }
    if let Some(signed) = signed_claims {
        let canonical = kavach_ports::jcs::to_vec(&claims).unwrap();
        assert_eq!(canonical, signed, "claims are not the canonical form of what was signed");
    }
});

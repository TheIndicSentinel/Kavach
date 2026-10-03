//! Agent access tokens (OIDC JWT) as the data plane verifies them.
//!
//! First byte 0: the rest is the token, as any string. Otherwise the rest
//! is `header\nclaims`, signed with the JWKS's Ed25519 key, so the claim
//! checks after the signature are reached with bytes the fuzzer chose.
//!
//! Invariant: an accepted token was signed with an allowed algorithm (only
//! EdDSA can verify here) and names a 1-256 character principal.

#![no_main]

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::SigningKey;
use kavach_api::{JwksSource, OidcConfig, OidcVerifier};
use kavach_fuzz::{sign_raw, split_header_payload, SIGNING_SEED};
use libfuzzer_sys::fuzz_target;
use serde_json::{json, Value};

fn verifier() -> &'static Arc<OidcVerifier> {
    static VERIFIER: OnceLock<Arc<OidcVerifier>> = OnceLock::new();
    VERIFIER.get_or_init(|| {
        let public = SigningKey::from_bytes(&SIGNING_SEED)
            .verifying_key()
            .to_bytes();
        let jwks = serde_json::from_value(json!({ "keys": [{
            "kty": "OKP", "crv": "Ed25519", "x": URL_SAFE_NO_PAD.encode(public),
            "kid": "agent-key", "alg": "EdDSA", "use": "sig"
        }]}))
        .unwrap();
        OidcVerifier::from_jwks(
            OidcConfig {
                issuer: "https://idp.fuzz.local".into(),
                audience: "kavach-agents".into(),
                jwks: JwksSource::File(PathBuf::new()),
                principal_claim: "azp".into(),
                groups_claim: "groups".into(),
                leeway_seconds: 60,
            },
            &jwks,
        )
    })
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let (token, header) = if mode == 0 {
        let Ok(token) = std::str::from_utf8(rest) else {
            return;
        };
        (token.to_string(), None)
    } else {
        let Some((header, claims)) = split_header_payload(rest) else {
            return;
        };
        (sign_raw(&SIGNING_SEED, header, claims), Some(header))
    };
    let Ok(verified) = verifier().verify(&token) else {
        return;
    };
    assert!(!verified.principal.is_empty() && verified.principal.len() <= 256);
    if let Some(header) = header {
        let header: Value = serde_json::from_slice(header).expect("accepted header is JSON");
        assert_eq!(header["alg"], "EdDSA", "accepted a token not signed with EdDSA");
    }
});

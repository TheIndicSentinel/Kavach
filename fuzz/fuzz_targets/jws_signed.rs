//! `header\npayload`: the fuzzer's own header and payload bytes, signed
//! with a trusted key, so everything after the signature check is reached:
//! header and payload parsing, the canonical-form checks, typed payloads.
//!
//! Invariant: a token that verifies has exactly one valid encoding. Its
//! header and payload are the JCS form of what was parsed, and signing the
//! parsed payload again yields the same token, byte for byte.

#![no_main]

use std::sync::OnceLock;

use kavach_credential::TYP_CREDENTIAL;
use kavach_domain::mandate::{Mandate, SorEvent};
use kavach_fuzz::{block_on, sign_raw, split_header_payload, SIGNING_SEED};
use kavach_jws::{sign, verify, KeySet};
use kavach_keys::InMemoryKeyProvider;
use kavach_mandate::jws::{TYP_MANDATE, TYP_SOR_EVENT};
use libfuzzer_sys::fuzz_target;
use serde_json::{json, Value};

fn provider_and_keys() -> &'static (InMemoryKeyProvider, KeySet) {
    static KEYS: OnceLock<(InMemoryKeyProvider, KeySet)> = OnceLock::new();
    KEYS.get_or_init(|| {
        let mut provider = InMemoryKeyProvider::new();
        let public = provider.insert_seed("k1", SIGNING_SEED).unwrap();
        (provider, KeySet::new([public]))
    })
}

fuzz_target!(|data: &[u8]| {
    let Some((header, payload)) = split_header_payload(data) else {
        return;
    };
    let (provider, keys) = provider_and_keys();
    let token = sign_raw(&SIGNING_SEED, header, payload);
    for typ in [TYP_MANDATE, TYP_SOR_EVENT, TYP_CREDENTIAL] {
        let _ = verify::<Mandate>(&token, typ, keys);
        let _ = verify::<SorEvent>(&token, typ, keys);
        let Ok((kid, value)) = verify::<Value>(&token, typ, keys) else {
            continue;
        };
        let expected_header =
            serde_json_canonicalizer::to_vec(&json!({ "alg": "EdDSA", "kid": kid, "typ": typ }))
                .unwrap();
        assert_eq!(header, expected_header.as_slice(), "header not unique");
        assert_eq!(
            payload,
            serde_json_canonicalizer::to_vec(&value).unwrap().as_slice(),
            "payload not unique"
        );
        let again = block_on(sign(provider, &kid, typ, &value)).expect("re-sign");
        assert_eq!(again, token, "a verified token must have one encoding");
    }
});

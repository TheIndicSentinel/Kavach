//! Any string as a compact JWS, for every token type Kavach accepts
//! (mandates, system-of-record events, broker credentials). The key is
//! fixed, so almost nothing passes the signature: this target covers
//! splitting, base64url, header parsing and the checks before it.

#![no_main]

use std::sync::OnceLock;

use kavach_credential::TYP_CREDENTIAL;
use kavach_domain::mandate::{Mandate, SorEvent};
use kavach_fuzz::SIGNING_SEED;
use kavach_jws::{verify, KeySet};
use kavach_keys::InMemoryKeyProvider;
use kavach_mandate::jws::{TYP_MANDATE, TYP_SOR_EVENT};
use libfuzzer_sys::fuzz_target;
use serde_json::Value;

fn keys() -> &'static KeySet {
    static KEYS: OnceLock<KeySet> = OnceLock::new();
    KEYS.get_or_init(|| {
        let mut provider = InMemoryKeyProvider::new();
        KeySet::new([provider.insert_seed("k1", SIGNING_SEED).unwrap()])
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(token) = std::str::from_utf8(data) else {
        return;
    };
    for typ in [TYP_MANDATE, TYP_SOR_EVENT, TYP_CREDENTIAL] {
        let _ = verify::<Value>(token, typ, keys());
        let _ = verify::<Mandate>(token, typ, keys());
        let _ = verify::<SorEvent>(token, typ, keys());
    }
});

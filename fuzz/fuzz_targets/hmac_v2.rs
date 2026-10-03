//! HMAC v2 request signing (`/v1/evaluate`), with a fixed server time and a
//! fresh nonce store per input, so a finding reproduces exactly.
//!
//! Input: fields separated by NUL: mode, method, path, body, timestamp,
//! nonce, signature. Mode byte 1 replaces the signature with the correct
//! one for the other fields, so the checks after the MAC are reached.
//!
//! Invariants: a request is accepted only with the correct MAC, a timestamp
//! within 300 s and a well-formed nonce; the same nonce is never accepted
//! twice.

#![no_main]

use http::{HeaderMap, HeaderValue};
use kavach_api::hmac_auth::{sign, string_to_sign, verify, NonceCache, MAX_SKEW_SECONDS};
use libfuzzer_sys::fuzz_target;

const SECRET: &str = "fuzz-hmac-secret";
const NOW: i64 = 1_790_000_000;

fn text(bytes: &[u8]) -> Option<&str> {
    std::str::from_utf8(bytes).ok()
}

fuzz_target!(|data: &[u8]| {
    let fields: Vec<&[u8]> = data.splitn(7, |b| *b == 0).collect();
    let [mode, method, path, body, timestamp, nonce, signature] = fields.as_slice() else {
        return;
    };
    let (Some(method), Some(path), Some(timestamp), Some(nonce)) =
        (text(method), text(path), text(timestamp), text(nonce))
    else {
        return;
    };
    let expected = sign(SECRET, &string_to_sign(timestamp, nonce, method, path, body));
    let signature: &[u8] = if mode.first() == Some(&1) {
        expected.as_bytes()
    } else {
        signature
    };
    let mut headers = HeaderMap::new();
    for (name, value) in [
        ("x-kavach-signature", signature),
        ("x-kavach-timestamp", timestamp.as_bytes()),
        ("x-kavach-nonce", nonce.as_bytes()),
    ] {
        let Ok(value) = HeaderValue::from_bytes(value) else {
            return;
        };
        headers.insert(name, value);
    }
    let nonces = NonceCache::default();
    if verify(SECRET, &nonces, &headers, method, path, body, NOW).is_err() {
        return;
    }
    assert_eq!(signature, expected.as_bytes(), "accepted without the right MAC");
    let ts: i64 = timestamp.parse().expect("accepted timestamp parses");
    assert!(NOW.abs_diff(ts) <= MAX_SKEW_SECONDS.unsigned_abs(), "stale timestamp accepted");
    assert!(
        (16..=128).contains(&nonce.len())
            && nonce.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "malformed nonce accepted"
    );
    assert!(
        verify(SECRET, &nonces, &headers, method, path, body, NOW).is_err(),
        "a nonce was accepted twice"
    );
});

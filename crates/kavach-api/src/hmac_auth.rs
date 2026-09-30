//! HMAC request signing v2 for `/v1/evaluate` (ADR-008).
//!
//! Headers: `X-Kavach-Timestamp` (unix seconds, within ±300 s of server time),
//! `X-Kavach-Nonce` (16–128 chars of `[A-Za-z0-9_-]`, single use) and
//! `X-Kavach-Signature: sha256=<hex>` over
//! `v2\n{timestamp}\n{nonce}\n{METHOD}\n{path?query}\n` followed by the raw
//! body. Body-only (v1) signatures no longer verify. HMAC is an optional
//! integrity/anti-replay layer for service callers; identity comes from the
//! OIDC token or mTLS certificate.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::http::HeaderMap;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::ApiError;

type HmacSha256 = Hmac<Sha256>;

pub const MAX_SKEW_SECONDS: i64 = 300;
const NONCE_TTL: Duration = Duration::from_secs(600);
const MAX_NONCES: usize = 100_000;

/// Remembers nonces for the replay window. When full (after pruning expired
/// entries) new requests are rejected rather than accepted unchecked.
#[derive(Debug, Default)]
pub struct NonceCache {
    seen: Mutex<HashMap<String, Instant>>,
}

impl NonceCache {
    /// Returns true if `nonce` was not seen within the TTL (and records it).
    pub fn check_and_insert(&self, nonce: &str) -> bool {
        let Ok(mut seen) = self.seen.lock() else {
            return false;
        };
        let now = Instant::now();
        if seen.len() >= MAX_NONCES {
            seen.retain(|_, at| now.duration_since(*at) < NONCE_TTL);
            if seen.len() >= MAX_NONCES {
                return false;
            }
        }
        match seen.get(nonce) {
            Some(at) if now.duration_since(*at) < NONCE_TTL => false,
            _ => {
                seen.insert(nonce.to_string(), now);
                true
            }
        }
    }
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

fn valid_nonce(nonce: &str) -> bool {
    (16..=128).contains(&nonce.len())
        && nonce
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
}

/// The exact bytes that are signed.
pub fn string_to_sign(
    timestamp: &str,
    nonce: &str,
    method: &str,
    path_and_query: &str,
    body: &[u8],
) -> Vec<u8> {
    let mut message =
        format!("v2\n{timestamp}\n{nonce}\n{method}\n{path_and_query}\n").into_bytes();
    message.extend_from_slice(body);
    message
}

pub fn sign(secret: &str, message: &[u8]) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(message);
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Verifies a v2 signature; `now_unix` is trusted server time.
pub fn verify(
    secret: &str,
    nonces: &NonceCache,
    headers: &HeaderMap,
    method: &str,
    path_and_query: &str,
    body: &[u8],
    now_unix: i64,
) -> Result<(), ApiError> {
    let signature = header(headers, "x-kavach-signature").ok_or(ApiError::Unauthorized)?;
    let timestamp = header(headers, "x-kavach-timestamp").ok_or(ApiError::Unauthorized)?;
    let nonce = header(headers, "x-kavach-nonce").ok_or(ApiError::Unauthorized)?;
    let ts: i64 = timestamp.parse().map_err(|_| ApiError::Unauthorized)?;
    if (now_unix - ts).abs() > MAX_SKEW_SECONDS || !valid_nonce(nonce) {
        return Err(ApiError::Unauthorized);
    }
    let expected = sign(
        secret,
        &string_to_sign(timestamp, nonce, method, path_and_query, body),
    );
    if !constant_time_eq(signature.as_bytes(), expected.as_bytes()) {
        return Err(ApiError::Unauthorized);
    }
    // Record the nonce only after the signature verifies, so unauthenticated
    // traffic cannot fill the cache.
    if nonces.check_and_insert(nonce) {
        Ok(())
    } else {
        Err(ApiError::Unauthorized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers(sig: &str, ts: i64, nonce: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-kavach-signature", HeaderValue::from_str(sig).unwrap());
        h.insert(
            "x-kavach-timestamp",
            HeaderValue::from_str(&ts.to_string()).unwrap(),
        );
        h.insert("x-kavach-nonce", HeaderValue::from_str(nonce).unwrap());
        h
    }

    /// Cross-language vector: `scripts/pilot-phase3.sh` (Python) must
    /// produce the same signature as the server.
    #[test]
    fn matches_pilot_script_vector() {
        let message = string_to_sign(
            "1790000000",
            "nonce-0123456789abcdef",
            "POST",
            "/v1/evaluate",
            b"{\"a\":1}\n",
        );
        assert_eq!(
            sign("s", &message),
            "sha256=4273571ba955aa97b352c1878ba077b08941f20aa362a46deb06d2e38ad91f1d"
        );
    }

    #[test]
    fn v2_signatures_verify_once_and_bind_method_path_time() {
        let secret = "s3cret";
        let body = br#"{"a":1}"#;
        let nonce = "nonce-0123456789abcdef";
        let now = 1_790_000_000;
        let sig = sign(
            secret,
            &string_to_sign(&now.to_string(), nonce, "POST", "/v1/evaluate", body),
        );
        let cache = NonceCache::default();

        let ok = verify(
            secret,
            &cache,
            &headers(&sig, now, nonce),
            "POST",
            "/v1/evaluate",
            body,
            now,
        );
        assert!(ok.is_ok());
        // Replay of the same nonce.
        assert!(verify(
            secret,
            &cache,
            &headers(&sig, now, nonce),
            "POST",
            "/v1/evaluate",
            body,
            now
        )
        .is_err());

        let fresh = NonceCache::default();
        // Different path, stale timestamp, v1 body-only signature.
        assert!(verify(
            secret,
            &fresh,
            &headers(&sig, now, nonce),
            "POST",
            "/v1/other",
            body,
            now
        )
        .is_err());
        assert!(verify(
            secret,
            &fresh,
            &headers(&sig, now, nonce),
            "POST",
            "/v1/evaluate",
            body,
            now + 301
        )
        .is_err());
        let v1 = sign(secret, body);
        assert!(verify(
            secret,
            &fresh,
            &headers(&v1, now, nonce),
            "POST",
            "/v1/evaluate",
            body,
            now
        )
        .is_err());
        // Malformed nonce.
        assert!(verify(
            secret,
            &fresh,
            &headers(&sig, now, "short"),
            "POST",
            "/v1/evaluate",
            body,
            now
        )
        .is_err());
    }
}

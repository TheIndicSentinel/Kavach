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
use std::future::Future;
use std::sync::{
    atomic::{AtomicI64, Ordering},
    Mutex,
};
use std::time::{Duration, Instant};

use axum::http::HeaderMap;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use kavach_ports::{ErrorClass, PortError, ReplayGuard};
use kavach_storage::{PostgresReplayGuard, StoragePool};

use crate::error::ApiError;

pub const MAX_SKEW_SECONDS: i64 = 300;
// Keep a nonce through the full inclusive past/future timestamp window. The
// extra second means a request timestamp exactly at the skew boundary cannot
// become replayable when the reservation expires at that same instant.
const NONCE_TTL: Duration = Duration::from_secs(MAX_SKEW_SECONDS.unsigned_abs() * 2 + 1);
const MAX_NONCES: usize = 100_000;
const POSTGRES_PURGE_INTERVAL_SECONDS: i64 = 300;
const HMAC_NONCE_PREFIX: &str = "hmac-v2:evaluate:";

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

impl ReplayGuard for NonceCache {
    fn check_and_record(
        &self,
        tenant_id: &str,
        key: &str,
        now: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> impl Future<Output = Result<(), PortError>> + Send {
        let result = if expires_at <= now {
            Err(PortError::invalid("nonce expiry must be in the future"))
        } else if self.check_and_insert(&format!("{tenant_id}:{key}")) {
            Ok(())
        } else {
            Err(PortError::rejected("request nonce was already used"))
        };
        std::future::ready(result)
    }
}

/// Runtime-selected replay protection. Database-backed APIs share nonce
/// reservations through Postgres; development mode keeps the bounded cache.
pub enum HmacNonceBackend {
    Memory(NonceCache),
    Postgres {
        guard: PostgresReplayGuard,
        last_purge_at: AtomicI64,
    },
}

impl HmacNonceBackend {
    #[must_use]
    pub fn from_pool(pool: Option<&StoragePool>) -> Self {
        pool.map_or_else(
            || Self::Memory(NonceCache::default()),
            |pool| Self::Postgres {
                guard: pool.replay_guard(),
                last_purge_at: AtomicI64::new(0),
            },
        )
    }
}

impl ReplayGuard for HmacNonceBackend {
    async fn check_and_record(
        &self,
        tenant_id: &str,
        key: &str,
        now: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<(), PortError> {
        match self {
            Self::Memory(cache) => {
                cache
                    .check_and_record(tenant_id, key, now, expires_at)
                    .await
            }
            Self::Postgres {
                guard,
                last_purge_at,
            } => {
                let reserved = guard
                    .check_and_record(tenant_id, key, now, expires_at)
                    .await;
                let previous = last_purge_at.load(Ordering::Relaxed);
                let purge_due =
                    now.timestamp().saturating_sub(previous) >= POSTGRES_PURGE_INTERVAL_SECONDS;
                if purge_due
                    && last_purge_at
                        .compare_exchange(
                            previous,
                            now.timestamp(),
                            Ordering::Relaxed,
                            Ordering::Relaxed,
                        )
                        .is_ok()
                {
                    if let Err(error) = guard.purge_expired(now).await {
                        tracing::warn!(error = %error, "could not purge expired replay reservations");
                    }
                }
                reserved
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
    // `ring` takes a key of any length and cannot fail, so there is no
    // error to handle and nothing here that could panic on a request.
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
    format!(
        "sha256={}",
        hex::encode(ring::hmac::sign(&key, message).as_ref())
    )
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Inputs to HMAC verification; kept together so signing context cannot be
/// accidentally omitted when replay protection changes backends.
pub struct HmacVerification<'a> {
    pub tenant_id: &'a str,
    pub headers: &'a HeaderMap,
    pub method: &'a str,
    pub path_and_query: &'a str,
    pub body: &'a [u8],
    pub now: DateTime<Utc>,
}

/// Verifies a v2 signature; `request.now` is trusted server time.
pub async fn verify<G: ReplayGuard>(
    secret: &str,
    nonces: &G,
    request: HmacVerification<'_>,
) -> Result<(), ApiError> {
    let HmacVerification {
        tenant_id,
        headers,
        method,
        path_and_query,
        body,
        now,
    } = request;
    let signature = header(headers, "x-kavach-signature").ok_or(ApiError::Unauthorized)?;
    let timestamp = header(headers, "x-kavach-timestamp").ok_or(ApiError::Unauthorized)?;
    let nonce = header(headers, "x-kavach-nonce").ok_or(ApiError::Unauthorized)?;
    let ts: i64 = timestamp.parse().map_err(|_| ApiError::Unauthorized)?;
    // `abs_diff`: the caller chooses `ts`, and a subtraction could overflow.
    if now.timestamp().abs_diff(ts) > MAX_SKEW_SECONDS.unsigned_abs() || !valid_nonce(nonce) {
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
    let key = format!("{HMAC_NONCE_PREFIX}{nonce}");
    let expires_at = now
        .checked_add_signed(ChronoDuration::from_std(NONCE_TTL).expect("valid nonce TTL"))
        .ok_or_else(|| ApiError::Internal("HMAC nonce expiry overflow".into()))?;
    match nonces
        .check_and_record(tenant_id, &key, now, expires_at)
        .await
    {
        Ok(()) => Ok(()),
        Err(error) if error.class == ErrorClass::Rejected => Err(ApiError::Unauthorized),
        Err(error) if error.class == ErrorClass::Unavailable => Err(ApiError::Unavailable(
            "HMAC replay protection is unavailable".into(),
        )),
        Err(_) => Err(ApiError::Internal("HMAC nonce reservation failed".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    struct UnavailableReplayGuard;

    impl ReplayGuard for UnavailableReplayGuard {
        fn check_and_record(
            &self,
            _tenant_id: &str,
            _key: &str,
            _now: DateTime<Utc>,
            _expires_at: DateTime<Utc>,
        ) -> impl Future<Output = Result<(), PortError>> + Send {
            std::future::ready(Err(PortError::unavailable("test replay store unavailable")))
        }
    }

    fn verification<'a>(
        tenant_id: &'a str,
        headers: &'a HeaderMap,
        method: &'a str,
        path_and_query: &'a str,
        body: &'a [u8],
        now: DateTime<Utc>,
    ) -> HmacVerification<'a> {
        HmacVerification {
            tenant_id,
            headers,
            method,
            path_and_query,
            body,
            now,
        }
    }

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

    /// The signature takes a key of any length and cannot fail: there is no
    /// panic to reach with any secret. Known answers: HMAC-SHA256 of the empty
    /// message under the empty key, and RFC 4231 test case 2.
    #[test]
    fn signing_accepts_any_key_length() {
        assert_eq!(
            sign("", b""),
            "sha256=b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"
        );
        assert_eq!(
            sign("Jefe", b"what do ya want for nothing?"),
            "sha256=5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        for length in [0, 1, 31, 32, 64, 65, 4096, 1 << 20] {
            let secret = "k".repeat(length);
            assert!(sign(&secret, b"m").starts_with("sha256="), "{length}");
        }
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
    fn nonce_retention_covers_the_inclusive_timestamp_skew_window() {
        assert!(NONCE_TTL > Duration::from_secs(MAX_SKEW_SECONDS.unsigned_abs() * 2));
    }

    #[tokio::test]
    async fn v2_signatures_verify_once_and_bind_method_path_time() {
        let secret = "s3cret";
        let body = br#"{"a":1}"#;
        let nonce = "nonce-0123456789abcdef";
        let now = 1_790_000_000;
        let now_utc = DateTime::from_timestamp(now, 0).expect("test timestamp");
        let sig = sign(
            secret,
            &string_to_sign(&now.to_string(), nonce, "POST", "/v1/evaluate", body),
        );
        let cache = NonceCache::default();

        let ok = verify(
            secret,
            &cache,
            verification(
                "tenant-a",
                &headers(&sig, now, nonce),
                "POST",
                "/v1/evaluate",
                body,
                now_utc,
            ),
        )
        .await;
        assert!(ok.is_ok());
        // Replay of the same nonce.
        assert!(verify(
            secret,
            &cache,
            verification(
                "tenant-a",
                &headers(&sig, now, nonce),
                "POST",
                "/v1/evaluate",
                body,
                now_utc,
            )
        )
        .await
        .is_err());

        let fresh = NonceCache::default();
        // Different path, stale timestamp, v1 body-only signature.
        assert!(verify(
            secret,
            &fresh,
            verification(
                "tenant-a",
                &headers(&sig, now, nonce),
                "POST",
                "/v1/other",
                body,
                now_utc,
            )
        )
        .await
        .is_err());
        assert!(verify(
            secret,
            &fresh,
            verification(
                "tenant-a",
                &headers(&sig, now, nonce),
                "POST",
                "/v1/evaluate",
                body,
                now_utc + ChronoDuration::seconds(301),
            )
        )
        .await
        .is_err());
        let v1 = sign(secret, body);
        assert!(verify(
            secret,
            &fresh,
            verification(
                "tenant-a",
                &headers(&v1, now, nonce),
                "POST",
                "/v1/evaluate",
                body,
                now_utc,
            )
        )
        .await
        .is_err());
        // Malformed nonce.
        assert!(verify(
            secret,
            &fresh,
            verification(
                "tenant-a",
                &headers(&sig, now, "short"),
                "POST",
                "/v1/evaluate",
                body,
                now_utc,
            )
        )
        .await
        .is_err());
    }

    /// The skew check must not overflow on an extreme timestamp. Before
    /// `abs_diff`, `now - ts` panicked with overflow checks on and, without
    /// them, wrapped so that one timestamp passed the skew check.
    #[tokio::test]
    async fn extreme_timestamps_are_refused_without_overflow() {
        let (secret, nonce, body, now) = ("s", "nonce-0123456789abcdef", b"{}", 1_790_000_000_i64);
        let now_utc = DateTime::from_timestamp(now, 0).expect("test timestamp");
        for ts in [i64::MIN, i64::MAX, now.wrapping_add(i64::MIN), -1] {
            let sig = sign(
                secret,
                &string_to_sign(&ts.to_string(), nonce, "POST", "/v1/evaluate", body),
            );
            assert!(
                verify(
                    secret,
                    &NonceCache::default(),
                    verification(
                        "tenant-a",
                        &headers(&sig, ts, nonce),
                        "POST",
                        "/v1/evaluate",
                        body,
                        now_utc,
                    )
                )
                .await
                .is_err(),
                "{ts}"
            );
        }
    }

    #[tokio::test]
    async fn replay_store_outage_refuses_a_valid_signed_request() {
        let secret = "s3cret";
        let body = b"{}";
        let now = DateTime::from_timestamp(1_790_000_000, 0).expect("test timestamp");
        let nonce = "nonce-0123456789abcdef";
        let signature = sign(
            secret,
            &string_to_sign(
                &now.timestamp().to_string(),
                nonce,
                "POST",
                "/v1/evaluate",
                body,
            ),
        );

        let error = verify(
            secret,
            &UnavailableReplayGuard,
            verification(
                "tenant-a",
                &headers(&signature, now.timestamp(), nonce),
                "POST",
                "/v1/evaluate",
                body,
                now,
            ),
        )
        .await
        .expect_err("unavailable replay guard must fail closed");
        assert_eq!(
            error.status_code(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
    }
}

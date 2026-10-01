//! **PROTOCOL FIXTURE (D16).** A mock messaging provider that accepts only
//! Kavach resource credentials. It exists so the gateway, the end-to-end
//! tests and the network-isolation tests have a backend that enforces the
//! credential; it is not a real provider and is not shipped in the
//! production image.
//!
//! Real WhatsApp or SMS providers accept their own API tokens, not Kavach
//! credentials: for them the boundary is the gateway holding the provider
//! token plus network isolation (FR-4 proxy injection). Credential-bound
//! destinations exist only for backends that adopt the Kavach format.
//!
//! # Protocol
//!
//! `POST /v1/messages` with `Authorization: Kavach-Credential <JWE>` and
//! **no body**: destination, channel and template come from inside the
//! credential, so nothing can be added or redirected.
//!
//! Order: decrypt and verify (signature, audience) → idempotency on `jti`
//! (by a digest of the decrypted claims) → lifetime and `send_by` on this
//! provider's clock (with a small leeway that never extends `send_by`) →
//! deliver. A stored result is returned for an exact repeat, even after the
//! credential expired; nothing is ever delivered twice.
//!
//! | Status | Meaning | Gateway outcome |
//! |---|---|---|
//! | 202 `accepted` | delivered | `delivered` |
//! | 200 `replayed: true` | the stored result of an exact repeat | the stored outcome |
//! | 400, 401, 403, 422, 429 | refused; provably not delivered | `failed` |
//! | 409 `jti_conflict` | the `jti` was used for other claims: an anomaly | `unknown` + alert |
//! | 408, 5xx, no response after sending | not known | `unknown` (never retried) |
//!
//! Responses carry only `status`, `message_id`, `reason` and `replayed`;
//! never the destination.
//!
//! # Reserved synthetic numbers (test behaviour, like payment test cards)
//!
//! - [`REFUSE_NUMBER`]: refused by the "recipient" (422).
//! - [`ERROR_NUMBER`]: provider error (500), not delivered.
//! - [`HANG_NUMBER`]: delivered, then the response is delayed past any
//!   reasonable client timeout (a lost response).
//!
//! # Limits (fixture)
//!
//! State is in memory: a restart within a credential's lifetime forgets its
//! `jti`. The idempotency store fails closed when full (503), evicting only
//! entries past `exp` plus a grace period. The clock is this host's, not
//! trusted time.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration as StdDuration;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use kavach_credential::{
    check_time, claims_digest, decrypt_and_verify, CredentialClaims, DecryptionKey,
};
use kavach_jws::KeySet;
use kavach_ports::ErrorClass;
use serde::{Serialize, Serializer};

/// Refused by the recipient (422).
pub const REFUSE_NUMBER: &str = "+910000000998";
/// Delivered, then the response hangs.
pub const HANG_NUMBER: &str = "+910000000999";
/// Provider error (500), not delivered.
pub const ERROR_NUMBER: &str = "+910000000997";

pub const AUTH_SCHEME: &str = "Kavach-Credential";

pub type Clock = Arc<dyn Fn() -> DateTime<Utc> + Send + Sync>;

pub struct ProviderConfig {
    /// This provider's credential audience (e.g. `mock-messaging`).
    pub audience: String,
    pub encryption_key: DecryptionKey,
    /// Trusted credential signing keys.
    pub credential_keys: KeySet,
    /// Clock-skew tolerance on `iat`/`exp` (never extends `send_by`).
    pub leeway_seconds: i64,
    /// Most `jti`s remembered; full → 503 (fail closed).
    pub capacity: usize,
    /// Entries are evicted only this long after their `exp`.
    pub grace_seconds: i64,
    /// How long [`HANG_NUMBER`] delays its response.
    pub hang: StdDuration,
}

impl ProviderConfig {
    pub fn new(
        audience: impl Into<String>,
        encryption_key: DecryptionKey,
        credential_keys: KeySet,
    ) -> Self {
        Self {
            audience: audience.into(),
            encryption_key,
            credential_keys,
            leeway_seconds: 2,
            capacity: 100_000,
            grace_seconds: 300,
            hang: StdDuration::from_secs(30),
        }
    }
}

/// The reply body: allowlisted fields only.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Reply {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    pub replayed: bool,
}

/// A delivered message, for the inspection listener.
#[derive(Clone, Serialize)]
pub struct Delivered {
    pub message_id: String,
    pub jti: String,
    pub mandate_id: String,
    pub record_id: String,
    pub channel: String,
    pub template_id: String,
    /// Synthetic by construction (the resolver fixture holds no others).
    #[serde(serialize_with = "expose")]
    pub destination: kavach_ports::Destination,
    pub accepted_at: DateTime<Utc>,
}

fn expose<S: Serializer>(d: &kavach_ports::Destination, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(d.expose())
}

struct Stored {
    digest: String,
    exp: i64,
    status: StatusCode,
    reply: Reply,
}

#[derive(Default)]
struct Memory {
    by_jti: HashMap<String, Stored>,
    inbox: Vec<Delivered>,
}

pub struct MockProvider {
    config: ProviderConfig,
    clock: Clock,
    state: Mutex<Memory>,
}

/// A status and its allowlisted reply.
type Outcome = (StatusCode, Reply);

fn refusal(status: StatusCode, reason: &'static str) -> Outcome {
    (
        status,
        Reply {
            status: "refused",
            message_id: None,
            reason: Some(reason),
            replayed: false,
        },
    )
}

/// Request shape checks: no body or content headers, exactly one
/// `Authorization: Kavach-Credential <token>`, no unknown `Kavach-*`
/// headers. Standard headers (Host, User-Agent, traceparent…) are ignored.
fn credential_from(headers: &HeaderMap, body: &Bytes) -> Result<String, Outcome> {
    let has_length = headers
        .get(header::CONTENT_LENGTH)
        .is_some_and(|v| v.as_bytes() != b"0");
    if !body.is_empty()
        || has_length
        || headers.contains_key(header::TRANSFER_ENCODING)
        || headers.contains_key(header::CONTENT_TYPE)
    {
        return Err(refusal(StatusCode::BAD_REQUEST, "body_not_allowed"));
    }
    if headers
        .keys()
        .any(|name| name.as_str().starts_with("kavach-"))
    {
        return Err(refusal(StatusCode::BAD_REQUEST, "unknown_kavach_header"));
    }
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let (Some(value), None) = (values.next(), values.next()) else {
        return Err(refusal(StatusCode::UNAUTHORIZED, "credential_required"));
    };
    value
        .to_str()
        .ok()
        .and_then(|v| v.split_once(' '))
        .filter(|(scheme, token)| *scheme == AUTH_SCHEME && !token.is_empty())
        .map(|(_, token)| token.to_string())
        .ok_or_else(|| refusal(StatusCode::UNAUTHORIZED, "credential_required"))
}

/// What a destination does (reserved synthetic numbers), and whether it
/// counts as delivered.
fn behaviour(destination: &str, message_id: String) -> (Outcome, bool) {
    let (status, reply, delivered) = match destination {
        REFUSE_NUMBER => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Reply {
                status: "refused",
                message_id: None,
                reason: Some("recipient_refused"),
                replayed: false,
            },
            false,
        ),
        ERROR_NUMBER => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Reply {
                status: "error",
                message_id: None,
                reason: Some("provider_error"),
                replayed: false,
            },
            false,
        ),
        _ => (
            StatusCode::ACCEPTED,
            Reply {
                status: "accepted",
                message_id: Some(message_id),
                reason: None,
                replayed: false,
            },
            true,
        ),
    };
    ((status, reply), delivered)
}

impl MockProvider {
    pub fn new(config: ProviderConfig, clock: Clock) -> Arc<Self> {
        Arc::new(Self {
            config,
            clock,
            state: Mutex::new(Memory::default()),
        })
    }

    /// A provider on the system clock.
    pub fn with_system_clock(config: ProviderConfig) -> Arc<Self> {
        Self::new(config, Arc::new(Utc::now))
    }

    /// Delivered messages (inspection).
    pub fn inbox(&self) -> Vec<Delivered> {
        self.state
            .lock()
            .map(|s| s.inbox.clone())
            .unwrap_or_default()
    }

    /// Shape, decryption, signature and audience.
    fn admit(
        &self,
        headers: &HeaderMap,
        body: &Bytes,
    ) -> Result<(CredentialClaims, String), Outcome> {
        let token = credential_from(headers, body)?;
        let claims = decrypt_and_verify(
            &token,
            &self.config.credential_keys,
            &self.config.encryption_key,
            &self.config.audience,
        )
        .map_err(|err| {
            if err.class == ErrorClass::Invalid {
                refusal(StatusCode::BAD_REQUEST, "malformed_credential")
            } else {
                refusal(StatusCode::UNAUTHORIZED, "invalid_credential")
            }
        })?;
        let digest = claims_digest(&claims)
            .map_err(|_| refusal(StatusCode::BAD_REQUEST, "malformed_credential"))?;
        Ok((claims, digest))
    }

    /// Idempotency, time, capacity, then delivery; atomic under the lock.
    fn decide(&self, claims: &CredentialClaims, digest: String) -> Outcome {
        let now = (self.clock)();
        let Ok(mut state) = self.state.lock() else {
            return refusal(StatusCode::SERVICE_UNAVAILABLE, "provider_unavailable");
        };
        // Idempotency before the time checks: an exact repeat gets the
        // stored result even after expiry; nothing is delivered twice.
        if let Some(stored) = state.by_jti.get(&claims.jti) {
            if stored.digest != digest {
                return refusal(StatusCode::CONFLICT, "jti_conflict");
            }
            let status = if stored.status == StatusCode::ACCEPTED {
                StatusCode::OK
            } else {
                stored.status
            };
            return (
                status,
                Reply {
                    replayed: true,
                    ..stored.reply.clone()
                },
            );
        }
        if let Err(err) = check_time(claims, now, self.config.leeway_seconds) {
            let reason = if err.message.contains("send_by") {
                "past_send_by"
            } else {
                "credential_not_current"
            };
            return refusal(StatusCode::FORBIDDEN, reason);
        }
        let horizon = now.timestamp() - self.config.grace_seconds;
        state.by_jti.retain(|_, stored| stored.exp > horizon);
        if state.by_jti.len() >= self.config.capacity {
            // Fail closed: evicting a live entry would allow a second delivery.
            return refusal(StatusCode::SERVICE_UNAVAILABLE, "idempotency_store_full");
        }
        let message_id = format!("pm-{}", uuid::Uuid::new_v4().simple());
        let (outcome, delivered) = behaviour(claims.req.destination.expose(), message_id.clone());
        state.by_jti.insert(
            claims.jti.clone(),
            Stored {
                digest,
                exp: claims.exp,
                status: outcome.0,
                reply: outcome.1.clone(),
            },
        );
        if delivered {
            state.inbox.push(Delivered {
                message_id,
                jti: claims.jti.clone(),
                mandate_id: claims.mandate_id.clone(),
                record_id: claims.record_id.clone(),
                channel: claims.req.channel.clone(),
                template_id: claims.req.template_id.clone(),
                destination: claims.req.destination.clone(),
                accepted_at: now,
            });
        }
        outcome
    }

    async fn handle(&self, headers: &HeaderMap, body: &Bytes) -> Response {
        let (status, body) = match self.admit(headers, body) {
            Err(outcome) => outcome,
            Ok((claims, digest)) => {
                let (status, body) = self.decide(&claims, digest);
                tracing::info!(jti = %claims.jti, status = status.as_u16(), "message request");
                // A first delivery to the hang number loses its response.
                if status == StatusCode::ACCEPTED && claims.req.destination.expose() == HANG_NUMBER
                {
                    tokio::time::sleep(self.config.hang).await;
                }
                (status, body)
            }
        };
        (status, Json(body)).into_response()
    }
}

async fn send(
    State(provider): State<Arc<MockProvider>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    provider.handle(&headers, &body).await
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok", "fixture": true }))
}

/// The provider API (attach to the backend network only).
pub fn router(provider: Arc<MockProvider>) -> Router {
    Router::new()
        .route("/v1/messages", post(send))
        .route("/health", get(health))
        .layer(DefaultBodyLimit::max(1024))
        .with_state(provider)
}

/// Inspection (delivered messages, synthetic destinations): a separate
/// listener, loopback or backend network only.
pub fn inspect_router(provider: Arc<MockProvider>) -> Router {
    Router::new()
        .route(
            "/v1/inbox",
            get(|State(p): State<Arc<MockProvider>>| async move { Json(p.inbox()) }),
        )
        .with_state(provider)
}

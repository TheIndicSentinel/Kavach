//! Request-bound resource credentials (H5b, FR-4).
//!
//! A credential is a compact JWS (`typ: kavach-credential+jws`, EdDSA,
//! canonical JSON) signed with a **dedicated credential key**, separate from
//! the mandate and evidence keys. It binds:
//!
//! - the decision: `tenant`, `agent`, `mandate_id`, `record_id` (the
//!   evidence record), `jti` (the record's `credential_id`), `action`;
//! - the provider: `aud`;
//! - the request: `bind`, a salted SHA-256 over the canonical
//!   `{channel, destination, template_id}`, so a stolen credential cannot
//!   message anyone else or send anything else;
//! - time: `iat`, `exp` (at most 15 s, never after `send_by`), `send_by`.
//!
//! **The salt binds; it does not hide.** With the salt in the token, the
//! destination (about 10¹⁰ phone numbers) can be recovered by search. A
//! credential is a bearer secret that may reveal personal data: never log
//! it. Encrypting the destination to the provider's key (JWE, ECDH-ES) is a
//! P1 follow-up.
//!
//! [`JwsCredentialBroker`] issues; [`verify_credential`] is what a resource
//! provider runs (it needs only this crate and the public key).

use std::collections::{BTreeSet, HashMap};
use std::future::{ready, Future};
use std::sync::Mutex;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use kavach_jws::KeySet;
use kavach_ports::{
    CredentialBroker, CredentialRequest, Destination, IssuedCredential, KeyProvider, PortError,
    TokenSecret, MAX_CREDENTIAL_TTL_SECONDS,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const TYP_CREDENTIAL: &str = "kavach-credential+jws";
pub const BINDING_ALG: &str = "sha256-salted-v1";
const BINDING_PREFIX: &[u8] = b"kavach-credential-binding-v1\n";
const SALT_BYTES: usize = 16;
/// How long issued `jti`s are remembered (a working day covers `send_by`).
const JTI_RETENTION_HOURS: i64 = 24;
/// Fail closed rather than grow without bound.
const MAX_REMEMBERED_JTIS: usize = 1_000_000;
/// Clock skew a verifier tolerates on `iat`.
const IAT_SKEW_SECONDS: i64 = 5;

/// The salted request binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub alg: String,
    /// base64url, 16 random bytes.
    pub salt: String,
    /// Hex SHA-256.
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialClaims {
    pub iss: String,
    pub tenant: String,
    pub agent: String,
    pub mandate_id: String,
    pub record_id: String,
    pub jti: String,
    pub aud: String,
    pub action: String,
    pub bind: Binding,
    /// Unix seconds.
    pub iat: i64,
    pub exp: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub send_by: Option<i64>,
}

#[derive(Serialize)]
struct BoundRequest<'a> {
    channel: &'a str,
    destination: &'a str,
    template_id: &'a str,
}

/// `sha256(prefix ‖ salt ‖ JCS({channel, destination, template_id}))`, hex.
pub fn binding_digest(
    salt: &[u8],
    destination: &Destination,
    channel: &str,
    template_id: &str,
) -> Result<String, PortError> {
    let canonical = serde_json_canonicalizer::to_vec(&BoundRequest {
        channel,
        destination: destination.expose(),
        template_id,
    })
    .map_err(|e| PortError::invalid(format!("canonical binding: {e}")))?;
    let mut hasher = Sha256::new();
    hasher.update(BINDING_PREFIX);
    hasher.update(salt);
    hasher.update(canonical);
    Ok(hex::encode(hasher.finalize()))
}

/// What the resource provider expects of the credential on a request.
#[derive(Debug, Clone, Copy)]
pub struct Expected<'a> {
    pub audience: &'a str,
    pub destination: &'a Destination,
    pub channel: &'a str,
    pub template_id: &'a str,
    pub now: DateTime<Utc>,
}

/// Verifies a credential for one request: signature and `typ`, audience,
/// lifetime, `send_by`, and the request binding. `Rejected` when it does
/// not authorise this request; `Invalid` when it is malformed. Replay
/// (`jti`) is the provider's idempotency check, not this function's.
pub fn verify_credential(
    token: &str,
    keys: &KeySet,
    expected: &Expected<'_>,
) -> Result<CredentialClaims, PortError> {
    let (_, claims): (String, CredentialClaims) = kavach_jws::verify(token, TYP_CREDENTIAL, keys)?;
    let now = expected.now.timestamp();
    if claims.aud != expected.audience {
        return Err(PortError::rejected("credential is for another audience"));
    }
    if claims.iat > now + IAT_SKEW_SECONDS {
        return Err(PortError::rejected("credential issued in the future"));
    }
    if claims.exp - claims.iat > MAX_CREDENTIAL_TTL_SECONDS || claims.exp <= claims.iat {
        return Err(PortError::rejected("credential lifetime out of bounds"));
    }
    if now >= claims.exp {
        return Err(PortError::rejected("credential expired"));
    }
    if claims
        .send_by
        .is_some_and(|send_by| now >= send_by || claims.exp > send_by)
    {
        return Err(PortError::rejected("credential past send_by"));
    }
    if claims.bind.alg != BINDING_ALG {
        return Err(PortError::invalid("unsupported credential binding"));
    }
    let salt = URL_SAFE_NO_PAD
        .decode(&claims.bind.salt)
        .ok()
        .filter(|s| s.len() == SALT_BYTES)
        .ok_or_else(|| PortError::invalid("credential binding salt"))?;
    let digest = binding_digest(
        &salt,
        expected.destination,
        expected.channel,
        expected.template_id,
    )?;
    if digest != claims.bind.digest {
        return Err(PortError::rejected(
            "credential is bound to a different request",
        ));
    }
    Ok(claims)
}

#[derive(Default)]
struct State {
    /// `jti` → when it may be forgotten.
    issued: HashMap<String, DateTime<Utc>>,
    revoked: BTreeSet<(String, String)>,
}

/// Issues credentials as JWS signed with a dedicated credential key.
pub struct JwsCredentialBroker<K> {
    keys: K,
    kid: String,
    issuer: String,
    state: Mutex<State>,
}

fn check_id(what: &str, value: &str, max: usize) -> Result<(), PortError> {
    if value.is_empty() || value.len() > max {
        return Err(PortError::invalid(format!("{what} must be 1-{max} bytes")));
    }
    Ok(())
}

impl<K: KeyProvider> JwsCredentialBroker<K> {
    /// `kid` must name the credential key, never the mandate or evidence key.
    pub fn new(keys: K, kid: impl Into<String>, issuer: impl Into<String>) -> Self {
        Self {
            keys,
            kid: kid.into(),
            issuer: issuer.into(),
            state: Mutex::new(State::default()),
        }
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    fn validate(request: &CredentialRequest<'_>) -> Result<(), PortError> {
        for (what, value) in [
            ("tenant_id", request.tenant_id),
            ("agent_id", request.agent_id),
            ("mandate_id", request.mandate_id),
            ("record_id", request.record_id),
            ("credential_id", request.credential_id),
            ("audience", request.audience),
            ("action", request.action),
        ] {
            check_id(what, value, 128)?;
        }
        check_id("channel", request.channel, 64)?;
        check_id("template_id", request.template_id, 64)?;
        let destination = request.destination.expose();
        if destination.is_empty() || destination.len() > 256 {
            return Err(PortError::invalid("destination must be 1-256 bytes"));
        }
        Ok(())
    }

    /// The credential's expiry, or why none may be issued.
    fn expiry(request: &CredentialRequest<'_>) -> Result<DateTime<Utc>, PortError> {
        let now = request.now;
        if request.send_by.is_some_and(|send_by| now >= send_by) {
            return Err(PortError::rejected("no credential at or after send_by"));
        }
        let mut exp = request
            .expires_at
            .min(now + Duration::seconds(MAX_CREDENTIAL_TTL_SECONDS));
        if let Some(send_by) = request.send_by {
            exp = exp.min(send_by);
        }
        // Whole seconds (JWT NumericDate), rounded down.
        let exp = DateTime::from_timestamp(exp.timestamp(), 0).unwrap_or(exp);
        if exp.timestamp() <= now.timestamp() {
            return Err(PortError::rejected("the grant has expired"));
        }
        Ok(exp)
    }

    /// Reserves the `jti`, so it is issued at most once.
    fn reserve(&self, request: &CredentialRequest<'_>) -> Result<(), PortError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| PortError::unavailable("credential broker state poisoned"))?;
        if state.revoked.contains(&(
            request.tenant_id.to_string(),
            request.mandate_id.to_string(),
        )) {
            return Err(PortError::rejected("mandate revoked"));
        }
        let now = request.now;
        state.issued.retain(|_, forget_at| *forget_at > now);
        if state.issued.contains_key(request.credential_id) {
            return Err(PortError::rejected("credential_id already issued"));
        }
        if state.issued.len() >= MAX_REMEMBERED_JTIS {
            return Err(PortError::unavailable("credential broker jti store full"));
        }
        state.issued.insert(
            request.credential_id.to_string(),
            now + Duration::hours(JTI_RETENTION_HOURS),
        );
        Ok(())
    }

    fn release(&self, credential_id: &str) {
        if let Ok(mut state) = self.state.lock() {
            state.issued.remove(credential_id);
        }
    }

    async fn sign(
        &self,
        request: &CredentialRequest<'_>,
        exp: DateTime<Utc>,
    ) -> Result<TokenSecret, PortError> {
        let mut salt = [0u8; SALT_BYTES];
        getrandom::fill(&mut salt).map_err(|e| PortError::unavailable(format!("os rng: {e}")))?;
        let claims = CredentialClaims {
            iss: self.issuer.clone(),
            tenant: request.tenant_id.into(),
            agent: request.agent_id.into(),
            mandate_id: request.mandate_id.into(),
            record_id: request.record_id.into(),
            jti: request.credential_id.into(),
            aud: request.audience.into(),
            action: request.action.into(),
            bind: Binding {
                alg: BINDING_ALG.into(),
                salt: URL_SAFE_NO_PAD.encode(salt),
                digest: binding_digest(
                    &salt,
                    request.destination,
                    request.channel,
                    request.template_id,
                )?,
            },
            iat: request.now.timestamp(),
            exp: exp.timestamp(),
            send_by: request.send_by.map(|t| t.timestamp()),
        };
        let token = kavach_jws::sign(&self.keys, &self.kid, TYP_CREDENTIAL, &claims)
            .await
            .map_err(|e| {
                // A key store failure is a dependency failure, whatever its class.
                PortError::unavailable(format!("credential signing: {}", e.message))
            })?;
        Ok(TokenSecret::new(token))
    }
}

impl<K: KeyProvider> CredentialBroker for JwsCredentialBroker<K> {
    async fn issue(&self, request: &CredentialRequest<'_>) -> Result<IssuedCredential, PortError> {
        Self::validate(request)?;
        let exp = Self::expiry(request)?;
        self.reserve(request)?;
        match self.sign(request, exp).await {
            Ok(token) => Ok(IssuedCredential {
                credential_id: request.credential_id.to_string(),
                token,
                expires_at: exp,
            }),
            Err(err) => {
                self.release(request.credential_id);
                Err(err)
            }
        }
    }

    fn revoke_by_mandate(
        &self,
        tenant_id: &str,
        mandate_id: &str,
    ) -> impl Future<Output = Result<u64, PortError>> + Send {
        let result = self
            .state
            .lock()
            .map_err(|_| PortError::unavailable("credential broker state poisoned"))
            .map(|mut state| {
                state
                    .revoked
                    .insert((tenant_id.to_string(), mandate_id.to_string()));
                // Signed tokens cannot be recalled; they expire within 15 s.
                0
            });
        ready(result)
    }
}

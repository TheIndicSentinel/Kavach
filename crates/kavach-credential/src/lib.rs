//! Request-bound resource credentials (H5b, FR-4).
//!
//! A credential is a **nested JWT, signed then encrypted** (RFC 7519 §11.2,
//! RFC 8725 §3.11 explicit typing):
//!
//! - **Inner:** a JWS (`typ: kavach-credential+jws`, EdDSA, canonical JSON)
//!   signed with a dedicated credential key, separate from the mandate and
//!   evidence keys. It binds the decision (`tenant`, `agent`, `mandate_id`,
//!   the evidence `record_id`, `jti` = the record's `credential_id`,
//!   `action`), the provider (`aud`), time (`iat`, `exp` ≤ 15 s and ≤
//!   `send_by`, `send_by`) and the request itself (`req`: destination,
//!   channel, template).
//! - **Outer:** a JWE (`typ: kavach-credential+jwe`, `cty:
//!   kavach-credential+jws`; ECDH-ES on X25519 with A256GCM) addressed to
//!   the provider's encryption key.
//!
//! Only the provider can read the destination, and it takes the request
//! from the credential, so nothing in transit, in a log line or in a stolen
//! token reveals the destination or lets a request be redirected.
//!
//! [`JoseCredentialBroker`] issues; [`open_credential`] and
//! [`verify_credential`] are what a resource provider runs (they need only
//! this crate, the credential public key and the provider's own key).

pub mod jwe;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::future::{ready, Future};
use std::sync::Mutex;

use chrono::{DateTime, Duration, Utc};
use kavach_jws::KeySet;
use kavach_ports::{
    CredentialBroker, CredentialRequest, Destination, IssuedCredential, KeyProvider, PortError,
    TokenSecret, MAX_CREDENTIAL_TTL_SECONDS,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub use jwe::{DecryptionKey, RecipientKey};

pub const TYP_CREDENTIAL: &str = "kavach-credential+jws";
pub const TYP_CREDENTIAL_JWE: &str = "kavach-credential+jwe";
/// How long issued `jti`s are remembered (a working day covers `send_by`).
const JTI_RETENTION_HOURS: i64 = 24;
/// Fail closed rather than grow without bound.
const MAX_REMEMBERED_JTIS: usize = 1_000_000;
/// Clock skew a verifier tolerates on `iat`.
const IAT_SKEW_SECONDS: i64 = 5;

/// The request a credential authorises. Readable only inside the JWE.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestClaims {
    pub channel: String,
    #[serde(
        serialize_with = "ser_destination",
        deserialize_with = "de_destination"
    )]
    pub destination: Destination,
    pub template_id: String,
}

impl fmt::Debug for RequestClaims {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestClaims")
            .field("channel", &self.channel)
            .field("destination", &self.destination)
            .field("template_id", &self.template_id)
            .finish()
    }
}

fn ser_destination<S: Serializer>(value: &Destination, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(value.expose())
}

fn de_destination<'de, D: Deserializer<'de>>(d: D) -> Result<Destination, D::Error> {
    String::deserialize(d).map(Destination::new)
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
    pub req: RequestClaims,
    /// Unix seconds.
    pub iat: i64,
    pub exp: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub send_by: Option<i64>,
}

/// Decrypts the JWE addressed to `key`, verifies the inner JWS against the
/// trusted credential keys and checks the audience. No time checks: a
/// provider runs its idempotency lookup between this and [`check_time`],
/// so a stored result stays recoverable after expiry without ever allowing
/// a new delivery.
pub fn decrypt_and_verify(
    token: &str,
    signing_keys: &KeySet,
    key: &DecryptionKey,
    audience: &str,
) -> Result<CredentialClaims, PortError> {
    let jws = jwe::decrypt(token, key, TYP_CREDENTIAL_JWE, TYP_CREDENTIAL)?;
    let jws =
        std::str::from_utf8(&jws).map_err(|_| PortError::invalid("credential is not UTF-8"))?;
    let (_, claims): (String, CredentialClaims) =
        kavach_jws::verify(jws, TYP_CREDENTIAL, signing_keys)?;
    if claims.aud != audience {
        return Err(PortError::rejected("credential is for another audience"));
    }
    Ok(claims)
}

/// Lifetime and deadline checks at `now` on the verifier's clock.
/// `leeway_seconds` tolerates clock skew on `iat` and `exp` only; it never
/// extends `send_by` (a policy deadline), which it makes stricter instead.
pub fn check_time(
    claims: &CredentialClaims,
    now: DateTime<Utc>,
    leeway_seconds: i64,
) -> Result<(), PortError> {
    let now = now.timestamp();
    let leeway = leeway_seconds.max(0);
    if claims.exp - claims.iat > MAX_CREDENTIAL_TTL_SECONDS || claims.exp <= claims.iat {
        return Err(PortError::rejected("credential lifetime out of bounds"));
    }
    if claims.iat > now + IAT_SKEW_SECONDS + leeway {
        return Err(PortError::rejected("credential issued in the future"));
    }
    if now >= claims.exp + leeway {
        return Err(PortError::rejected("credential expired"));
    }
    if claims
        .send_by
        .is_some_and(|send_by| now + leeway >= send_by || claims.exp > send_by)
    {
        return Err(PortError::rejected("credential past send_by"));
    }
    Ok(())
}

/// Decrypts and verifies a credential presented to the provider `audience`
/// at `now`: JWE to the provider's key, JWS from a trusted credential key,
/// `aud`, lifetime and `send_by` (no leeway). The provider then delivers to
/// `claims.req` (destination, channel, template). Replay (`jti`) is the
/// provider's idempotency check, not this function's.
pub fn open_credential(
    token: &str,
    signing_keys: &KeySet,
    key: &DecryptionKey,
    audience: &str,
    now: DateTime<Utc>,
) -> Result<CredentialClaims, PortError> {
    let claims = decrypt_and_verify(token, signing_keys, key, audience)?;
    check_time(&claims, now, 0)?;
    Ok(claims)
}

/// Hex SHA-256 of the canonical (RFC 8785) claims: "the same credential"
/// for idempotency. Token bytes cannot serve, since every encryption of the
/// same claims differs.
pub fn claims_digest(claims: &CredentialClaims) -> Result<String, PortError> {
    use sha2::{Digest, Sha256};
    let canonical = kavach_ports::jcs::to_vec(claims)?;
    Ok(hex::encode(Sha256::digest(canonical)))
}

/// What a provider that also receives the request fields expects.
#[derive(Debug, Clone, Copy)]
pub struct Expected<'a> {
    pub audience: &'a str,
    pub destination: &'a Destination,
    pub channel: &'a str,
    pub template_id: &'a str,
    pub now: DateTime<Utc>,
}

/// [`open_credential`], then checks the credential authorises exactly this
/// request.
pub fn verify_credential(
    token: &str,
    signing_keys: &KeySet,
    key: &DecryptionKey,
    expected: &Expected<'_>,
) -> Result<CredentialClaims, PortError> {
    let claims = open_credential(token, signing_keys, key, expected.audience, expected.now)?;
    if claims.req.destination != *expected.destination
        || claims.req.channel != expected.channel
        || claims.req.template_id != expected.template_id
    {
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

/// Issues credentials: signed with a dedicated credential key, encrypted to
/// the audience's registered encryption key.
pub struct JoseCredentialBroker<K> {
    keys: K,
    kid: String,
    issuer: String,
    recipients: BTreeMap<String, RecipientKey>,
    state: Mutex<State>,
}

fn check_id(what: &str, value: &str, max: usize) -> Result<(), PortError> {
    if value.is_empty() || value.len() > max {
        return Err(PortError::invalid(format!("{what} must be 1-{max} bytes")));
    }
    Ok(())
}

impl<K: KeyProvider> JoseCredentialBroker<K> {
    /// `kid` must name the credential key, never the mandate or evidence
    /// key. `recipients` maps each provider audience to its encryption key;
    /// no credential is issued for an audience without one.
    pub fn new(
        keys: K,
        kid: impl Into<String>,
        issuer: impl Into<String>,
        recipients: BTreeMap<String, RecipientKey>,
    ) -> Self {
        Self {
            keys,
            kid: kid.into(),
            issuer: issuer.into(),
            recipients,
            state: Mutex::new(State::default()),
        }
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The signing key store (to check key separation at startup).
    pub fn keys(&self) -> &K {
        &self.keys
    }

    /// Audiences this broker can issue for.
    pub fn audiences(&self) -> impl Iterator<Item = &str> {
        self.recipients.keys().map(String::as_str)
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

    async fn seal(
        &self,
        request: &CredentialRequest<'_>,
        recipient: &RecipientKey,
        exp: DateTime<Utc>,
    ) -> Result<TokenSecret, PortError> {
        let claims = CredentialClaims {
            iss: self.issuer.clone(),
            tenant: request.tenant_id.into(),
            agent: request.agent_id.into(),
            mandate_id: request.mandate_id.into(),
            record_id: request.record_id.into(),
            jti: request.credential_id.into(),
            aud: request.audience.into(),
            action: request.action.into(),
            req: RequestClaims {
                channel: request.channel.into(),
                destination: request.destination.clone(),
                template_id: request.template_id.into(),
            },
            iat: request.now.timestamp(),
            exp: exp.timestamp(),
            send_by: request.send_by.map(|t| t.timestamp()),
        };
        let jws = TokenSecret::new(
            kavach_jws::sign(&self.keys, &self.kid, TYP_CREDENTIAL, &claims)
                .await
                .map_err(|e| {
                    // A key store failure is a dependency failure, whatever its class.
                    PortError::unavailable(format!("credential signing: {}", e.message))
                })?,
        );
        let sealed = jwe::encrypt(
            jws.expose().as_bytes(),
            recipient,
            TYP_CREDENTIAL_JWE,
            TYP_CREDENTIAL,
        )?;
        Ok(TokenSecret::new(sealed))
    }
}

impl<K: KeyProvider> CredentialBroker for JoseCredentialBroker<K> {
    async fn issue(&self, request: &CredentialRequest<'_>) -> Result<IssuedCredential, PortError> {
        Self::validate(request)?;
        let recipient = self.recipients.get(request.audience).ok_or_else(|| {
            PortError::invalid("no encryption key is registered for this audience")
        })?;
        let exp = Self::expiry(request)?;
        self.reserve(request)?;
        match self.seal(request, recipient, exp).await {
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

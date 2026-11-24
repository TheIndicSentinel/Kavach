//! OIDC / OAuth 2.0 JWT access-token verification (ADR-008, RFC 7519,
//! RFC 8725, RFC 9068).
//!
//! - Only asymmetric algorithms are accepted (RS256, PS256, ES256, EdDSA);
//!   `none` and HMAC algorithms are rejected.
//! - The header must be valid UTF-8 JSON, a JSON object (RFC 7515 §4). The
//!   JWT library skips unknown header members without checking their
//!   bytes, so this is checked first.
//! - `kid` is required and must be in the configured JWKS; the JWK's own
//!   `alg`, when present, must match the token header.
//! - `iss`, `aud`, `exp` and `nbf` are validated with a small leeway.
//! - JWKS comes from a file (fully offline) or an HTTPS URL at the bank's own
//!   identity provider (fetched at startup, refreshed periodically and — rate
//!   limited — on an unknown `kid`).
//! - Each JWK is decoded once, when the JWKS is loaded or refreshed, not on
//!   every token.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::jwk::{JwkSet, KeyAlgorithm};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde_json::{Map, Value};

const ALLOWED_ALGORITHMS: [Algorithm; 4] = [
    Algorithm::RS256,
    Algorithm::PS256,
    Algorithm::ES256,
    Algorithm::EdDSA,
];
const REFRESH_INTERVAL: Duration = Duration::from_secs(600);
const MIN_REFRESH_GAP: Duration = Duration::from_secs(60);
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_ID_LEN: usize = 256;

#[derive(Debug, Clone)]
pub enum JwksSource {
    File(PathBuf),
    Url(String),
}

#[derive(Debug, Clone)]
pub struct OidcConfig {
    pub issuer: String,
    pub audience: String,
    pub jwks: JwksSource,
    pub principal_claim: String,
    pub groups_claim: String,
    pub leeway_seconds: u64,
}

/// Identity established from a verified token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedToken {
    /// The configured principal claim: the display id the audit records.
    pub principal: String,
    /// The `sub` claim, which role bindings name (ADR-019); `None` when the
    /// token has none, so only group bindings can apply.
    pub subject: Option<String>,
    pub groups: Vec<String>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OidcError {
    #[error("token header: {0}")]
    Header(String),
    #[error("algorithm {0:?} not allowed")]
    Algorithm(Algorithm),
    #[error("token has no kid")]
    MissingKid,
    #[error("unknown signing key {0}")]
    UnknownKid(String),
    #[error("jwk algorithm does not match token")]
    KeyAlgorithmMismatch,
    #[error("token rejected: {0}")]
    Invalid(String),
    #[error("claim {0}: {1}")]
    Claim(String, String),
}

/// Whether a JWK that states `alg` may verify a token signed with `token`.
/// An exhaustive match on both enums (no wildcard, no string comparison): a
/// new variant in the library stops this compiling until it is decided. The
/// key-management algorithms of JWE (`RSA1_5`, `RSA-OAEP`…) sign nothing, so a
/// key that names one verifies no token, and neither does a key whose `alg`
/// the library does not know (`UNKNOWN_ALGORITHM`).
fn key_allows(key: KeyAlgorithm, token: Algorithm) -> bool {
    let signs_with = match key {
        KeyAlgorithm::HS256 => Algorithm::HS256,
        KeyAlgorithm::HS384 => Algorithm::HS384,
        KeyAlgorithm::HS512 => Algorithm::HS512,
        KeyAlgorithm::ES256 => Algorithm::ES256,
        KeyAlgorithm::ES384 => Algorithm::ES384,
        KeyAlgorithm::RS256 => Algorithm::RS256,
        KeyAlgorithm::RS384 => Algorithm::RS384,
        KeyAlgorithm::RS512 => Algorithm::RS512,
        KeyAlgorithm::PS256 => Algorithm::PS256,
        KeyAlgorithm::PS384 => Algorithm::PS384,
        KeyAlgorithm::PS512 => Algorithm::PS512,
        KeyAlgorithm::EdDSA => Algorithm::EdDSA,
        KeyAlgorithm::RSA1_5
        | KeyAlgorithm::RSA_OAEP
        | KeyAlgorithm::RSA_OAEP_256
        | KeyAlgorithm::UNKNOWN_ALGORITHM => return false,
    };
    signs_with == token
}

/// A JWK decoded for verification. A JWK that does not decode keeps its
/// error, so a token naming it is rejected exactly as before the cache.
struct VerifyingKey {
    algorithm: Option<KeyAlgorithm>,
    key: Result<Arc<DecodingKey>, String>,
}

/// Decoded keys by `kid`. As with `JwkSet::find`, the first JWK with a given
/// `kid` wins and a JWK without one can never be selected.
type KeySet = HashMap<String, VerifyingKey>;

fn decode_keys(jwks: &JwkSet) -> KeySet {
    let mut keys = KeySet::new();
    for jwk in &jwks.keys {
        if let Some(kid) = &jwk.common.key_id {
            keys.entry(kid.clone()).or_insert_with(|| VerifyingKey {
                algorithm: jwk.common.key_algorithm,
                key: DecodingKey::from_jwk(jwk)
                    .map(Arc::new)
                    .map_err(|e| e.to_string()),
            });
        }
    }
    keys
}

pub struct OidcVerifier {
    config: OidcConfig,
    keys: RwLock<KeySet>,
    last_refresh: Mutex<Instant>,
    client: Option<reqwest::Client>,
}

impl std::fmt::Debug for OidcVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcVerifier")
            .field("issuer", &self.config.issuer)
            .field("audience", &self.config.audience)
            .finish_non_exhaustive()
    }
}

impl OidcVerifier {
    /// The configured (and verified) token issuer.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.config.issuer
    }

    /// Loads the JWKS (file, or HTTPS fetch) and returns a ready verifier.
    pub async fn load(config: OidcConfig) -> Result<Arc<Self>, String> {
        let client = match &config.jwks {
            JwksSource::Url(url) => {
                if !url.starts_with("https://") {
                    return Err("--oidc-jwks-url must use https://".into());
                }
                Some(
                    reqwest::Client::builder()
                        .timeout(FETCH_TIMEOUT)
                        .https_only(true)
                        .build()
                        .map_err(|e| format!("jwks http client: {e}"))?,
                )
            }
            JwksSource::File(_) => None,
        };
        let verifier = Self {
            config,
            keys: RwLock::new(KeySet::new()),
            last_refresh: Mutex::new(Instant::now()),
            client,
        };
        let keys = verifier.fetch().await?;
        if keys.keys.is_empty() {
            return Err("JWKS contains no keys".into());
        }
        *verifier.keys.write().map_err(|_| "jwks lock poisoned")? = decode_keys(&keys);
        Ok(Arc::new(verifier))
    }

    /// Builds a verifier from an in-memory JWKS (tests, embedded setups).
    pub fn from_jwks(config: OidcConfig, keys: &JwkSet) -> Arc<Self> {
        Arc::new(Self {
            config,
            keys: RwLock::new(decode_keys(keys)),
            last_refresh: Mutex::new(Instant::now()),
            client: None,
        })
    }

    async fn fetch(&self) -> Result<JwkSet, String> {
        match (&self.config.jwks, &self.client) {
            (JwksSource::File(path), _) => {
                let text = std::fs::read_to_string(path)
                    .map_err(|e| format!("read JWKS {}: {e}", path.display()))?;
                serde_json::from_str(&text).map_err(|e| format!("parse JWKS: {e}"))
            }
            // The URL is named by scheme, host and port only, and the reqwest
            // error drops its copy: these errors reach stderr and the log, and
            // the rest of the URL can carry a credential.
            (JwksSource::Url(url), Some(client)) => {
                let shown = crate::hardening::shown_endpoint(url);
                client
                    .get(url)
                    .send()
                    .await
                    .and_then(reqwest::Response::error_for_status)
                    .map_err(|e| format!("fetch JWKS {shown}: {}", e.without_url()))?
                    .json::<JwkSet>()
                    .await
                    .map_err(|e| format!("parse JWKS {shown}: {}", e.without_url()))
            }
            (JwksSource::Url(_), None) => Err("JWKS URL client missing".into()),
        }
    }

    /// Re-fetches the JWKS; keeps the old keys if the fetch fails.
    pub async fn refresh(&self) -> Result<(), String> {
        let keys = self.fetch().await?;
        if keys.keys.is_empty() {
            return Err("refreshed JWKS contains no keys".into());
        }
        let keys = decode_keys(&keys);
        *self.keys.write().map_err(|_| "jwks lock poisoned")? = keys;
        Ok(())
    }

    /// Periodic refresh for URL-backed JWKS.
    pub fn spawn_refresher(self: &Arc<Self>) {
        if !matches!(self.config.jwks, JwksSource::Url(_)) {
            return;
        }
        let verifier = Arc::clone(self);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(REFRESH_INTERVAL);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                if let Err(e) = verifier.refresh().await {
                    tracing::warn!("JWKS refresh failed (keeping old keys): {e}");
                }
            }
        });
    }

    /// On an unknown `kid`, refresh in the background at most once a minute
    /// (key rotation at the identity provider).
    pub fn request_refresh(self: &Arc<Self>) {
        if !matches!(self.config.jwks, JwksSource::Url(_)) {
            return;
        }
        let Ok(mut last) = self.last_refresh.lock() else {
            return;
        };
        if last.elapsed() < MIN_REFRESH_GAP {
            return;
        }
        *last = Instant::now();
        drop(last);
        let verifier = Arc::clone(self);
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                if let Err(e) = verifier.refresh().await {
                    tracing::warn!("JWKS refresh failed: {e}");
                }
            });
        }
    }

    /// The checked header algorithm and the decoded key a token names: the
    /// header is UTF-8 JSON, the algorithm is allowed, the `kid` is known and
    /// its JWK allows the algorithm. Shared by access and ID tokens.
    fn signing_key(&self, token: &str) -> Result<(Algorithm, Arc<DecodingKey>), OidcError> {
        // RFC 7515 §4: the whole header is UTF-8 JSON, an object. Checked
        // before the library, which would skip invalid bytes in members it
        // does not know.
        let header_json = token
            .split('.')
            .next()
            .and_then(|part| URL_SAFE_NO_PAD.decode(part).ok())
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
        if !matches!(header_json, Some(Value::Object(_))) {
            return Err(OidcError::Header("not a JSON object in UTF-8".into()));
        }
        let header = decode_header(token).map_err(|e| OidcError::Header(e.to_string()))?;
        if !ALLOWED_ALGORITHMS.contains(&header.alg) {
            return Err(OidcError::Algorithm(header.alg));
        }
        let kid = header.kid.ok_or(OidcError::MissingKid)?;
        let keys = self
            .keys
            .read()
            .map_err(|_| OidcError::Invalid("jwks lock poisoned".into()))?;
        let entry = keys
            .get(&kid)
            .ok_or_else(|| OidcError::UnknownKid(kid.clone()))?;
        if let Some(alg) = entry.algorithm {
            if !key_allows(alg, header.alg) {
                return Err(OidcError::KeyAlgorithmMismatch);
            }
        }
        let key = Arc::clone(
            entry
                .key
                .as_ref()
                .map_err(|e| OidcError::Invalid(e.clone()))?,
        );
        Ok((header.alg, key))
    }

    /// Verifies an OpenID Connect ID token for the console login (ADR-018):
    /// the same issuer and keys as access tokens, `aud` = the console's
    /// client id (and `azp`, when present or when `aud` names several
    /// clients), and `nonce` = the one sent with the login. Nothing of the
    /// token is returned: the console identity comes from the access token,
    /// which is then verified with [`Self::verify`].
    pub fn verify_id_token(
        &self,
        token: &str,
        client_id: &str,
        nonce: &str,
    ) -> Result<(), OidcError> {
        let (alg, key) = self.signing_key(token)?;
        let mut validation = Validation::new(alg);
        validation.leeway = self.config.leeway_seconds;
        validation.validate_nbf = true;
        validation.set_issuer(&[self.config.issuer.as_str()]);
        validation.set_audience(&[client_id]);
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);
        let claims = decode::<Map<String, Value>>(token, &key, &validation)
            .map_err(|e| OidcError::Invalid(e.to_string()))?
            .claims;
        check_not_before(&claims, self.config.leeway_seconds)?;
        if claims.get("nonce").and_then(Value::as_str) != Some(nonce) {
            return Err(OidcError::Claim("nonce".into(), "does not match".into()));
        }
        let several = matches!(claims.get("aud"), Some(Value::Array(a)) if a.len() > 1);
        match claims.get("azp") {
            Some(Value::String(azp)) if azp == client_id => Ok(()),
            None if !several => Ok(()),
            _ => Err(OidcError::Claim("azp".into(), "is not this client".into())),
        }
    }

    /// Verifies a bearer token and extracts the principal and groups.
    pub fn verify(&self, token: &str) -> Result<VerifiedToken, OidcError> {
        let (alg, key) = self.signing_key(token)?;
        let mut validation = Validation::new(alg);
        validation.leeway = self.config.leeway_seconds;
        validation.validate_nbf = true;
        validation.set_issuer(&[self.config.issuer.as_str()]);
        validation.set_audience(&[self.config.audience.as_str()]);
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);
        let claims = decode::<Map<String, Value>>(token, &key, &validation)
            .map_err(|e| OidcError::Invalid(e.to_string()))?
            .claims;
        check_not_before(&claims, self.config.leeway_seconds)?;

        let principal = claims
            .get(&self.config.principal_claim)
            .and_then(Value::as_str)
            .filter(|p| !p.is_empty() && p.len() <= MAX_ID_LEN)
            .ok_or_else(|| {
                OidcError::Claim(
                    self.config.principal_claim.clone(),
                    "missing or not a 1-256 character string".into(),
                )
            })?
            .to_string();
        // A `sub` no binding could name is treated as absent rather than
        // rejected: tokens accepted before ADR-019 stay accepted, and the
        // only effect is that no person binding applies.
        let subject = claims
            .get("sub")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty() && s.len() <= MAX_ID_LEN)
            .map(str::to_string);
        let groups = match claims.get(&self.config.groups_claim) {
            None | Some(Value::Null) => vec![],
            Some(Value::Array(items)) => items
                .iter()
                .map(|g| {
                    g.as_str().map(str::to_string).ok_or_else(|| {
                        OidcError::Claim(
                            self.config.groups_claim.clone(),
                            "non-string group".into(),
                        )
                    })
                })
                .collect::<Result<_, _>>()?,
            Some(_) => {
                return Err(OidcError::Claim(
                    self.config.groups_claim.clone(),
                    "must be an array of strings".into(),
                ))
            }
        };
        Ok(VerifiedToken {
            principal,
            subject,
            groups,
        })
    }
}

/// `jsonwebtoken` before 10.3 checked `nbf` only when it parsed as an
/// unsigned integer: a string or fractional `nbf` counted as absent, so its
/// check was skipped (GHSA-h395-gr6q-cpjc; `exp`, `iss` and `aud` are required
/// claims and are refused when malformed). Kept on 10.x so the refusal does
/// not depend on the library version: an integer is checked by the library,
/// any other number is compared here, and anything that is not a number is
/// refused.
fn check_not_before(claims: &Map<String, Value>, leeway_seconds: u64) -> Result<(), OidcError> {
    match claims.get("nbf") {
        None => Ok(()),
        Some(nbf) if nbf.is_u64() => Ok(()),
        Some(Value::Number(nbf)) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0.0, |d| d.as_secs_f64());
            let latest = now + f64::from(u32::try_from(leeway_seconds).unwrap_or(u32::MAX));
            match nbf.as_f64() {
                Some(nbf) if nbf.is_finite() && nbf <= latest => Ok(()),
                _ => Err(OidcError::Claim("nbf".into(), "is in the future".into())),
            }
        }
        Some(_) => Err(OidcError::Claim(
            "nbf".into(),
            "is not a NumericDate".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde_json::json;

    use super::*;

    const ISSUER: &str = "https://idp.test";
    const AUDIENCE: &str = "kavach-api";

    fn config(jwks: JwksSource) -> OidcConfig {
        OidcConfig {
            issuer: ISSUER.into(),
            audience: AUDIENCE.into(),
            jwks,
            principal_claim: "sub".into(),
            groups_claim: "groups".into(),
            leeway_seconds: 0,
        }
    }

    fn jwk(seed: u8, kid: &str) -> Value {
        let public = SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes();
        json!({ "kty": "OKP", "crv": "Ed25519", "x": URL_SAFE_NO_PAD.encode(public),
                "kid": kid, "alg": "EdDSA", "use": "sig" })
    }

    fn jwks(keys: &[Value]) -> JwkSet {
        serde_json::from_value(json!({ "keys": keys })).unwrap()
    }

    fn token(seed: u8, kid: &str) -> String {
        // PKCS#8 v1 DER for an Ed25519 private key (RFC 8410).
        let mut der = vec![
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ];
        der.extend_from_slice(&[seed; 32]);
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(kid.into());
        let now = chrono::Utc::now().timestamp();
        let claims = json!({ "iss": ISSUER, "aud": AUDIENCE, "sub": "alice",
                             "groups": ["ops"], "exp": now + 300 });
        encode(&header, &claims, &EncodingKey::from_ed_der(&der)).unwrap()
    }

    /// Every signing algorithm the library knows.
    const EVERY_ALGORITHM: [Algorithm; 12] = [
        Algorithm::HS256,
        Algorithm::HS384,
        Algorithm::HS512,
        Algorithm::ES256,
        Algorithm::ES384,
        Algorithm::RS256,
        Algorithm::RS384,
        Algorithm::RS512,
        Algorithm::PS256,
        Algorithm::PS384,
        Algorithm::PS512,
        Algorithm::EdDSA,
    ];

    /// A token whose header names `alg` (as the text a token carries) and a
    /// key that exists, with no valid signature: only the algorithm check can
    /// decide the outcome before the signature is looked at.
    fn token_naming(alg: &str) -> String {
        let header =
            URL_SAFE_NO_PAD.encode(json!({ "alg": alg, "kid": "good", "typ": "JWT" }).to_string());
        let payload = URL_SAFE_NO_PAD.encode(r#"{"sub":"x"}"#);
        format!("{header}.{payload}.AAAA")
    }

    fn verifier() -> Arc<OidcVerifier> {
        OidcVerifier::from_jwks(
            config(JwksSource::File(PathBuf::new())),
            &jwks(&[jwk(1, "good")]),
        )
    }

    /// Only RS256, PS256, ES256 and EdDSA are accepted; every other algorithm
    /// the library knows is refused by name before any key is looked up, and
    /// so are the spellings of "none" and anything that is not an algorithm.
    #[test]
    fn only_four_algorithms_get_as_far_as_the_key() {
        let verifier = verifier();
        for alg in EVERY_ALGORITHM {
            let name = format!("{alg:?}");
            let result = verifier.verify(&token_naming(&name));
            if ALLOWED_ALGORITHMS.contains(&alg) {
                // Past the algorithm check: refused for the key or the
                // signature, never for the algorithm.
                assert!(
                    !matches!(result, Err(OidcError::Algorithm(_))),
                    "{name}: {result:?}"
                );
            } else {
                assert_eq!(result, Err(OidcError::Algorithm(alg)), "{name}");
            }
        }
        // The allowed set is exactly these four.
        assert_eq!(
            ALLOWED_ALGORITHMS,
            [
                Algorithm::RS256,
                Algorithm::PS256,
                Algorithm::ES256,
                Algorithm::EdDSA
            ]
        );
        for spelling in [
            "none", "None", "NONE", "nOnE", "", "HS257", "EdDSA ", "eddsa", "ES256K",
        ] {
            assert!(
                matches!(
                    verifier.verify(&token_naming(spelling)),
                    Err(OidcError::Header(_))
                ),
                "alg {spelling:?}"
            );
        }
        // No alg at all.
        let bare = format!(
            "{}.{}.AAAA",
            URL_SAFE_NO_PAD.encode(r#"{"kid":"good"}"#),
            URL_SAFE_NO_PAD.encode("{}")
        );
        assert!(matches!(verifier.verify(&bare), Err(OidcError::Header(_))));
    }

    /// A key that states an algorithm verifies only tokens of that algorithm,
    /// for every pair, and a key that states a key-management algorithm
    /// verifies none.
    #[test]
    fn a_key_algorithm_allows_only_its_own() {
        let key_algorithms = [
            (KeyAlgorithm::HS256, Some(Algorithm::HS256)),
            (KeyAlgorithm::HS384, Some(Algorithm::HS384)),
            (KeyAlgorithm::HS512, Some(Algorithm::HS512)),
            (KeyAlgorithm::ES256, Some(Algorithm::ES256)),
            (KeyAlgorithm::ES384, Some(Algorithm::ES384)),
            (KeyAlgorithm::RS256, Some(Algorithm::RS256)),
            (KeyAlgorithm::RS384, Some(Algorithm::RS384)),
            (KeyAlgorithm::RS512, Some(Algorithm::RS512)),
            (KeyAlgorithm::PS256, Some(Algorithm::PS256)),
            (KeyAlgorithm::PS384, Some(Algorithm::PS384)),
            (KeyAlgorithm::PS512, Some(Algorithm::PS512)),
            (KeyAlgorithm::EdDSA, Some(Algorithm::EdDSA)),
            (KeyAlgorithm::RSA1_5, None),
            (KeyAlgorithm::RSA_OAEP, None),
            (KeyAlgorithm::RSA_OAEP_256, None),
            (KeyAlgorithm::UNKNOWN_ALGORITHM, None),
        ];
        for (key, own) in key_algorithms {
            for token in EVERY_ALGORITHM {
                assert_eq!(
                    key_allows(key, token),
                    Some(token) == own,
                    "{key:?} vs {token:?}"
                );
            }
        }
    }

    /// An HS256 token that names a real key, however it is signed (even with
    /// the public key as the secret), never verifies: the algorithm is refused
    /// first.
    #[test]
    fn an_hs256_token_signed_with_the_public_key_is_refused() {
        use jsonwebtoken::EncodingKey;
        let public = SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes();
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("good".into());
        let now = chrono::Utc::now().timestamp();
        let claims = json!({ "iss": ISSUER, "aud": AUDIENCE, "sub": "mallory", "exp": now + 300 });
        let forged = encode(&header, &claims, &EncodingKey::from_secret(&public)).unwrap();
        assert_eq!(
            verifier().verify(&forged),
            Err(OidcError::Algorithm(Algorithm::HS256))
        );
    }

    /// A JWK that states `RS256` refuses an `EdDSA` token signed by a key of
    /// that kid, so a key cannot be used under another algorithm than the one
    /// it declares.
    #[test]
    fn a_jwk_that_states_another_algorithm_refuses_the_token() {
        let mut stated = jwk(1, "good");
        stated["alg"] = json!("RS256");
        let verifier =
            OidcVerifier::from_jwks(config(JwksSource::File(PathBuf::new())), &jwks(&[stated]));
        assert_eq!(
            verifier.verify(&token(1, "good")),
            Err(OidcError::KeyAlgorithmMismatch)
        );
    }

    #[test]
    fn a_key_that_does_not_decode_rejects_only_its_own_tokens() {
        let broken = json!({ "kty": "OKP", "crv": "Ed25519", "x": "not-base64!", "kid": "broken" });
        let verifier = OidcVerifier::from_jwks(
            config(JwksSource::File(PathBuf::new())),
            &jwks(&[broken, jwk(1, "good")]),
        );
        assert!(matches!(
            verifier.verify(&token(1, "broken")),
            Err(OidcError::Invalid(_))
        ));
        assert_eq!(
            verifier.verify(&token(1, "good")).unwrap(),
            VerifiedToken {
                principal: "alice".into(),
                subject: Some("alice".into()),
                groups: vec!["ops".into()]
            }
        );
    }

    #[test]
    fn the_first_key_with_a_kid_wins() {
        let verifier = OidcVerifier::from_jwks(
            config(JwksSource::File(PathBuf::new())),
            &jwks(&[jwk(1, "k"), jwk(2, "k")]),
        );
        assert!(verifier.verify(&token(1, "k")).is_ok());
        assert!(matches!(
            verifier.verify(&token(2, "k")),
            Err(OidcError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn a_refresh_replaces_the_decoded_keys() {
        let path = std::env::temp_dir().join(format!(
            "kavach-oidc-rotation-{}-{}.json",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::write(&path, json!({ "keys": [jwk(1, "old")] }).to_string()).unwrap();
        let verifier = OidcVerifier::load(config(JwksSource::File(path.clone())))
            .await
            .unwrap();
        assert!(verifier.verify(&token(1, "old")).is_ok());
        assert_eq!(
            verifier.verify(&token(2, "new")),
            Err(OidcError::UnknownKid("new".into()))
        );

        std::fs::write(&path, json!({ "keys": [jwk(2, "new")] }).to_string()).unwrap();
        verifier.refresh().await.unwrap();
        assert!(verifier.verify(&token(2, "new")).is_ok());
        assert_eq!(
            verifier.verify(&token(1, "old")),
            Err(OidcError::UnknownKid("old".into()))
        );

        // A refresh that fails keeps the keys it had.
        std::fs::write(&path, json!({ "keys": [] }).to_string()).unwrap();
        assert!(verifier.refresh().await.is_err());
        assert!(verifier.verify(&token(2, "new")).is_ok());
        std::fs::remove_file(&path).ok();
    }

    /// A token signed over raw header and claims bytes.
    fn raw_token(seed: u8, header: &[u8], claims: &[u8]) -> String {
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(claims)
        );
        let signature = SigningKey::from_bytes(&[seed; 32]).sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }

    /// GHSA-h395-gr6q-cpjc: a signed token whose `nbf` is a string or a
    /// fraction is not left unchecked. A future `nbf` is refused in every
    /// form, a string `nbf` is refused even in the past, a past fractional
    /// `nbf` is accepted like an integer one, and a negative `nbf` (no
    /// NumericDate a provider issues) is refused.
    #[test]
    fn a_malformed_not_before_is_never_skipped() {
        let verifier = verifier();
        let now = chrono::Utc::now().timestamp();
        let header = br#"{"alg":"EdDSA","kid":"good"}"#;
        let with_nbf = |nbf: Value| {
            let claims = json!({ "iss": ISSUER, "aud": AUDIENCE, "sub": "alice",
                                 "exp": now + 300, "nbf": nbf });
            verifier.verify(&raw_token(1, header, claims.to_string().as_bytes()))
        };
        let future = now + 3600;
        let fraction = |secs: i64| serde_json::from_str::<Value>(&format!("{secs}.5")).unwrap();
        for nbf in [
            json!(future),
            json!(future.to_string()),
            fraction(future),
            json!((now - 60).to_string()),
            json!(null),
            json!(true),
            json!(-1),
        ] {
            assert!(with_nbf(nbf.clone()).is_err(), "nbf {nbf} was accepted");
        }
        assert!(with_nbf(json!(now - 60)).is_ok());
        assert!(with_nbf(fraction(now - 60)).is_ok());
    }

    /// Found by the `agent_token` fuzz target: a correctly signed token whose
    /// header holds a byte that is not UTF-8 in a member the library does
    /// not know. RFC 7515 §4 requires UTF-8 JSON, so it is refused.
    #[test]
    fn a_header_that_is_not_utf8_json_is_refused_even_when_signed() {
        let verifier = OidcVerifier::from_jwks(
            config(JwksSource::File(PathBuf::new())),
            &jwks(&[jwk(1, "good")]),
        );
        let now = chrono::Utc::now().timestamp();
        let claims =
            json!({ "iss": ISSUER, "aud": AUDIENCE, "sub": "alice", "exp": now + 300 }).to_string();
        let good = br#"{"alg":"EdDSA","kid":"good"}"#;
        assert!(verifier
            .verify(&raw_token(1, good, claims.as_bytes()))
            .is_ok());
        for header in [
            &b"{\"alg\":\"EdDSA\",\"kid\":\"good\",\"x\":\"a\x84t\"}"[..],
            &br#"["EdDSA"]"#[..],
            &b"{\"alg\":\"EdDSA\",\"kid\":\"good\"} trailing"[..],
        ] {
            assert!(
                matches!(
                    verifier.verify(&raw_token(1, header, claims.as_bytes())),
                    Err(OidcError::Header(_))
                ),
                "{}",
                String::from_utf8_lossy(header)
            );
        }
    }
}

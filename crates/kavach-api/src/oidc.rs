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
    pub principal: String,
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
            (JwksSource::Url(url), Some(client)) => client
                .get(url)
                .send()
                .await
                .and_then(reqwest::Response::error_for_status)
                .map_err(|e| format!("fetch JWKS {url}: {e}"))?
                .json::<JwkSet>()
                .await
                .map_err(|e| format!("parse JWKS {url}: {e}")),
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

    /// Verifies a bearer token and extracts the principal and groups.
    pub fn verify(&self, token: &str) -> Result<VerifiedToken, OidcError> {
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
        let key = {
            let keys = self
                .keys
                .read()
                .map_err(|_| OidcError::Invalid("jwks lock poisoned".into()))?;
            let entry = keys
                .get(&kid)
                .ok_or_else(|| OidcError::UnknownKid(kid.clone()))?;
            if let Some(alg) = entry.algorithm {
                if format!("{alg:?}") != format!("{:?}", header.alg) {
                    return Err(OidcError::KeyAlgorithmMismatch);
                }
            }
            Arc::clone(
                entry
                    .key
                    .as_ref()
                    .map_err(|e| OidcError::Invalid(e.clone()))?,
            )
        };

        let mut validation = Validation::new(header.alg);
        validation.leeway = self.config.leeway_seconds;
        validation.validate_nbf = true;
        validation.set_issuer(&[self.config.issuer.as_str()]);
        validation.set_audience(&[self.config.audience.as_str()]);
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);
        let claims = decode::<Map<String, Value>>(token, &key, &validation)
            .map_err(|e| OidcError::Invalid(e.to_string()))?
            .claims;

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
        Ok(VerifiedToken { principal, groups })
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

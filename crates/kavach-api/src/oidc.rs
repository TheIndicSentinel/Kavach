//! OIDC / OAuth 2.0 JWT access-token verification (ADR-008, RFC 7519,
//! RFC 8725, RFC 9068).
//!
//! - Only asymmetric algorithms are accepted (RS256, PS256, ES256, EdDSA);
//!   `none` and HMAC algorithms are rejected.
//! - `kid` is required and must be in the configured JWKS; the JWK's own
//!   `alg`, when present, must match the token header.
//! - `iss`, `aud`, `exp` and `nbf` are validated with a small leeway.
//! - JWKS comes from a file (fully offline) or an HTTPS URL at the bank's own
//!   identity provider (fetched at startup, refreshed periodically and — rate
//!   limited — on an unknown `kid`).

use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::JwkSet;
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

pub struct OidcVerifier {
    config: OidcConfig,
    keys: RwLock<JwkSet>,
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
            keys: RwLock::new(JwkSet { keys: vec![] }),
            last_refresh: Mutex::new(Instant::now()),
            client,
        };
        let keys = verifier.fetch().await?;
        if keys.keys.is_empty() {
            return Err("JWKS contains no keys".into());
        }
        *verifier.keys.write().map_err(|_| "jwks lock poisoned")? = keys;
        Ok(Arc::new(verifier))
    }

    /// Builds a verifier from an in-memory JWKS (tests, embedded setups).
    pub fn from_jwks(config: OidcConfig, keys: JwkSet) -> Arc<Self> {
        Arc::new(Self {
            config,
            keys: RwLock::new(keys),
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
                    eprintln!("WARNING: kavach-api: JWKS refresh failed (keeping old keys): {e}");
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
                    eprintln!("WARNING: kavach-api: JWKS refresh failed: {e}");
                }
            });
        }
    }

    /// Verifies a bearer token and extracts the principal and groups.
    pub fn verify(&self, token: &str) -> Result<VerifiedToken, OidcError> {
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
            let jwk = keys
                .find(&kid)
                .ok_or_else(|| OidcError::UnknownKid(kid.clone()))?;
            if let Some(alg) = jwk.common.key_algorithm {
                if format!("{alg:?}") != format!("{:?}", header.alg) {
                    return Err(OidcError::KeyAlgorithmMismatch);
                }
            }
            DecodingKey::from_jwk(jwk).map_err(|e| OidcError::Invalid(e.to_string()))?
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

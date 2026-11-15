//! Console sign-in (ADR-018 option C): a backend-for-frontend on the
//! operator listener. The API runs the OpenID Connect authorization code
//! flow with PKCE as a confidential client, keeps the identity provider's
//! tokens in server memory, and gives the browser one opaque, `HttpOnly`
//! session cookie.
//!
//! - **Off unless configured.** Without `--console-client-id` nothing here
//!   runs: the `/auth/*` routes answer "not configured" and the cookie is
//!   never read.
//! - **Tokens never leave the server.** Access, refresh and ID tokens and the
//!   client secret are held as [`TokenSecret`] (redacted `Debug`, zeroed on
//!   drop). They are never logged, stored or sent to the browser. The ID
//!   token is dropped once verified.
//! - **One identity.** A request carrying the session cookie and no
//!   credential header gets the session's access token in front of the
//!   existing path ([`cookie_step`]): `verify_token`, Cedar and the
//!   `oidc:<issuer>#<subject>` identity are unchanged.
//! - **Refused before verification:** the cookie with `Authorization` or
//!   `X-Kavach-Principal` (400); without `X-Kavach-Console: 1`, or with a
//!   cross-site `Origin` or `Sec-Fetch-Site` (403).
//! - **Bounded.** Login records last at most ten minutes, are used once and
//!   are capped; the session table is capped, refuses new logins when full
//!   and never evicts a live session. Sessions end at the idle limit, at the
//!   absolute limit (a refresh never extends it), at logout, or when a
//!   refresh fails.
//! - Only the operator router mounts the routes and the cookie step: the
//!   agent and system-of-record routers never read the cookie.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration as StdDuration, Instant};

use axum::extract::{Query, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use kavach_ports::TokenSecret;
use reqwest::Url;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::config::ApiConfig;
use crate::oidc::{OidcError, OidcVerifier};
use crate::problem::Problem;
use crate::state::AppState;

/// The login cookie: binds the callback to the browser that started it.
pub const LOGIN_COOKIE: &str = "__Host-kavach_login";
/// The session cookie: an opaque 256-bit session id.
pub const SESSION_COOKIE: &str = "__Host-kavach_session";
/// The header every console request sends (a CSRF defence: a cross-site
/// form or image cannot set it).
pub const CONSOLE_HEADER: &str = "x-kavach-console";
/// Where the browser is sent after a refused login.
pub const SIGNIN_PATH: &str = "/signin";
/// The only path a redirect URI may name.
pub const CALLBACK_PATH: &str = "/auth/callback";

pub const DEFAULT_IDLE_MINUTES: u64 = 15;
pub const MIN_IDLE_MINUTES: u64 = 5;
pub const MAX_IDLE_MINUTES: u64 = 60;
pub const DEFAULT_ABSOLUTE_MINUTES: u64 = 8 * 60;
pub const MAX_ABSOLUTE_MINUTES: u64 = 12 * 60;
pub const DEFAULT_MAX_SESSIONS: usize = 1000;
pub const MAX_MAX_SESSIONS: usize = 10_000;
pub const DEFAULT_SCOPE: &str = "openid";
/// A login record lives at most this long (and the login cookie as long).
pub const LOGIN_TTL_SECONDS: i64 = 600;
/// Pending login records at most; a full table refuses new logins.
pub const MAX_PENDING_LOGINS: usize = 1000;
/// An access token is refreshed when it expires within this.
pub const REFRESH_MARGIN_SECONDS: i64 = 60;
const IDP_TIMEOUT: StdDuration = StdDuration::from_secs(10);
const MAX_IDP_RESPONSE_BYTES: usize = 64 * 1024;
const DEFAULT_EXPIRES_IN: i64 = 300;
const MAX_EXPIRES_IN: i64 = 3600;
const MIN_EXPIRES_IN: i64 = 1;
const MAX_SECRET_BYTES: usize = 4096;
/// Login and callback attempts: a token bucket for the whole process.
const LOGIN_RATE_PER_SECOND: f64 = 5.0;
const LOGIN_BURST: f64 = 20.0;

/// The identity provider endpoints the flow uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdpEndpoints {
    pub authorization: String,
    pub token: String,
    pub revocation: Option<String>,
    pub end_session: Option<String>,
}

/// The console sign-in settings, as configured.
#[derive(Debug, Clone)]
pub struct ConsoleLoginSettings {
    pub client_id: String,
    pub client_secret_file: PathBuf,
    /// The exact `https://<host>/auth/callback` registered at the IdP.
    pub redirect_uri: String,
    /// `None`: read once from `{issuer}/.well-known/openid-configuration`.
    pub endpoints: Option<IdpEndpoints>,
    pub scope: String,
    pub idle_minutes: u64,
    pub absolute_minutes: u64,
    /// Return the IdP's end-session URL from logout (off by default).
    pub idp_logout: bool,
    pub max_sessions: usize,
}

impl ConsoleLoginSettings {
    /// The defaults for everything but the client registration.
    #[must_use]
    pub fn new(client_id: &str, client_secret_file: PathBuf, redirect_uri: &str) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret_file,
            redirect_uri: redirect_uri.into(),
            endpoints: None,
            scope: DEFAULT_SCOPE.into(),
            idle_minutes: DEFAULT_IDLE_MINUTES,
            absolute_minutes: DEFAULT_ABSOLUTE_MINUTES,
            idp_logout: false,
            max_sessions: DEFAULT_MAX_SESSIONS,
        }
    }
}

/// An endpoint the flow may call or send the browser to: HTTPS (plain HTTP
/// only under `--insecure-dev`), a host, and no userinfo or fragment.
fn check_endpoint(flag: &str, value: &str, insecure_dev: bool) -> Result<(), String> {
    let url = Url::parse(value).map_err(|_| format!("{flag} is not a URL"))?;
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(format!(
            "{flag} must be a URL with a host and no userinfo or fragment"
        ));
    }
    match url.scheme() {
        "https" => Ok(()),
        "http" if insecure_dev => Ok(()),
        _ => Err(format!(
            "{flag} must use https:// (plain http only with --insecure-dev)"
        )),
    }
}

fn check_redirect_uri(value: &str, insecure_dev: bool) -> Result<Url, String> {
    let url = Url::parse(value).map_err(|_| "--console-redirect-uri is not a URL".to_string())?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != CALLBACK_PATH
    {
        return Err(format!(
            "--console-redirect-uri must be exactly https://<host>{CALLBACK_PATH}, with no \
             userinfo, query or fragment"
        ));
    }
    let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    match url.scheme() {
        "https" if url.host_str().is_some() => Ok(url),
        "http" if insecure_dev && loopback => Ok(url),
        "http" if insecure_dev => Err(
            "--console-redirect-uri may use plain http only for localhost, and only with \
             --insecure-dev"
                .into(),
        ),
        _ => Err(
            "--console-redirect-uri must use https:// (http://localhost only with --insecure-dev)"
                .into(),
        ),
    }
}

/// The startup refusals of ADR-018 §6.2 that need no network: run before
/// anything is built. Discovery adds the issuer check ([`ConsoleLogin::start`]).
pub fn validate(settings: &ConsoleLoginSettings, config: &ApiConfig) -> Result<(), String> {
    let Some(oidc) = &config.oidc else {
        return Err(
            "console login needs operator OIDC: set --oidc-issuer, --oidc-audience and \
                    --oidc-jwks-file or --oidc-jwks-url"
                .into(),
        );
    };
    let client_id = settings.client_id.trim();
    if client_id.is_empty() || client_id.len() > 256 || client_id != settings.client_id {
        return Err(
            "--console-client-id must be 1-256 characters with no surrounding space".into(),
        );
    }
    if settings.client_id == oidc.audience {
        return Err(
            "--console-client-id must differ from --oidc-audience (the operator audience)".into(),
        );
    }
    if config
        .dataplane
        .as_ref()
        .is_some_and(|dp| dp.agent_oidc.audience == settings.client_id)
    {
        return Err(
            "--console-client-id must differ from --agent-oidc-audience (the agent audience)"
                .into(),
        );
    }
    check_redirect_uri(&settings.redirect_uri, config.insecure_dev)?;
    if let Some(endpoints) = &settings.endpoints {
        check_endpoints(endpoints, config.insecure_dev)?;
    }
    let scopes: Vec<&str> = settings.scope.split(' ').collect();
    if !scopes.contains(&"openid") || scopes.iter().any(|s| s.is_empty()) {
        return Err("--console-scope must be space-separated scopes including openid".into());
    }
    if scopes.contains(&"offline_access") {
        return Err("--console-scope must not ask for offline_access".into());
    }
    if !(MIN_IDLE_MINUTES..=MAX_IDLE_MINUTES).contains(&settings.idle_minutes) {
        return Err(format!(
            "--console-session-idle-minutes must be {MIN_IDLE_MINUTES}-{MAX_IDLE_MINUTES}"
        ));
    }
    if settings.absolute_minutes > MAX_ABSOLUTE_MINUTES
        || settings.absolute_minutes < settings.idle_minutes
    {
        return Err(format!(
            "--console-session-absolute-minutes must be at most {MAX_ABSOLUTE_MINUTES} and at \
             least the idle limit"
        ));
    }
    if !(1..=MAX_MAX_SESSIONS).contains(&settings.max_sessions) {
        return Err(format!(
            "--console-max-sessions must be 1-{MAX_MAX_SESSIONS}"
        ));
    }
    Ok(())
}

fn check_endpoints(endpoints: &IdpEndpoints, insecure_dev: bool) -> Result<(), String> {
    check_endpoint(
        "the authorization endpoint",
        &endpoints.authorization,
        insecure_dev,
    )?;
    check_endpoint("the token endpoint", &endpoints.token, insecure_dev)?;
    if let Some(revocation) = &endpoints.revocation {
        check_endpoint("the revocation endpoint", revocation, insecure_dev)?;
    }
    if let Some(end_session) = &endpoints.end_session {
        check_endpoint("the end-session endpoint", end_session, insecure_dev)?;
    }
    Ok(())
}

/// Reads the client secret: one line, at most 4 KiB. Nothing of it is
/// printed on a failure.
pub fn read_client_secret(path: &Path) -> Result<TokenSecret, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|_| "the --console-client-secret-file file could not be read".to_string())?;
    let secret = TokenSecret::new(text);
    let value = secret.expose().trim();
    if value.is_empty() || value.len() > MAX_SECRET_BYTES || value.contains(['\r', '\n']) {
        return Err(
            "the --console-client-secret-file file must hold one non-empty line of at most 4 KiB"
                .into(),
        );
    }
    Ok(TokenSecret::new(value))
}

#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    revocation_endpoint: Option<String>,
    end_session_endpoint: Option<String>,
    code_challenge_methods_supported: Option<Vec<String>>,
}

/// Reads the endpoints once from the operator issuer's discovery document.
/// Its `issuer` must be the operator issuer exactly.
pub async fn discover(issuer: &str, insecure_dev: bool) -> Result<IdpEndpoints, String> {
    let url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    check_endpoint("the discovery URL", &url, insecure_dev)?;
    let client = idp_client(insecure_dev)?;
    let response =
        client.get(&url).send().await.map_err(|_| {
            "console login: the discovery document could not be fetched".to_string()
        })?;
    if !response.status().is_success() {
        return Err(format!(
            "console login: the discovery document answered {}",
            response.status().as_u16()
        ));
    }
    let body = read_bounded(response)
        .await
        .map_err(|()| "console login: the discovery document could not be read".to_string())?;
    let doc: Discovery = serde_json::from_slice(&body)
        .map_err(|_| "console login: the discovery document does not parse".to_string())?;
    if doc.issuer != issuer {
        return Err(
            "console login: the discovery document names another issuer than --oidc-issuer".into(),
        );
    }
    if doc
        .code_challenge_methods_supported
        .is_some_and(|methods| !methods.iter().any(|m| m == "S256"))
    {
        return Err("console login: the identity provider does not support PKCE S256".into());
    }
    let endpoints = IdpEndpoints {
        authorization: doc.authorization_endpoint,
        token: doc.token_endpoint,
        revocation: doc.revocation_endpoint,
        end_session: doc.end_session_endpoint,
    };
    check_endpoints(&endpoints, insecure_dev)?;
    Ok(endpoints)
}

fn idp_client(allow_plain_http: bool) -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(IDP_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .https_only(!allow_plain_http)
        .build()
        .map_err(|_| "console login: the HTTP client could not be built".to_string())
}

async fn read_bounded(mut response: reqwest::Response) -> Result<Vec<u8>, ()> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| ())? {
        if body.len() + chunk.len() > MAX_IDP_RESPONSE_BYTES {
            body.fill(0);
            return Err(());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Why a login was refused: the fixed `/signin?error=` codes. Nothing from
/// the identity provider is ever echoed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginError {
    /// `state`, `nonce`, the code or a token was refused.
    Failed,
    /// The login record expired or was already used.
    Expired,
    /// The session table is at its maximum.
    SessionsFull,
    /// The identity provider is unreachable, or login is not configured.
    Unavailable,
}

impl LoginError {
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Failed => "login_failed",
            Self::Expired => "login_expired",
            Self::SessionsFull => "sessions_full",
            Self::Unavailable => "login_unavailable",
        }
    }
}

/// The time source (a test injects its own).
pub type Clock = Arc<dyn Fn() -> DateTime<Utc> + Send + Sync>;

struct PendingLogin {
    state: String,
    nonce: TokenSecret,
    verifier: TokenSecret,
    created: DateTime<Utc>,
}

struct Tokens {
    access: TokenSecret,
    refresh: Option<TokenSecret>,
    access_expires: DateTime<Utc>,
    groups: Vec<String>,
}

struct Session {
    principal: String,
    absolute_expires: DateTime<Utc>,
    last_seen: Mutex<DateTime<Utc>>,
    /// One refresh at a time per session.
    tokens: tokio::sync::Mutex<Tokens>,
    /// A random reference for the audit log; never the cookie value.
    audit_ref: String,
}

/// What `/auth/session` returns: never a token.
#[derive(Debug, Clone, Serialize)]
pub struct SessionView {
    pub principal: String,
    pub groups: Vec<String>,
    pub expires_at: DateTime<Utc>,
    pub idle_expires_at: DateTime<Utc>,
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

/// The console sign-in at runtime.
pub struct ConsoleLogin {
    client_id: String,
    client_secret: TokenSecret,
    redirect_uri: String,
    /// `scheme://host[:port]` of the redirect URI: the console's origin.
    origin: String,
    endpoints: IdpEndpoints,
    scope: String,
    idle: Duration,
    absolute: Duration,
    idp_logout: bool,
    max_sessions: usize,
    http: reqwest::Client,
    clock: Clock,
    rng: SystemRandom,
    logins: Mutex<HashMap<[u8; 32], PendingLogin>>,
    sessions: Mutex<HashMap<[u8; 32], Arc<Session>>>,
    limiter: Mutex<Bucket>,
}

impl std::fmt::Debug for ConsoleLogin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsoleLogin")
            .field("client_id", &self.client_id)
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

fn digest(value: &str) -> [u8; 32] {
    Sha256::digest(value.as_bytes()).into()
}

/// RFC 6749 §2.3.1: the client id and secret are form-encoded before HTTP
/// Basic authentication.
fn form_encode(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(char::from(HEX[usize::from(byte >> 4)]));
            out.push(char::from(HEX[usize::from(byte & 0x0F)]));
        }
    }
    out
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: Option<String>,
    expires_in: Option<i64>,
    refresh_token: Option<String>,
    id_token: Option<String>,
}

/// A token response with every token held as a [`TokenSecret`].
struct Granted {
    access: TokenSecret,
    refresh: Option<TokenSecret>,
    id: Option<TokenSecret>,
    expires_in: i64,
}

enum IdpRefusal {
    /// The IdP answered and refused (or answered nonsense).
    Refused,
    /// The IdP could not be reached or failed.
    Unreachable,
}

impl ConsoleLogin {
    /// Validates the settings, reads the client secret, reads the endpoints
    /// (configured, or discovery) and builds the runtime.
    pub async fn start(
        settings: &ConsoleLoginSettings,
        config: &ApiConfig,
    ) -> Result<Self, String> {
        validate(settings, config)?;
        let issuer = &config
            .oidc
            .as_ref()
            .ok_or("console login needs operator OIDC")?
            .issuer;
        let secret = read_client_secret(&settings.client_secret_file)?;
        let endpoints = match &settings.endpoints {
            Some(endpoints) => endpoints.clone(),
            None => discover(issuer, config.insecure_dev).await?,
        };
        Self::build(settings, endpoints, secret, config.insecure_dev)
    }

    /// Builds the runtime from checked parts. `allow_plain_http` lets the
    /// HTTP client reach a plain-HTTP identity provider (`--insecure-dev`,
    /// and the in-process test double).
    pub fn build(
        settings: &ConsoleLoginSettings,
        endpoints: IdpEndpoints,
        client_secret: TokenSecret,
        allow_plain_http: bool,
    ) -> Result<Self, String> {
        let redirect = Url::parse(&settings.redirect_uri)
            .map_err(|_| "--console-redirect-uri is not a URL".to_string())?;
        let origin = crate::hardening::origin_of(redirect.as_str())
            .ok_or("--console-redirect-uri has no host")?;
        Ok(Self {
            client_id: settings.client_id.clone(),
            client_secret,
            redirect_uri: settings.redirect_uri.clone(),
            origin,
            endpoints,
            scope: settings.scope.clone(),
            idle: minutes(settings.idle_minutes),
            absolute: minutes(settings.absolute_minutes),
            idp_logout: settings.idp_logout,
            max_sessions: settings.max_sessions,
            http: idp_client(allow_plain_http)?,
            clock: Arc::new(Utc::now),
            rng: SystemRandom::new(),
            logins: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
            limiter: Mutex::new(Bucket {
                tokens: LOGIN_BURST,
                last: Instant::now(),
            }),
        })
    }

    /// Replaces the clock (tests).
    #[must_use]
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    fn now(&self) -> DateTime<Utc> {
        (self.clock)()
    }

    /// The console's origin (`scheme://host[:port]` of the redirect URI).
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Live sessions (tests and the session-table bound).
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.sessions.lock().map_or(0, |s| s.len())
    }

    /// Pending login records.
    #[must_use]
    pub fn pending_logins(&self) -> usize {
        self.logins.lock().map_or(0, |l| l.len())
    }

    fn random(&self) -> Result<String, LoginError> {
        let mut bytes = [0u8; 32];
        self.rng
            .fill(&mut bytes)
            .map_err(|_| LoginError::Unavailable)?;
        Ok(URL_SAFE_NO_PAD.encode(bytes))
    }

    fn admit(&self) -> bool {
        let Ok(mut bucket) = self.limiter.lock() else {
            return false;
        };
        let elapsed = bucket.last.elapsed().as_secs_f64();
        bucket.last = Instant::now();
        bucket.tokens = (bucket.tokens + elapsed * LOGIN_RATE_PER_SECOND).min(LOGIN_BURST);
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn live(&self, session: &Session, now: DateTime<Utc>) -> bool {
        let last_seen = session.last_seen.lock().map_or(now, |t| *t);
        now < session.absolute_expires && now < last_seen + self.idle
    }

    /// Drops ended sessions (an ended session is not an eviction).
    fn purge_sessions(&self, sessions: &mut HashMap<[u8; 32], Arc<Session>>) {
        let now = self.now();
        sessions.retain(|_, s| self.live(s, now));
    }

    fn sessions_full(&self) -> bool {
        let Ok(mut sessions) = self.sessions.lock() else {
            return true;
        };
        self.purge_sessions(&mut sessions);
        sessions.len() >= self.max_sessions
    }

    /// `GET /auth/login`: a new login record, and the authorization URL and
    /// login cookie value. The cookie is the record's key.
    pub fn begin(&self) -> Result<(String, String), LoginError> {
        if !self.admit() {
            return Err(LoginError::Unavailable);
        }
        if self.sessions_full() {
            return Err(LoginError::SessionsFull);
        }
        let cookie = self.random()?;
        let state = self.random()?;
        let nonce = TokenSecret::new(self.random()?);
        let verifier = TokenSecret::new(self.random()?);
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.expose().as_bytes()));
        let mut url =
            Url::parse(&self.endpoints.authorization).map_err(|_| LoginError::Unavailable)?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", &self.redirect_uri)
            .append_pair("scope", &self.scope)
            .append_pair("state", &state)
            .append_pair("nonce", nonce.expose())
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");
        let now = self.now();
        let mut logins = self.logins.lock().map_err(|_| LoginError::Unavailable)?;
        logins.retain(|_, l| now < l.created + Duration::seconds(LOGIN_TTL_SECONDS));
        if logins.len() >= MAX_PENDING_LOGINS {
            return Err(LoginError::Unavailable);
        }
        logins.insert(
            digest(&cookie),
            PendingLogin {
                state,
                nonce,
                verifier,
                created: now,
            },
        );
        Ok((url.into(), cookie))
    }

    /// `GET /auth/callback`: checks the login record and `state`, exchanges
    /// the code, verifies the ID token and the access token, and opens a
    /// session. Returns the session cookie value.
    pub async fn finish(
        &self,
        state: &AppState,
        login_cookie: Option<&str>,
        query: &CallbackQuery,
    ) -> Result<String, LoginError> {
        if !self.admit() {
            return Err(LoginError::Unavailable);
        }
        let verifier = state.oidc().ok_or(LoginError::Unavailable)?;
        // Single use: the record is removed whatever happens next.
        let record = login_cookie
            .and_then(|cookie| {
                self.logins
                    .lock()
                    .ok()
                    .and_then(|mut logins| logins.remove(&digest(cookie)))
            })
            .ok_or(LoginError::Expired)?;
        let now = self.now();
        if now >= record.created + Duration::seconds(LOGIN_TTL_SECONDS) {
            return Err(LoginError::Expired);
        }
        if query.state.as_deref() != Some(record.state.as_str()) || query.error.is_some() {
            return Err(LoginError::Failed);
        }
        let code = query.code.as_deref().ok_or(LoginError::Failed)?;
        let granted = self
            .token_request(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", &self.redirect_uri),
                ("code_verifier", record.verifier.expose()),
            ])
            .await
            .map_err(|refusal| match refusal {
                IdpRefusal::Refused => LoginError::Failed,
                IdpRefusal::Unreachable => LoginError::Unavailable,
            })?;
        let id_token = granted.id.as_ref().ok_or(LoginError::Failed)?;
        verifier
            .verify_id_token(id_token.expose(), &self.client_id, record.nonce.expose())
            .map_err(|e| refused_token(verifier, &e))?;
        let identity = verifier
            .verify(granted.access.expose())
            .map_err(|e| refused_token(verifier, &e))?;
        drop(granted.id);

        let cookie = self.random()?;
        let session = Arc::new(Session {
            principal: identity.principal.clone(),
            absolute_expires: now + self.absolute,
            last_seen: Mutex::new(now),
            tokens: tokio::sync::Mutex::new(Tokens {
                access: granted.access,
                refresh: granted.refresh,
                access_expires: now + Duration::seconds(granted.expires_in),
                groups: identity.groups,
            }),
            audit_ref: uuid::Uuid::new_v4().to_string(),
        });
        if !self.insert_session(&cookie, &session)? {
            self.revoke(&session).await;
            return Err(LoginError::SessionsFull);
        }
        // A login that cannot be audited does not happen.
        let audited = state
            .admin()
            .append_audit(kavach_storage::AuditInsert {
                action: "console_login".into(),
                resource_type: "console_session".into(),
                resource_id: session.audit_ref.clone(),
                actor_principal: session.principal.clone(),
                approver_principal: String::new(),
                payload: json!({}),
            })
            .await;
        if audited.is_err() {
            tracing::error!("a console login could not be audited; no session was opened");
            self.end(&cookie);
            self.revoke(&session).await;
            return Err(LoginError::Unavailable);
        }
        Ok(cookie)
    }

    /// Adds a session unless the table is full (it never evicts).
    fn insert_session(&self, cookie: &str, session: &Arc<Session>) -> Result<bool, LoginError> {
        let mut sessions = self.sessions.lock().map_err(|_| LoginError::Unavailable)?;
        self.purge_sessions(&mut sessions);
        if sessions.len() >= self.max_sessions {
            return Ok(false);
        }
        sessions.insert(digest(cookie), Arc::clone(session));
        Ok(true)
    }

    async fn token_request(&self, form: &[(&str, &str)]) -> Result<Granted, IdpRefusal> {
        let basic = STANDARD.encode(format!(
            "{}:{}",
            form_encode(&self.client_id),
            form_encode(self.client_secret.expose())
        ));
        let authorization = TokenSecret::new(format!("Basic {basic}"));
        drop(TokenSecret::new(basic));
        let mut value =
            HeaderValue::from_str(authorization.expose()).map_err(|_| IdpRefusal::Refused)?;
        value.set_sensitive(true);
        let response = self
            .http
            .post(&self.endpoints.token)
            .header(header::AUTHORIZATION, value)
            .header(header::ACCEPT, "application/json")
            .form(form)
            .send()
            .await
            .map_err(|_| IdpRefusal::Unreachable)?;
        let status = response.status();
        if status.is_server_error() {
            return Err(IdpRefusal::Unreachable);
        }
        let mut body = read_bounded(response)
            .await
            .map_err(|()| IdpRefusal::Unreachable)?;
        if !status.is_success() {
            body.fill(0);
            return Err(IdpRefusal::Refused);
        }
        let parsed = serde_json::from_slice::<TokenResponse>(&body);
        body.fill(0);
        let parsed = parsed.map_err(|_| IdpRefusal::Refused)?;
        let granted = Granted {
            access: TokenSecret::new(parsed.access_token),
            refresh: parsed.refresh_token.map(TokenSecret::new),
            id: parsed.id_token.map(TokenSecret::new),
            expires_in: parsed
                .expires_in
                .unwrap_or(DEFAULT_EXPIRES_IN)
                .clamp(MIN_EXPIRES_IN, MAX_EXPIRES_IN),
        };
        if !parsed
            .token_type
            .is_some_and(|t| t.eq_ignore_ascii_case("bearer"))
            || granted.access.expose().is_empty()
        {
            return Err(IdpRefusal::Refused);
        }
        Ok(granted)
    }

    /// The live session a cookie names, refreshed when its access token is
    /// about to expire; the access token to put in front of the request.
    /// `None` ends the session if it had ended (idle, absolute, a failed
    /// refresh) and means "no session".
    pub async fn access_token(
        &self,
        verifier: &Arc<OidcVerifier>,
        cookie: &str,
    ) -> Option<TokenSecret> {
        self.with_live(verifier, cookie, |_, tokens| tokens.access.clone())
            .await
    }

    /// `GET /auth/session`: the session's identity and limits.
    pub async fn view(&self, verifier: &Arc<OidcVerifier>, cookie: &str) -> Option<SessionView> {
        let idle = self.idle;
        self.with_live(verifier, cookie, |session, tokens| {
            let last_seen = session
                .last_seen
                .lock()
                .map_or(session.absolute_expires, |t| *t);
            SessionView {
                principal: session.principal.clone(),
                groups: tokens.groups.clone(),
                expires_at: session.absolute_expires,
                idle_expires_at: (last_seen + idle).min(session.absolute_expires),
            }
        })
        .await
    }

    async fn with_live<T>(
        &self,
        verifier: &Arc<OidcVerifier>,
        cookie: &str,
        then: impl FnOnce(&Session, &Tokens) -> T,
    ) -> Option<T> {
        let key = digest(cookie);
        let session = self.sessions.lock().ok()?.get(&key).cloned()?;
        if !self.live(&session, self.now()) {
            self.end(cookie);
            return None;
        }
        let mut tokens = session.tokens.lock().await;
        // Logged out (or ended) while this request waited for the refresh.
        if !self.sessions.lock().ok()?.contains_key(&key) {
            return None;
        }
        let now = self.now();
        if now >= session.absolute_expires {
            drop(tokens);
            self.end(cookie);
            return None;
        }
        if tokens.access_expires - Duration::seconds(REFRESH_MARGIN_SECONDS) <= now
            && self.refresh(verifier, &session, &mut tokens).await.is_err()
        {
            drop(tokens);
            self.end(cookie);
            return None;
        }
        if let Ok(mut last_seen) = session.last_seen.lock() {
            *last_seen = now;
        }
        Some(then(&session, &tokens))
    }

    /// One refresh, under the session's lock. A rotated refresh token
    /// replaces the old one. The absolute limit is not touched.
    async fn refresh(
        &self,
        verifier: &Arc<OidcVerifier>,
        session: &Session,
        tokens: &mut Tokens,
    ) -> Result<(), ()> {
        let refresh = tokens.refresh.as_ref().ok_or(())?;
        let granted = self
            .token_request(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh.expose()),
            ])
            .await
            .map_err(|_| ())?;
        let identity = verifier.verify(granted.access.expose()).map_err(|e| {
            if matches!(e, OidcError::UnknownKid(_)) {
                verifier.request_refresh();
            }
        })?;
        if identity.principal != session.principal {
            return Err(());
        }
        tokens.access = granted.access;
        tokens.access_expires = self.now() + Duration::seconds(granted.expires_in);
        tokens.groups = identity.groups;
        if let Some(rotated) = granted.refresh {
            tokens.refresh = Some(rotated);
        }
        Ok(())
    }

    fn end(&self, cookie: &str) -> Option<Arc<Session>> {
        self.sessions.lock().ok()?.remove(&digest(cookie))
    }

    /// RFC 7009: revokes the session's refresh token when the IdP has a
    /// revocation endpoint. Best effort; nothing of the token is logged.
    async fn revoke(&self, session: &Session) {
        let Some(endpoint) = &self.endpoints.revocation else {
            return;
        };
        let tokens = session.tokens.lock().await;
        let Some(refresh) = &tokens.refresh else {
            return;
        };
        let basic = TokenSecret::new(format!(
            "Basic {}",
            STANDARD.encode(format!(
                "{}:{}",
                form_encode(&self.client_id),
                form_encode(self.client_secret.expose())
            ))
        ));
        let Ok(mut value) = HeaderValue::from_str(basic.expose()) else {
            return;
        };
        value.set_sensitive(true);
        let sent = self
            .http
            .post(endpoint)
            .header(header::AUTHORIZATION, value)
            .form(&[
                ("token", refresh.expose()),
                ("token_type_hint", "refresh_token"),
            ])
            .send()
            .await;
        if !sent.is_ok_and(|r| r.status().is_success()) {
            tracing::warn!("console logout: the identity provider did not confirm the revocation");
        }
    }

    /// `POST /auth/logout`: ends the session, revokes its refresh token and
    /// returns the IdP end-session URL when that setting is on. `None`: no
    /// live session.
    pub async fn logout(
        &self,
        state: &AppState,
        verifier: &Arc<OidcVerifier>,
        cookie: &str,
    ) -> Option<Option<String>> {
        self.with_live(verifier, cookie, |_, _| ()).await?;
        let session = self.end(cookie)?;
        self.revoke(&session).await;
        let audited = state
            .admin()
            .append_audit(kavach_storage::AuditInsert {
                action: "console_logout".into(),
                resource_type: "console_session".into(),
                resource_id: session.audit_ref.clone(),
                actor_principal: session.principal.clone(),
                approver_principal: String::new(),
                payload: json!({}),
            })
            .await;
        if audited.is_err() {
            // The session has ended either way.
            tracing::warn!("a console logout could not be audited");
        }
        Some(self.end_session_url())
    }

    /// The IdP end-session URL: `client_id` and `post_logout_redirect_uri`
    /// only, never `id_token_hint` (the ID token is not kept).
    fn end_session_url(&self) -> Option<String> {
        if !self.idp_logout {
            return None;
        }
        let mut url = Url::parse(self.endpoints.end_session.as_ref()?).ok()?;
        url.query_pairs_mut()
            .append_pair("client_id", &self.client_id)
            .append_pair(
                "post_logout_redirect_uri",
                &format!("{}{SIGNIN_PATH}", self.origin),
            );
        Some(url.into())
    }
}

fn minutes(value: u64) -> Duration {
    Duration::minutes(i64::try_from(value).unwrap_or(i64::MAX / 60_000))
}

fn refused_token(verifier: &Arc<OidcVerifier>, error: &OidcError) -> LoginError {
    if matches!(error, OidcError::UnknownKid(_)) {
        verifier.request_refresh();
    }
    LoginError::Failed
}

// ---- HTTP ----------------------------------------------------------------

/// The value of the first cookie named `name`, from every `Cookie` header.
#[must_use]
pub fn cookie<'h>(headers: &'h HeaderMap, name: &str) -> Option<&'h str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(n, _)| *n == name)
        .map(|(_, v)| v.trim())
        .filter(|v| !v.is_empty())
}

fn refusal(status: StatusCode, code: &'static str, detail: &str) -> Response {
    Problem::new(status, code, detail).into_response()
}

/// The checks a cookie-authenticated request must pass before anything is
/// verified: no credential header beside the cookie (400), the console
/// header, and a same-origin `Origin` and `Sec-Fetch-Site` (403).
fn refuse_cookie_request(headers: &HeaderMap, origin: &str) -> Option<Response> {
    if headers.contains_key(header::AUTHORIZATION) || headers.contains_key("x-kavach-principal") {
        return Some(refusal(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "send either the console session cookie or a credential header, not both",
        ));
    }
    if headers.get(CONSOLE_HEADER).map(HeaderValue::as_bytes) != Some(b"1") {
        return Some(refusal(
            StatusCode::FORBIDDEN,
            "forbidden",
            "a console session request needs the X-Kavach-Console: 1 header",
        ));
    }
    if headers
        .get(header::ORIGIN)
        .is_some_and(|o| o.as_bytes() != origin.as_bytes())
    {
        return Some(refusal(
            StatusCode::FORBIDDEN,
            "forbidden",
            "a cross-origin console session request is refused",
        ));
    }
    if headers
        .get("sec-fetch-site")
        .is_some_and(|s| !matches!(s.as_bytes(), b"same-origin" | b"none"))
    {
        return Some(refusal(
            StatusCode::FORBIDDEN,
            "forbidden",
            "a cross-site console session request is refused",
        ));
    }
    None
}

fn no_session() -> Response {
    refusal(
        StatusCode::UNAUTHORIZED,
        "unauthorized",
        "no live console session; sign in again",
    )
}

/// The operator router's session-cookie step (API routes only). With login
/// configured and the session cookie present, the request must pass
/// [`refuse_cookie_request`]; a live session's access token then becomes
/// the request's `Authorization`, and the existing path verifies it. A
/// cookie with no live session is a 401. Without login configured, or
/// without the cookie, the request passes untouched.
pub async fn cookie_step(
    State(state): State<Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(login) = state.console_login() else {
        return next.run(request).await;
    };
    let Some(session) = cookie(request.headers(), SESSION_COOKIE).map(str::to_owned) else {
        return next.run(request).await;
    };
    let session = TokenSecret::new(session);
    if let Some(refused) = refuse_cookie_request(request.headers(), login.origin()) {
        return refused;
    }
    let Some(verifier) = state.oidc() else {
        return no_session();
    };
    let Some(access) = login.access_token(verifier, session.expose()).await else {
        return no_session();
    };
    let bearer = TokenSecret::new(format!("Bearer {}", access.expose()));
    let Ok(mut value) = HeaderValue::from_str(bearer.expose()) else {
        return no_session();
    };
    value.set_sensitive(true);
    request.headers_mut().insert(header::AUTHORIZATION, value);
    next.run(request).await
}

fn signin_redirect(error: LoginError, expire_login: bool) -> Response {
    let mut response = (
        StatusCode::SEE_OTHER,
        [(
            header::LOCATION,
            format!("{SIGNIN_PATH}?error={}", error.code()),
        )],
    )
        .into_response();
    if expire_login {
        append_cookie(&mut response, &expired_cookie(LOGIN_COOKIE, "Lax"));
    }
    response
}

fn append_cookie(response: &mut Response, value: &str) {
    if let Ok(value) = HeaderValue::from_str(value) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

fn expired_cookie(name: &str, same_site: &str) -> String {
    format!("{name}=; HttpOnly; Secure; SameSite={same_site}; Path=/; Max-Age=0")
}

/// `GET /auth/config`: what the sign-in screen offers.
pub async fn config(State(state): State<Arc<AppState>>) -> Response {
    let configured = state.console_login().is_some();
    Json(json!({
        "login_configured": configured,
        "pasted_token_allowed": !configured && state.insecure_dev(),
    }))
    .into_response()
}

/// `GET /auth/login`: to the identity provider, with a login cookie.
pub async fn login(State(state): State<Arc<AppState>>) -> Response {
    let Some(login) = state.console_login() else {
        return signin_redirect(LoginError::Unavailable, false);
    };
    match login.begin() {
        Ok((location, handle)) => {
            let mut response =
                (StatusCode::SEE_OTHER, [(header::LOCATION, location)]).into_response();
            let cookie = TokenSecret::new(format!(
                "{LOGIN_COOKIE}={handle}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={LOGIN_TTL_SECONDS}"
            ));
            append_cookie(&mut response, cookie.expose());
            response
        }
        Err(error) => signin_redirect(error, false),
    }
}

/// The callback's query. Only these members are read.
#[derive(Debug, Default, Deserialize)]
pub struct CallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

/// `GET /auth/callback`: a session cookie and `/`, or `/signin?error=`.
pub async fn callback(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    query: Result<Query<CallbackQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let Some(login) = state.console_login() else {
        return signin_redirect(LoginError::Unavailable, true);
    };
    let query = query.map(|Query(q)| q).unwrap_or_default();
    let outcome = login
        .finish(&state, cookie(&headers, LOGIN_COOKIE), &query)
        .await;
    match outcome {
        Ok(session) => {
            let mut response = (StatusCode::SEE_OTHER, [(header::LOCATION, "/")]).into_response();
            let cookie = TokenSecret::new(format!(
                "{SESSION_COOKIE}={session}; HttpOnly; Secure; SameSite=Strict; Path=/"
            ));
            append_cookie(&mut response, cookie.expose());
            append_cookie(&mut response, &expired_cookie(LOGIN_COOKIE, "Lax"));
            response
        }
        Err(error) => signin_redirect(error, true),
    }
}

/// `GET /auth/session`: who is signed in, and until when. Never a token.
pub async fn session(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let (Some(login), Some(verifier)) = (state.console_login(), state.oidc()) else {
        return no_session();
    };
    let Some(cookie) = cookie(&headers, SESSION_COOKIE) else {
        return no_session();
    };
    if let Some(refused) = refuse_cookie_request(&headers, login.origin()) {
        return refused;
    }
    match login.view(verifier, cookie).await {
        Some(view) => Json(view).into_response(),
        None => no_session(),
    }
}

/// `POST /auth/logout`: ends the session and expires both cookies.
pub async fn logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let mut response = logout_response(&state, &headers).await;
    append_cookie(&mut response, &expired_cookie(SESSION_COOKIE, "Strict"));
    append_cookie(&mut response, &expired_cookie(LOGIN_COOKIE, "Lax"));
    response
}

async fn logout_response(state: &AppState, headers: &HeaderMap) -> Response {
    let (Some(login), Some(verifier)) = (state.console_login(), state.oidc()) else {
        return no_session();
    };
    let Some(cookie) = cookie(headers, SESSION_COOKIE) else {
        return no_session();
    };
    if let Some(refused) = refuse_cookie_request(headers, login.origin()) {
        return refused;
    }
    match login.logout(state, verifier, cookie).await {
        Some(end_session_url) => {
            Json(json!({ "end_session_url": end_session_url })).into_response()
        }
        None => no_session(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_encoding_keeps_only_unreserved_characters() {
        assert_eq!(form_encode("abc-._~XYZ09"), "abc-._~XYZ09");
        assert_eq!(form_encode("a b:c%/+"), "a%20b%3Ac%25%2F%2B");
    }

    #[test]
    fn cookies_are_read_from_every_cookie_header() {
        let mut headers = HeaderMap::new();
        headers.append(header::COOKIE, HeaderValue::from_static("a=1; b=2"));
        headers.append(
            header::COOKIE,
            HeaderValue::from_static("__Host-kavach_session=xyz"),
        );
        assert_eq!(cookie(&headers, "b"), Some("2"));
        assert_eq!(cookie(&headers, SESSION_COOKIE), Some("xyz"));
        assert_eq!(cookie(&headers, "c"), None);
    }

    #[test]
    fn the_redirect_uri_is_an_exact_https_callback() {
        assert!(check_redirect_uri("https://kavach.example/auth/callback", false).is_ok());
        for bad in [
            "http://kavach.example/auth/callback",
            "https://kavach.example/auth/callback?x=1",
            "https://kavach.example/auth/callback#f",
            "https://u:p@kavach.example/auth/callback",
            "https://kavach.example/other",
            "http://localhost:8080/auth/callback",
        ] {
            assert!(check_redirect_uri(bad, false).is_err(), "{bad}");
        }
        assert!(check_redirect_uri("http://localhost:8080/auth/callback", true).is_ok());
        assert!(check_redirect_uri("http://kavach.example/auth/callback", true).is_err());
    }
}

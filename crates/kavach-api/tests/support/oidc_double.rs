//! An OpenID Connect identity provider double for the console sign-in
//! (ADR-018), written once for two uses:
//!
//! - the Rust tests (`tests/console_login.rs`) start it in-process on
//!   `127.0.0.1:0` and change its behaviour per test;
//! - `examples/oidc_double.rs` runs it as a development IdP for the
//!   Playwright checks (see the example's header).
//!
//! It serves discovery, the JWKS, `authorize` (auto-approves the configured
//! test user and redirects back with a code), `token` (the code with a PKCE
//! S256 check and the client secret, and refresh with optional rotation),
//! RFC 7009 revocation and end-session. Tokens are EdDSA JWTs signed with a
//! key from a 32-byte seed. **A test tool only**: it approves everyone who
//! asks.
//!
//! Who signs in is the configured user, or, when [`Behaviour::users`] lists
//! more, the one the browser names in the [`USER_COOKIE`] cookie at the
//! double's origin (a Playwright check sets it before it signs in). A name
//! the double does not know is refused, never replaced by the default.
//!
//! With [`Behaviour::pick`] on (the example's `--pick`, for a person at a
//! browser), `authorize` instead answers with a page that lists every user,
//! each a link back to `authorize` with `login_as=<sub>`; the cookie is
//! then not read.
#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::extract::{Form, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// The signed-in user the double approves.
#[derive(Debug, Clone)]
pub struct TestUser {
    pub sub: String,
    pub groups: Vec<String>,
}

/// What the double is.
#[derive(Debug, Clone)]
pub struct DoubleConfig {
    /// The `iss` of every token; `None`: the double's own URL.
    pub issuer: Option<String>,
    pub seed: [u8; 32],
    pub kid: String,
    pub client_id: String,
    pub client_secret: String,
    /// The operator audience (`aud` of access tokens).
    pub audience: String,
    pub user: TestUser,
    pub listen: SocketAddr,
}

/// The cookie, at the double's origin, that names who signs in by `sub`
/// (one of [`Behaviour::users`]).
pub const USER_COOKIE: &str = "oidc_double_user";

/// What a test may change while the double runs.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)] // independent test switches, not a state
pub struct Behaviour {
    pub user: TestUser,
    /// Users a sign-in may name in the [`USER_COOKIE`] cookie, by `sub`.
    /// A sign-in that names none signs in `user`.
    pub users: HashMap<String, TestUser>,
    /// `expires_in` of access tokens (and their `exp`, from now).
    pub expires_in: i64,
    /// Replace the ID token's nonce / aud / iss.
    pub id_token_nonce: Option<String>,
    pub id_token_aud: Option<String>,
    pub id_token_iss: Option<String>,
    /// Replace the access token's aud (the OidcVerifier refuses it).
    pub access_aud: Option<String>,
    /// A refresh returns a new refresh token and retires the old one.
    pub rotate_refresh: bool,
    /// Every refresh is refused.
    pub refuse_refresh: bool,
    /// Issue a refresh token at all.
    pub issue_refresh: bool,
    /// Ask who signs in: `authorize` without `login_as` serves a page of
    /// links, one per user; with it, signs in that user (an unknown one is
    /// refused). The cookie is not read.
    pub pick: bool,
}

struct CodeGrant {
    redirect_uri: String,
    challenge: String,
    nonce: String,
    user: TestUser,
}

struct Shared {
    config: DoubleConfig,
    issuer: String,
    url: String,
    behaviour: Mutex<Behaviour>,
    codes: Mutex<HashMap<String, CodeGrant>>,
    refresh: Mutex<HashMap<String, TestUser>>,
    revoked: Mutex<HashSet<String>>,
    refreshes: Mutex<u32>,
    /// Every code and token issued (for the token-material scans).
    issued: Mutex<Vec<String>>,
    rng: SystemRandom,
}

/// A running double.
pub struct OidcDouble {
    pub url: String,
    pub issuer: String,
    shared: Arc<Shared>,
}

/// PKCS#8 v1 DER for an Ed25519 private key (RFC 8410).
fn pkcs8(seed: &[u8; 32]) -> Vec<u8> {
    let mut der = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    der.extend_from_slice(seed);
    der
}

/// The JWKS of a seed's key.
pub fn jwks_for(seed: &[u8; 32], kid: &str) -> Value {
    let pair = Ed25519KeyPair::from_seed_unchecked(seed).expect("ed25519 seed");
    json!({ "keys": [{
        "kty": "OKP", "crv": "Ed25519", "x": URL_SAFE_NO_PAD.encode(pair.public_key().as_ref()),
        "kid": kid, "alg": "EdDSA", "use": "sig"
    }]})
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

impl Shared {
    fn random(&self) -> String {
        let mut bytes = [0u8; 24];
        self.rng.fill(&mut bytes).expect("random");
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// A random code or refresh token, remembered as issued.
    fn issue(&self) -> String {
        let value = self.random();
        self.issued.lock().unwrap().push(value.clone());
        value
    }

    fn sign(&self, claims: &Value) -> String {
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(self.config.kid.clone());
        let token = encode(
            &header,
            claims,
            &EncodingKey::from_ed_der(&pkcs8(&self.config.seed)),
        )
        .expect("sign");
        self.issued.lock().unwrap().push(token.clone());
        token
    }

    fn access_token(&self, user: &TestUser, b: &Behaviour) -> String {
        self.sign(&json!({
            "iss": self.issuer, "aud": b.access_aud.clone().unwrap_or_else(|| self.config.audience.clone()),
            "sub": user.sub, "groups": user.groups, "azp": self.config.client_id,
            "iat": now(), "exp": now() + b.expires_in, "jti": self.random(),
        }))
    }

    fn id_token(&self, user: &TestUser, nonce: &str, b: &Behaviour) -> String {
        self.sign(&json!({
            "iss": b.id_token_iss.clone().unwrap_or_else(|| self.issuer.clone()),
            "aud": b.id_token_aud.clone().unwrap_or_else(|| self.config.client_id.clone()),
            "sub": user.sub, "nonce": b.id_token_nonce.clone().unwrap_or_else(|| nonce.to_string()),
            "iat": now(), "exp": now() + 300,
        }))
    }

    /// HTTP Basic client authentication (RFC 6749 §2.3.1).
    fn client_ok(&self, headers: &HeaderMap) -> bool {
        let Some(basic) = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Basic "))
        else {
            return false;
        };
        let Some(decoded) = STANDARD
            .decode(basic)
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
        else {
            return false;
        };
        decoded.split_once(':').is_some_and(|(id, secret)| {
            percent_decode(id) == self.config.client_id
                && percent_decode(secret) == self.config.client_secret
        })
    }
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&value[i + 1..i + 3], 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn oauth_error(error: &str) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": error }))).into_response()
}

async fn discovery(State(s): State<Arc<Shared>>) -> Json<Value> {
    Json(json!({
        "issuer": s.issuer,
        "authorization_endpoint": format!("{}/authorize", s.url),
        "token_endpoint": format!("{}/token", s.url),
        "jwks_uri": format!("{}/jwks", s.url),
        "revocation_endpoint": format!("{}/revoke", s.url),
        "end_session_endpoint": format!("{}/logout", s.url),
        "response_types_supported": ["code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic"],
        "id_token_signing_alg_values_supported": ["EdDSA"],
        "subject_types_supported": ["public"],
    }))
}

async fn jwks(State(s): State<Arc<Shared>>) -> Json<Value> {
    Json(jwks_for(&s.config.seed, &s.config.kid))
}

/// The `sub` the [`USER_COOKIE`] cookie names, if the browser sent one.
fn named_user(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(name, _)| *name == USER_COOKIE)
        .map(|(_, sub)| sub.to_string())
}

async fn authorize(
    State(s): State<Arc<Shared>>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let field = |k: &str| q.get(k).cloned().unwrap_or_default();
    if field("client_id") != s.config.client_id
        || field("response_type") != "code"
        || field("code_challenge_method") != "S256"
        || field("code_challenge").is_empty()
        || !field("scope").split(' ').any(|x| x == "openid")
        || field("redirect_uri").is_empty()
    {
        return oauth_error("invalid_request");
    }
    let user = {
        let b = s.behaviour.lock().unwrap();
        if b.pick {
            let Some(sub) = q.get("login_as") else {
                return picker(&s.url, &q, &b);
            };
            match known_user(&b, sub) {
                Some(user) => user,
                None => return oauth_error("access_denied"),
            }
        } else {
            match named_user(&headers) {
                None => b.user.clone(),
                Some(sub) => match b.users.get(&sub) {
                    Some(user) => user.clone(),
                    None => return oauth_error("access_denied"),
                },
            }
        }
    };
    let code = s.issue();
    s.codes.lock().unwrap().insert(
        code.clone(),
        CodeGrant {
            redirect_uri: field("redirect_uri"),
            challenge: field("code_challenge"),
            nonce: field("nonce"),
            user,
        },
    );
    let mut back = reqwest::Url::parse(&field("redirect_uri")).expect("redirect_uri");
    back.query_pairs_mut()
        .append_pair("code", &code)
        .append_pair("state", &field("state"));
    (
        StatusCode::SEE_OTHER,
        [(header::LOCATION, back.to_string())],
    )
        .into_response()
}

/// The default user or one of [`Behaviour::users`], by `sub`.
fn known_user(b: &Behaviour, sub: &str) -> Option<TestUser> {
    if b.user.sub == sub {
        return Some(b.user.clone());
    }
    b.users.get(sub).cloned()
}

/// Escapes text for an HTML element or a double-quoted attribute.
fn html_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// The [`Behaviour::pick`] page: one link per user, back to `authorize`
/// with the same query and `login_as=<sub>`. Static HTML, no script; an
/// empty icon, so a browser asks the double for no `/favicon.ico`.
fn picker(base: &str, q: &HashMap<String, String>, b: &Behaviour) -> Response {
    let mut users: Vec<&TestUser> = b.users.values().collect();
    if !b.users.contains_key(&b.user.sub) {
        users.push(&b.user);
    }
    users.sort_by(|x, y| x.sub.cmp(&y.sub));
    let mut pairs: Vec<(&String, &String)> = q.iter().filter(|(k, _)| *k != "login_as").collect();
    pairs.sort();
    let items = users.iter().fold(String::new(), |mut items, user| {
        let mut link = reqwest::Url::parse(&format!("{base}/authorize")).expect("double URL");
        {
            let mut query = link.query_pairs_mut();
            for (k, v) in &pairs {
                query.append_pair(k, v);
            }
            query.append_pair("login_as", &user.sub);
        }
        let _ = write!(
            items,
            "<li><a href=\"{href}\">{sub}</a> <span>({groups})</span></li>",
            href = html_escape(link.as_str()),
            sub = html_escape(&user.sub),
            groups = html_escape(&user.groups.join(", ")),
        );
        items
    });
    let page = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <title>Sign in as (OIDC test double)</title>\
         <link rel=\"icon\" href=\"data:,\"></head><body>\
         <h1>Sign in as</h1>\
         <p>The Kavach OIDC test double, for local development only. \
         Pick the user to sign in as.</p><ul>{items}</ul></body></html>"
    );
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'none'; img-src data:; frame-ancestors 'none'",
            ),
        ],
        page,
    )
        .into_response()
}

async fn token(
    State(s): State<Arc<Shared>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if !s.client_ok(&headers) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "invalid_client" })),
        )
            .into_response();
    }
    let b = s.behaviour.lock().unwrap().clone();
    let field = |k: &str| form.get(k).cloned().unwrap_or_default();
    match field("grant_type").as_str() {
        "authorization_code" => {
            // A code is used once, whatever the outcome.
            let Some(grant) = s.codes.lock().unwrap().remove(&field("code")) else {
                return oauth_error("invalid_grant");
            };
            let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(field("code_verifier")));
            if challenge != grant.challenge || field("redirect_uri") != grant.redirect_uri {
                return oauth_error("invalid_grant");
            }
            let mut body = json!({
                "access_token": s.access_token(&grant.user, &b),
                "token_type": "Bearer",
                "expires_in": b.expires_in,
                "id_token": s.id_token(&grant.user, &grant.nonce, &b),
            });
            if b.issue_refresh {
                let refresh = s.issue();
                s.refresh
                    .lock()
                    .unwrap()
                    .insert(refresh.clone(), grant.user.clone());
                body["refresh_token"] = refresh.into();
            }
            Json(body).into_response()
        }
        "refresh_token" => {
            *s.refreshes.lock().unwrap() += 1;
            let presented = field("refresh_token");
            let user = s.refresh.lock().unwrap().get(&presented).cloned();
            let Some(user) = user.filter(|_| !b.refuse_refresh) else {
                return oauth_error("invalid_grant");
            };
            let mut body = json!({
                "access_token": s.access_token(&user, &b),
                "token_type": "Bearer",
                "expires_in": b.expires_in,
            });
            if b.rotate_refresh {
                let rotated = s.issue();
                let mut tokens = s.refresh.lock().unwrap();
                tokens.remove(&presented);
                tokens.insert(rotated.clone(), user);
                body["refresh_token"] = rotated.into();
            }
            Json(body).into_response()
        }
        _ => oauth_error("unsupported_grant_type"),
    }
}

async fn revoke(
    State(s): State<Arc<Shared>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if !s.client_ok(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if let Some(token) = form.get("token") {
        s.refresh.lock().unwrap().remove(token);
        s.revoked.lock().unwrap().insert(token.clone());
    }
    StatusCode::OK.into_response()
}

async fn end_session(Query(q): Query<HashMap<String, String>>) -> Response {
    match q.get("post_logout_redirect_uri") {
        Some(to) => (StatusCode::SEE_OTHER, [(header::LOCATION, to.clone())]).into_response(),
        None => (StatusCode::OK, "signed out of the test identity provider").into_response(),
    }
}

impl OidcDouble {
    /// Starts the double; it runs until the runtime stops.
    pub async fn start(config: DoubleConfig) -> Self {
        let listener = tokio::net::TcpListener::bind(config.listen)
            .await
            .expect("bind the OIDC double");
        let url = format!("http://{}", listener.local_addr().unwrap());
        let issuer = config.issuer.clone().unwrap_or_else(|| url.clone());
        let shared = Arc::new(Shared {
            behaviour: Mutex::new(Behaviour {
                user: config.user.clone(),
                users: HashMap::new(),
                expires_in: 300,
                id_token_nonce: None,
                id_token_aud: None,
                id_token_iss: None,
                access_aud: None,
                rotate_refresh: false,
                refuse_refresh: false,
                issue_refresh: true,
                pick: false,
            }),
            config,
            issuer: issuer.clone(),
            url: url.clone(),
            codes: Mutex::new(HashMap::new()),
            refresh: Mutex::new(HashMap::new()),
            revoked: Mutex::new(HashSet::new()),
            refreshes: Mutex::new(0),
            issued: Mutex::new(Vec::new()),
            rng: SystemRandom::new(),
        });
        let app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/jwks", get(jwks))
            .route("/authorize", get(authorize))
            .route("/token", post(token))
            .route("/revoke", post(revoke))
            .route("/logout", get(end_session))
            .with_state(shared.clone());
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self {
            url,
            issuer,
            shared,
        }
    }

    pub fn authorization_endpoint(&self) -> String {
        format!("{}/authorize", self.url)
    }
    pub fn token_endpoint(&self) -> String {
        format!("{}/token", self.url)
    }
    pub fn revocation_endpoint(&self) -> String {
        format!("{}/revoke", self.url)
    }
    pub fn end_session_endpoint(&self) -> String {
        format!("{}/logout", self.url)
    }

    pub fn jwks(&self) -> Value {
        jwks_for(&self.shared.config.seed, &self.shared.config.kid)
    }

    /// Changes the behaviour for the requests that follow.
    pub fn set(&self, change: impl FnOnce(&mut Behaviour)) {
        change(&mut self.shared.behaviour.lock().unwrap());
    }

    /// An access token for `user`, as a CLI would hold (same issuer and key).
    pub fn mint_access_token(&self, user: &TestUser) -> String {
        let b = self.shared.behaviour.lock().unwrap().clone();
        self.shared.access_token(user, &b)
    }

    /// Refresh requests received.
    pub fn refreshes(&self) -> u32 {
        *self.shared.refreshes.lock().unwrap()
    }

    /// Tokens revoked through the revocation endpoint.
    pub fn revoked(&self) -> usize {
        self.shared.revoked.lock().unwrap().len()
    }

    /// Every code and token issued so far.
    pub fn issued(&self) -> Vec<String> {
        self.shared.issued.lock().unwrap().clone()
    }

    /// Refresh tokens still accepted.
    pub fn live_refresh_tokens(&self) -> usize {
        self.shared.refresh.lock().unwrap().len()
    }
}

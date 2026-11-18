//! ADR-018: console sign-in (authorization code with PKCE, tokens kept by
//! the server, an `HttpOnly` session cookie for the browser), end to end
//! against the OIDC test double in `tests/support/oidc_double.rs`.
//!
//! The sections follow the ADR's test plan, in its order. Every response
//! from the operator, agent and system-of-record routers is also held to
//! `docs/openapi.yaml` (the `contract` routers). A fake clock drives the
//! session limits; the tokens themselves carry real times, so the
//! existing verifier checks them as it always does.

mod agent_fixture;
mod common;
mod contract;
#[path = "support/oidc_double.rs"]
mod oidc_double;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use agent_fixture::{owner_only, IDP_SEED, ISSUER, KID};
use axum::body::Body;
use axum::http::{header, HeaderMap, Request, StatusCode};
use axum::Router;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use common::Creds;
use http_body_util::BodyExt;
use kavach_api::console_login::{
    self, ConsoleLogin, ConsoleLoginSettings, IdpEndpoints, LOGIN_COOKIE, SESSION_COOKIE,
    STEP_UP_COOKIE,
};
use kavach_api::dataplane::TestClock;
use kavach_api::hardening::{console_login_violations, Violation};
use kavach_api::{ApiConfig, AppState, EvidenceStoreKind};
use kavach_ports::agent_evidence::AgentEvidenceStore;
use kavach_ports::ReviewApprovalStore;
use kavach_ports::TokenSecret;
use kavach_ports_testkit::FakeClock;
use oidc_double::{DoubleConfig, OidcDouble, TestUser};
use serde_json::{json, Value};
use tower::ServiceExt;

const CLIENT_ID: &str = "kavach-console";
const CLIENT_SECRET: &str = "console-client-secret-0123456789";
const ORIGIN: &str = "https://console.kavach.test";
const REDIRECT_URI: &str = "https://console.kavach.test/auth/callback";
const AGENT: &str = "collections-agent";

// ---- log capture (as in tests/gateway.rs) -------------------------------

/// Every log line written by this test binary: the real redacting
/// subscriber, writing here instead of stderr.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn logs() -> &'static Capture {
    static LOGS: OnceLock<Capture> = OnceLock::new();
    LOGS.get_or_init(|| {
        let capture = Capture::default();
        let writer = capture.clone();
        kavach_telemetry::init_with(kavach_telemetry::LogFormat::Json, move || writer.clone())
            .expect("subscriber");
        capture
    })
}

fn log_text() -> String {
    String::from_utf8_lossy(&logs().0.lock().unwrap()).into_owned()
}

// ---- harness ---------------------------------------------------------------

fn user(sub: &str, groups: &[&str]) -> TestUser {
    TestUser {
        sub: sub.into(),
        groups: groups.iter().map(|g| (*g).to_string()).collect(),
    }
}

fn admin() -> TestUser {
    user("ops-1", &["admins"])
}

struct Harness {
    state: Arc<AppState>,
    idp: OidcDouble,
    clock: Arc<Mutex<DateTime<Utc>>>,
}

impl Harness {
    fn app(&self) -> Router {
        contract::router(self.state.clone())
    }

    fn login(&self) -> &ConsoleLogin {
        self.state.console_login().expect("console login")
    }

    fn advance(&self, by: Duration) {
        *self.clock.lock().unwrap() += by;
    }
}

async fn double(first_user: TestUser) -> OidcDouble {
    OidcDouble::start(DoubleConfig {
        issuer: Some(ISSUER.into()),
        seed: IDP_SEED,
        kid: KID.into(),
        client_id: CLIENT_ID.into(),
        client_secret: CLIENT_SECRET.into(),
        audience: "kavach-api".into(),
        user: first_user,
        listen: "127.0.0.1:0".parse().unwrap(),
    })
    .await
}

/// The fixture's operator OIDC and Cedar, without agent surfaces and
/// without `--insecure-dev`: the production shape for operator routes.
fn plain_config(insecure_dev: bool) -> ApiConfig {
    let mut config = agent_fixture::config(EvidenceStoreKind::Memory, insecure_dev, 50);
    config.dataplane = None;
    config
}

fn api_config() -> ApiConfig {
    plain_config(false)
}

/// With agent surfaces (the agent and system-of-record listeners, the kill
/// switch). They need trusted time: a test clock, which startup accepts
/// under `--insecure-dev` only.
fn agents_config() -> ApiConfig {
    let mut config = agent_fixture::config(EvidenceStoreKind::Memory, true, 50);
    let clock = Arc::new(FakeClock::synced_at(Utc::now()));
    config.dataplane.as_mut().unwrap().test_clock = Some(TestClock(clock));
    config
}

fn settings() -> ConsoleLoginSettings {
    ConsoleLoginSettings::new(CLIENT_ID, PathBuf::from("unused.secret"), REDIRECT_URI)
}

/// The operator IdP is the double (same issuer and key as the fixture's
/// JWKS). The settings pass the startup checks; the endpoints are the
/// double's plain-HTTP loopback ones, so the runtime is built directly.
async fn harness_as(
    first_user: TestUser,
    change: impl FnOnce(&mut ConsoleLoginSettings),
) -> Harness {
    harness_on(api_config(), first_user, change).await
}

async fn harness_on(
    config: ApiConfig,
    first_user: TestUser,
    change: impl FnOnce(&mut ConsoleLoginSettings),
) -> Harness {
    logs();
    let idp = double(first_user).await;
    let mut settings = settings();
    change(&mut settings);
    console_login::validate(&settings, &config).expect("valid settings");
    let endpoints = IdpEndpoints {
        authorization: idp.authorization_endpoint(),
        token: idp.token_endpoint(),
        revocation: Some(idp.revocation_endpoint()),
        end_session: Some(idp.end_session_endpoint()),
    };
    let clock = Arc::new(Mutex::new(Utc::now()));
    let shared = Arc::clone(&clock);
    let login = ConsoleLogin::build(&settings, endpoints, TokenSecret::new(CLIENT_SECRET), true)
        .expect("console login")
        .with_clock(Arc::new(move || *shared.lock().unwrap()));
    let state = AppState::from_config(&config)
        .await
        .expect("state")
        .with_console_login(Arc::new(login));
    Harness {
        state: Arc::new(state),
        idp,
        clock,
    }
}

async fn harness(change: impl FnOnce(&mut ConsoleLoginSettings)) -> Harness {
    harness_as(admin(), change).await
}

// ---- requests ----------------------------------------------------------------

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }

    fn location(&self) -> &str {
        self.headers
            .get(header::LOCATION)
            .map_or("", |v| v.to_str().unwrap())
    }

    fn set_cookies(&self) -> Vec<String> {
        self.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect()
    }

    fn set_cookie(&self, name: &str) -> Option<String> {
        self.set_cookies()
            .into_iter()
            .find(|c| c.starts_with(&format!("{name}=")))
    }

    /// Every header and the body, as text (for the token scans).
    fn text(&self) -> String {
        let mut text = String::new();
        for (name, value) in &self.headers {
            text.push_str(name.as_str());
            text.push_str(": ");
            text.push_str(value.to_str().unwrap_or("?"));
            text.push('\n');
        }
        text.push_str(&String::from_utf8_lossy(&self.body));
        text
    }
}

async fn send(
    app: &Router,
    method: &str,
    uri: &str,
    headers: &Creds,
    body: Option<Value>,
) -> Reply {
    let mut request = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        request = request.header(*name, value);
    }
    let body = match body {
        Some(value) => {
            request = request.header("content-type", "application/json");
            Body::from(value.to_string())
        }
        None => Body::empty(),
    };
    let response = app
        .clone()
        .oneshot(request.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    Reply {
        status,
        headers,
        body,
    }
}

/// What the console sends with its session: the cookie, the custom header,
/// and the browser's same-origin metadata.
fn console(session: &str) -> Creds {
    vec![
        ("cookie", format!("{SESSION_COOKIE}={session}")),
        ("x-kavach-console", "1".into()),
        ("origin", ORIGIN.into()),
        ("sec-fetch-site", "same-origin".into()),
    ]
}

fn without(mut creds: Creds, name: &str) -> Creds {
    creds.retain(|(n, _)| *n != name);
    creds
}

fn with(mut creds: Creds, name: &'static str, value: &str) -> Creds {
    creds.retain(|(n, _)| *n != name);
    creds.push((name, value.to_string()));
    creds
}

fn cookie_value(set_cookie: &str) -> String {
    set_cookie
        .split(';')
        .next()
        .and_then(|pair| pair.split_once('='))
        .map(|(_, v)| v.to_string())
        .unwrap()
}

fn query_of(url: &str) -> HashMap<String, String> {
    reqwest::Url::parse(url)
        .unwrap()
        .query_pairs()
        .into_owned()
        .collect()
}

/// `GET /auth/login`: the login cookie value and the authorization URL.
async fn begin(h: &Harness) -> (String, String) {
    let reply = send(&h.app(), "GET", "/auth/login", &vec![], None).await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.text());
    let cookie = cookie_value(&reply.set_cookie(LOGIN_COOKIE).expect("a login cookie"));
    (cookie, reply.location().to_string())
}

/// The browser at the IdP: it approves and redirects back. Returns the
/// callback's `code` and `state`.
async fn authorize(authorization_url: &str) -> (String, String) {
    let response = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
        .get(authorization_url)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 303);
    let back = response.headers()["location"].to_str().unwrap().to_string();
    assert!(back.starts_with(&format!("{REDIRECT_URI}?")), "{back}");
    let query = query_of(&back);
    (query["code"].clone(), query["state"].clone())
}

/// The IdP returns a step-up callback rather than the normal login callback.
async fn authorize_step_up(authorization_url: &str) -> (String, String) {
    let response = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
        .get(authorization_url)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 303);
    let back = response.headers()["location"].to_str().unwrap().to_string();
    assert!(
        back.starts_with(&format!("{ORIGIN}/auth/step-up/callback?")),
        "{back}"
    );
    let query = query_of(&back);
    (query["code"].clone(), query["state"].clone())
}

/// `GET /auth/callback` with this `Cookie` header and query.
async fn callback_raw(h: &Harness, cookie_header: Option<&str>, query: &[(&str, &str)]) -> Reply {
    let mut url = reqwest::Url::parse("http://console.invalid/auth/callback").unwrap();
    for (name, value) in query {
        url.query_pairs_mut().append_pair(name, value);
    }
    let uri = match url.query() {
        Some(q) => format!("/auth/callback?{q}"),
        None => "/auth/callback".to_string(),
    };
    let headers: Creds = cookie_header
        .map(|c| vec![("cookie", c.to_string())])
        .unwrap_or_default();
    send(&h.app(), "GET", &uri, &headers, None).await
}

async fn callback(h: &Harness, login_cookie: Option<&str>, query: &[(&str, &str)]) -> Reply {
    let header = login_cookie.map(|c| format!("{LOGIN_COOKIE}={c}"));
    callback_raw(h, header.as_deref(), query).await
}

/// A whole sign-in; the session cookie value.
async fn sign_in(h: &Harness) -> String {
    let (cookie, url) = begin(h).await;
    let (code, state) = authorize(&url).await;
    let reply = callback(h, Some(&cookie), &[("code", &code), ("state", &state)]).await;
    assert_eq!(
        (reply.status, reply.location()),
        (StatusCode::SEE_OTHER, "/"),
        "{}",
        reply.text()
    );
    cookie_value(&reply.set_cookie(SESSION_COOKIE).expect("a session cookie"))
}

async fn session(h: &Harness, cookie: &str) -> Reply {
    send(&h.app(), "GET", "/auth/session", &console(cookie), None).await
}

async fn logout(h: &Harness, creds: &Creds) -> Reply {
    send(&h.app(), "POST", "/auth/logout", creds, None).await
}

async fn runtime(h: &Harness, creds: &Creds) -> Reply {
    send(&h.app(), "GET", "/v1/runtime", creds, None).await
}

/// A callback refused with `error`: back to the sign-in page, the login
/// cookie expired, no session cookie, and `sessions` sessions in the table.
fn assert_refused(h: &Harness, reply: &Reply, error: &str, sessions: usize) {
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.text());
    assert_eq!(reply.location(), format!("/signin?error={error}"));
    assert!(
        reply.set_cookie(SESSION_COOKIE).is_none(),
        "{}",
        reply.text()
    );
    assert!(
        reply
            .set_cookie(LOGIN_COOKIE)
            .is_some_and(|c| c.contains("Max-Age=0")),
        "the login cookie is expired: {}",
        reply.text()
    );
    assert_eq!(h.login().session_count(), sessions, "sessions");
}

fn assert_problem(reply: &Reply, status: StatusCode, code: &str) {
    assert_eq!(reply.status, status, "{}", reply.text());
    assert_eq!(reply.json()["code"], code, "{}", reply.text());
}

fn bearer(token: &str) -> Creds {
    vec![("authorization", format!("Bearer {token}"))]
}

// ---- 1. Callback refusals: each creates no session ---------------------------

#[tokio::test]
async fn callback_with_a_wrong_or_missing_state_creates_no_session() {
    let h = harness(|_| {}).await;
    let (cookie, url) = begin(&h).await;
    let (code, state) = authorize(&url).await;
    let reply = callback(
        &h,
        Some(&cookie),
        &[("code", &code), ("state", "not-the-state")],
    )
    .await;
    assert_refused(&h, &reply, "login_failed", 0);
    // The record was used by the failed attempt: the right state now finds nothing.
    let reply = callback(&h, Some(&cookie), &[("code", &code), ("state", &state)]).await;
    assert_refused(&h, &reply, "login_expired", 0);

    let (cookie, url) = begin(&h).await;
    let (code, _) = authorize(&url).await;
    let reply = callback(&h, Some(&cookie), &[("code", &code)]).await;
    assert_refused(&h, &reply, "login_failed", 0);

    // No login cookie: no record.
    let (_, url) = begin(&h).await;
    let (code, state) = authorize(&url).await;
    let reply = callback(&h, None, &[("code", &code), ("state", &state)]).await;
    assert_refused(&h, &reply, "login_expired", 0);

    // The IdP's error answer, even with the right state.
    let (cookie, url) = begin(&h).await;
    let state = query_of(&url)["state"].clone();
    let reply = callback(
        &h,
        Some(&cookie),
        &[("error", "access_denied"), ("state", &state)],
    )
    .await;
    assert_refused(&h, &reply, "login_failed", 0);
}

#[tokio::test]
async fn a_replayed_code_or_login_record_creates_no_session() {
    let h = harness(|_| {}).await;
    let (cookie, url) = begin(&h).await;
    let (code, state) = authorize(&url).await;
    let first = callback(&h, Some(&cookie), &[("code", &code), ("state", &state)]).await;
    assert_eq!(first.location(), "/", "{}", first.text());
    assert_eq!(h.login().session_count(), 1);

    // The same callback again: the login record was used.
    let again = callback(&h, Some(&cookie), &[("code", &code), ("state", &state)]).await;
    assert_refused(&h, &again, "login_expired", 1);

    // The used code with a fresh login record and its state: the IdP refuses it.
    let (fresh, url) = begin(&h).await;
    let fresh_state = query_of(&url)["state"].clone();
    let replay = callback(
        &h,
        Some(&fresh),
        &[("code", &code), ("state", &fresh_state)],
    )
    .await;
    assert_refused(&h, &replay, "login_failed", 1);
}

#[tokio::test]
async fn an_expired_login_record_creates_no_session() {
    let h = harness(|_| {}).await;
    let (cookie, url) = begin(&h).await;
    let (code, state) = authorize(&url).await;
    h.advance(Duration::seconds(console_login::LOGIN_TTL_SECONDS));
    let reply = callback(&h, Some(&cookie), &[("code", &code), ("state", &state)]).await;
    assert_refused(&h, &reply, "login_expired", 0);

    // Just inside the limit it works.
    let (cookie, url) = begin(&h).await;
    let (code, state) = authorize(&url).await;
    h.advance(Duration::seconds(console_login::LOGIN_TTL_SECONDS - 1));
    let reply = callback(&h, Some(&cookie), &[("code", &code), ("state", &state)]).await;
    assert_eq!(reply.location(), "/", "{}", reply.text());
}

#[tokio::test]
async fn a_wrong_code_verifier_creates_no_session() {
    let h = harness(|_| {}).await;
    // Two sign-ins in flight; the code of the first with the record (and so
    // the code_verifier) of the second.
    let (_, url_a) = begin(&h).await;
    let (cookie_b, url_b) = begin(&h).await;
    let (code_a, _) = authorize(&url_a).await;
    let state_b = query_of(&url_b)["state"].clone();
    let reply = callback(
        &h,
        Some(&cookie_b),
        &[("code", &code_a), ("state", &state_b)],
    )
    .await;
    assert_refused(&h, &reply, "login_failed", 0);
}

#[tokio::test]
async fn an_id_token_with_the_wrong_nonce_aud_or_iss_creates_no_session() {
    type Change = fn(&mut oidc_double::Behaviour);
    let h = harness(|_| {}).await;
    let cases: [(&str, Change); 3] = [
        ("nonce", |b| b.id_token_nonce = Some("another-nonce".into())),
        ("aud", |b| b.id_token_aud = Some("kavach-api".into())),
        ("iss", |b| {
            b.id_token_iss = Some("https://other-idp.test".into());
        }),
    ];
    for (what, change) in cases {
        h.idp.set(change);
        let (cookie, url) = begin(&h).await;
        let (code, state) = authorize(&url).await;
        let reply = callback(&h, Some(&cookie), &[("code", &code), ("state", &state)]).await;
        assert_eq!(reply.location(), "/signin?error=login_failed", "{what}");
        assert_refused(&h, &reply, "login_failed", 0);
        h.idp.set(|b| {
            b.id_token_nonce = None;
            b.id_token_aud = None;
            b.id_token_iss = None;
        });
    }
    // With the double back to normal, the same flow signs in.
    sign_in(&h).await;
}

#[tokio::test]
async fn an_access_token_the_verifier_refuses_creates_no_session() {
    let h = harness(|_| {}).await;
    h.idp.set(|b| b.access_aud = Some("another-api".into()));
    let (cookie, url) = begin(&h).await;
    let (code, state) = authorize(&url).await;
    let reply = callback(&h, Some(&cookie), &[("code", &code), ("state", &state)]).await;
    assert_refused(&h, &reply, "login_failed", 0);
}

// ---- 2. Cookie attributes, and a new session id -------------------------------

#[tokio::test]
async fn login_and_session_cookies_are_exactly_as_in_decision_1() {
    let h = harness(|_| {}).await;
    let login = send(&h.app(), "GET", "/auth/login", &vec![], None).await;
    let line = login.set_cookie(LOGIN_COOKIE).unwrap();
    let login_cookie = cookie_value(&line);
    assert_eq!(
        line,
        format!(
            "{LOGIN_COOKIE}={login_cookie}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600"
        )
    );
    assert_eq!(login.set_cookies().len(), 1);
    let to_idp = login.location();
    assert!(
        to_idp.starts_with(&h.idp.authorization_endpoint()),
        "{to_idp}"
    );
    let asked = query_of(to_idp);
    assert_eq!(asked["response_type"], "code");
    assert_eq!(asked["client_id"], CLIENT_ID);
    assert_eq!(asked["redirect_uri"], REDIRECT_URI);
    assert_eq!(asked["code_challenge_method"], "S256");
    assert!(asked["scope"].split(' ').any(|s| s == "openid"));
    for random in ["state", "nonce", "code_challenge"] {
        assert_eq!(
            URL_SAFE_NO_PAD.decode(&asked[random]).unwrap().len(),
            32,
            "{random}"
        );
    }

    let (code, state) = authorize(to_idp).await;
    let reply = callback(
        &h,
        Some(&login_cookie),
        &[("code", &code), ("state", &state)],
    )
    .await;
    assert_eq!(reply.location(), "/");
    let line = reply.set_cookie(SESSION_COOKIE).unwrap();
    let session_cookie = cookie_value(&line);
    // No Domain, no Max-Age or Expires: it ends with the browser session,
    // and the server ends it at the idle or absolute limit.
    assert_eq!(
        line,
        format!("{SESSION_COOKIE}={session_cookie}; HttpOnly; Secure; SameSite=Strict; Path=/")
    );
    assert_eq!(
        reply.set_cookie(LOGIN_COOKIE).unwrap(),
        format!("{LOGIN_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0")
    );
    assert_eq!(
        URL_SAFE_NO_PAD.decode(&session_cookie).unwrap().len(),
        32,
        "256-bit"
    );
    for r in [&login, &reply] {
        assert_eq!(r.headers["cache-control"], "no-store");
        assert_eq!(r.headers["referrer-policy"], "no-referrer");
    }
}

#[tokio::test]
async fn every_login_gets_a_new_session_id_never_a_pre_login_one() {
    let h = harness(|_| {}).await;
    let planted = URL_SAFE_NO_PAD.encode([9u8; 32]);
    let (login_cookie, url) = begin(&h).await;
    let (code, state) = authorize(&url).await;
    let reply = callback_raw(
        &h,
        Some(&format!(
            "{SESSION_COOKIE}={planted}; {LOGIN_COOKIE}={login_cookie}"
        )),
        &[("code", &code), ("state", &state)],
    )
    .await;
    let first = cookie_value(&reply.set_cookie(SESSION_COOKIE).unwrap());
    assert_ne!(first, planted);
    assert_ne!(first, login_cookie);
    assert_eq!(session(&h, &planted).await.status, StatusCode::UNAUTHORIZED);

    let second = sign_in(&h).await;
    assert_ne!(second, first);
    assert_eq!(session(&h, &first).await.status, StatusCode::OK);
    assert_eq!(session(&h, &second).await.status, StatusCode::OK);
}

// ---- 3. CSRF checks; the cookie on the agent and SoR listeners ----------------

#[tokio::test]
async fn a_session_cookie_without_the_console_header_is_refused() {
    let h = harness(|_| {}).await;
    let cookie = sign_in(&h).await;
    assert_eq!(runtime(&h, &console(&cookie)).await.status, StatusCode::OK);
    for creds in [
        without(console(&cookie), "x-kavach-console"),
        with(console(&cookie), "x-kavach-console", "0"),
        with(console(&cookie), "x-kavach-console", "true"),
    ] {
        assert_problem(
            &runtime(&h, &creds).await,
            StatusCode::FORBIDDEN,
            "forbidden",
        );
        assert_problem(
            &send(&h.app(), "GET", "/auth/session", &creds, None).await,
            StatusCode::FORBIDDEN,
            "forbidden",
        );
        assert_problem(
            &logout(&h, &creds).await,
            StatusCode::FORBIDDEN,
            "forbidden",
        );
        let (status, _) = common::propose(
            &h.app(),
            &creds,
            "update_retention",
            json!({ "evidence_retention_days": 30 }),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
    // Refused before the session is looked up: an unknown cookie is a 403 too.
    let unknown = without(console("no-such-session"), "x-kavach-console");
    assert_problem(
        &runtime(&h, &unknown).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    // The refused logout ended nothing.
    assert_eq!(session(&h, &cookie).await.status, StatusCode::OK);
}

#[tokio::test]
async fn a_session_cookie_from_a_cross_site_origin_or_fetch_site_is_refused() {
    let h = harness(|_| {}).await;
    let cookie = sign_in(&h).await;
    let mut refused = Vec::new();
    for origin in [
        "https://evil.test",
        "null",
        "http://console.kavach.test",
        "https://console.kavach.test:8443",
        "https://kavach.test",
    ] {
        refused.push(with(console(&cookie), "origin", origin));
    }
    for site in ["cross-site", "same-site"] {
        refused.push(with(console(&cookie), "sec-fetch-site", site));
    }
    for creds in &refused {
        assert_problem(
            &runtime(&h, creds).await,
            StatusCode::FORBIDDEN,
            "forbidden",
        );
        assert_problem(&logout(&h, creds).await, StatusCode::FORBIDDEN, "forbidden");
        assert_problem(
            &send(&h.app(), "GET", "/auth/session", creds, None).await,
            StatusCode::FORBIDDEN,
            "forbidden",
        );
    }
    // Same origin, or a request the user started ("none"), or a client that
    // sends neither header (not a browser): accepted.
    for creds in [
        console(&cookie),
        with(console(&cookie), "sec-fetch-site", "none"),
        without(without(console(&cookie), "origin"), "sec-fetch-site"),
    ] {
        assert_eq!(runtime(&h, &creds).await.status, StatusCode::OK);
    }
    assert_eq!(session(&h, &cookie).await.status, StatusCode::OK);
}

#[tokio::test]
async fn a_session_cookie_with_a_credential_header_is_refused() {
    let h = harness(|_| {}).await;
    let cookie = sign_in(&h).await;
    let other = h.idp.mint_access_token(&user("ops-2", &["admins"]));
    for creds in [
        with(
            console(&cookie),
            "authorization",
            &format!("Bearer {other}"),
        ),
        with(console(&cookie), "x-kavach-principal", "admin-1"),
        with(
            console("no-such-session"),
            "authorization",
            &format!("Bearer {other}"),
        ),
    ] {
        assert_problem(
            &runtime(&h, &creds).await,
            StatusCode::BAD_REQUEST,
            "bad_request",
        );
        assert_problem(
            &send(&h.app(), "GET", "/auth/session", &creds, None).await,
            StatusCode::BAD_REQUEST,
            "bad_request",
        );
        assert_problem(
            &logout(&h, &creds).await,
            StatusCode::BAD_REQUEST,
            "bad_request",
        );
    }
    // The token alone works as before.
    assert_eq!(runtime(&h, &bearer(&other)).await.status, StatusCode::OK);
    assert_eq!(session(&h, &cookie).await.status, StatusCode::OK);
}

#[tokio::test]
async fn the_session_cookie_is_refused_on_the_agent_listener_and_never_read_by_the_sor_listener() {
    let h = harness_on(agents_config(), admin(), |_| {}).await;
    let cookie = sign_in(&h).await;
    // Past the access token's refresh point: a listener that looked the
    // session up would refresh it, which the double counts.
    h.advance(Duration::minutes(5));
    let agent = contract::agent_router(h.state.clone());
    let body =
        json!({ "tool": "send_reminder", "mandate_id": "m", "request_id": "r", "params": {} });
    for uri in ["/v1/authorize", "/v1/tools/send_reminder"] {
        let reply = send(&agent, "POST", uri, &console(&cookie), Some(body.clone())).await;
        assert_problem(&reply, StatusCode::UNAUTHORIZED, "unauthorized");
    }
    // The system-of-record listener authenticates signed events only: the
    // same refusal with the cookie as without it.
    let sor = contract::sor_router(h.state.clone());
    let event = json!({ "event": "not-a-signed-event" });
    let bare = send(&sor, "POST", "/v1/sor/events", &vec![], Some(event.clone())).await;
    let with_cookie = send(
        &sor,
        "POST",
        "/v1/sor/events",
        &console(&cookie),
        Some(event),
    )
    .await;
    assert!(bare.status.is_client_error(), "{}", bare.text());
    assert_eq!(with_cookie.status, bare.status, "{}", with_cookie.text());
    assert_eq!(with_cookie.json()["code"], bare.json()["code"]);

    // Neither listener read the cookie: the session was never looked up (no
    // refresh), although the operator listener refreshes it at once.
    assert_eq!(
        h.idp.refreshes(),
        0,
        "the agent or SoR listener read the cookie"
    );
    assert_eq!(session(&h, &cookie).await.status, StatusCode::OK);
    assert_eq!(h.idp.refreshes(), 1);
}

// ---- 4. Idle and absolute limits, refresh, logout --------------------------

#[tokio::test]
async fn the_idle_limit_ends_a_session() {
    let h = harness(|s| s.idle_minutes = 15).await;
    let cookie = sign_in(&h).await;
    // Activity keeps it.
    h.advance(Duration::minutes(14));
    assert_eq!(session(&h, &cookie).await.status, StatusCode::OK);
    h.advance(Duration::minutes(14));
    assert_eq!(runtime(&h, &console(&cookie)).await.status, StatusCode::OK);
    // Fifteen minutes without a request.
    h.advance(Duration::minutes(15));
    assert_problem(
        &session(&h, &cookie).await,
        StatusCode::UNAUTHORIZED,
        "unauthorized",
    );
    assert_problem(
        &runtime(&h, &console(&cookie)).await,
        StatusCode::UNAUTHORIZED,
        "unauthorized",
    );
    assert_eq!(h.login().session_count(), 0);
}

#[tokio::test]
async fn a_refresh_that_rotates_the_refresh_token_never_extends_the_absolute_limit() {
    let h = harness(|s| {
        s.idle_minutes = 15;
        s.absolute_minutes = 60;
    })
    .await;
    h.idp.set(|b| b.rotate_refresh = true);
    let cookie = sign_in(&h).await;
    let first = session(&h, &cookie).await.json();
    let expires_at = first["expires_at"].clone();
    for step in 1..=5 {
        // Each step is past the access token's refresh point (300 s, 60 s margin).
        h.advance(Duration::minutes(10));
        let view = session(&h, &cookie).await;
        assert_eq!(view.status, StatusCode::OK, "step {step}: {}", view.text());
        assert_eq!(view.json()["expires_at"], expires_at, "step {step}");
        assert_eq!(runtime(&h, &console(&cookie)).await.status, StatusCode::OK);
    }
    assert_eq!(h.idp.refreshes(), 5);
    // The double retires each presented refresh token: five refreshes that
    // all worked means the server used every rotated one.
    assert_eq!(h.idp.live_refresh_tokens(), 1);

    // Sixty minutes after sign-in, whatever the refreshes did.
    h.advance(Duration::minutes(10));
    assert_problem(
        &session(&h, &cookie).await,
        StatusCode::UNAUTHORIZED,
        "unauthorized",
    );
    assert_eq!(h.login().session_count(), 0);
    assert_eq!(h.idp.refreshes(), 5, "no refresh after the absolute limit");
}

#[tokio::test]
async fn a_failed_refresh_ends_the_session() {
    let h = harness(|_| {}).await;
    let cookie = sign_in(&h).await;
    h.idp.set(|b| b.refuse_refresh = true);
    // Not yet at the refresh point: nothing is refreshed.
    h.advance(Duration::seconds(
        300 - console_login::REFRESH_MARGIN_SECONDS - 1,
    ));
    assert_eq!(session(&h, &cookie).await.status, StatusCode::OK);
    assert_eq!(h.idp.refreshes(), 0);
    h.advance(Duration::seconds(1));
    assert_problem(
        &runtime(&h, &console(&cookie)).await,
        StatusCode::UNAUTHORIZED,
        "unauthorized",
    );
    assert_eq!(h.idp.refreshes(), 1);
    assert_eq!(h.login().session_count(), 0);

    // No refresh token at all: the session ends at the refresh point.
    let h = harness(|_| {}).await;
    h.idp.set(|b| b.issue_refresh = false);
    let cookie = sign_in(&h).await;
    h.advance(Duration::seconds(
        300 - console_login::REFRESH_MARGIN_SECONDS,
    ));
    assert_problem(
        &session(&h, &cookie).await,
        StatusCode::UNAUTHORIZED,
        "unauthorized",
    );
}

#[tokio::test]
async fn logout_makes_the_old_cookie_useless() {
    let h = harness(|_| {}).await;
    let cookie = sign_in(&h).await;
    let reply = logout(&h, &console(&cookie)).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    assert_eq!(
        reply.set_cookie(SESSION_COOKIE).unwrap(),
        format!("{SESSION_COOKIE}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0")
    );
    assert_eq!(
        reply.set_cookie(LOGIN_COOKIE).unwrap(),
        format!("{LOGIN_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0")
    );
    // The refresh token was revoked at the IdP (RFC 7009).
    assert_eq!(h.idp.revoked(), 1);
    assert_eq!(h.idp.live_refresh_tokens(), 0);

    assert_problem(
        &session(&h, &cookie).await,
        StatusCode::UNAUTHORIZED,
        "unauthorized",
    );
    assert_problem(
        &runtime(&h, &console(&cookie)).await,
        StatusCode::UNAUTHORIZED,
        "unauthorized",
    );
    let again = logout(&h, &console(&cookie)).await;
    assert_problem(&again, StatusCode::UNAUTHORIZED, "unauthorized");
    assert!(again
        .set_cookie(SESSION_COOKIE)
        .unwrap()
        .contains("Max-Age=0"));

    let actions: Vec<String> = h
        .state
        .admin()
        .list_audit(50)
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.action)
        .collect();
    assert!(
        actions.contains(&"console_login".to_string()),
        "{actions:?}"
    );
    assert!(
        actions.contains(&"console_logout".to_string()),
        "{actions:?}"
    );
}

// ---- 5. IdP logout -----------------------------------------------------------

#[tokio::test]
async fn logout_with_idp_logout_off_returns_no_end_session_url() {
    let h = harness(|_| {}).await;
    let cookie = sign_in(&h).await;
    let reply = logout(&h, &console(&cookie)).await;
    assert_eq!(reply.json(), json!({ "end_session_url": null }));
}

#[tokio::test]
async fn logout_with_idp_logout_on_returns_an_end_session_url_without_id_token_hint() {
    let h = harness(|s| s.idp_logout = true).await;
    let cookie = sign_in(&h).await;
    let reply = logout(&h, &console(&cookie)).await;
    let url = reply.json()["end_session_url"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        url.starts_with(&format!("{}?", h.idp.end_session_endpoint())),
        "{url}"
    );
    let query = query_of(&url);
    assert_eq!(
        query,
        HashMap::from([
            ("client_id".to_string(), CLIENT_ID.to_string()),
            (
                "post_logout_redirect_uri".to_string(),
                format!("{ORIGIN}/signin")
            ),
        ])
    );
    assert!(!url.contains("id_token_hint"), "{url}");
    for token in h.idp.issued() {
        assert!(!url.contains(&token), "a token in the end-session URL");
    }
}

// ---- 6. A full session table ----------------------------------------------------

#[tokio::test]
async fn a_full_session_table_refuses_a_new_login_and_keeps_every_session() {
    let h = harness(|s| s.max_sessions = 2).await;
    // Started while there was room; it reaches the callback once the table is full.
    let (late_cookie, late_url) = begin(&h).await;
    let (late_code, late_state) = authorize(&late_url).await;
    let a = sign_in(&h).await;
    let b = sign_in(&h).await;

    let refused = send(&h.app(), "GET", "/auth/login", &vec![], None).await;
    assert_eq!(refused.status, StatusCode::SEE_OTHER);
    assert_eq!(refused.location(), "/signin?error=sessions_full");
    assert!(refused.set_cookie(LOGIN_COOKIE).is_none());

    let late = callback(
        &h,
        Some(&late_cookie),
        &[("code", &late_code), ("state", &late_state)],
    )
    .await;
    assert_refused(&h, &late, "sessions_full", 2);
    assert_eq!(
        h.idp.revoked(),
        1,
        "the refused session's refresh token is revoked"
    );

    for cookie in [&a, &b] {
        assert_eq!(session(&h, cookie).await.status, StatusCode::OK);
        assert_eq!(runtime(&h, &console(cookie)).await.status, StatusCode::OK);
    }
    // A logout makes room.
    assert_eq!(logout(&h, &console(&a)).await.status, StatusCode::OK);
    let c = sign_in(&h).await;
    assert_eq!(session(&h, &c).await.status, StatusCode::OK);
    assert_eq!(session(&h, &b).await.status, StatusCode::OK);
}

// ---- 7. Cedar through a session ------------------------------------------------

async fn restrict(h: &Harness, creds: &Creds) -> (StatusCode, Value) {
    common::call(
        &h.app(),
        "POST",
        &format!("/v1/agents/{AGENT}/restrict"),
        creds,
        Some(json!({ "reason_code": "rogue_behaviour", "note": "console session test" })),
    )
    .await
}

#[tokio::test]
async fn a_viewer_session_cannot_stop_an_agent() {
    let h = harness_on(agents_config(), user("viewer-1", &["viewers"]), |_| {}).await;
    let viewer = sign_in(&h).await;
    let (status, body) = restrict(&h, &console(&viewer)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["code"], "forbidden");
    // The 403 is Cedar's: an admin's session may.
    h.idp.set(|b| b.user = admin());
    let admin = sign_in(&h).await;
    let (status, body) = restrict(&h, &console(&admin)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn the_session_names_the_groups_cedar_evaluates_the_principal_in() {
    // `viewer-1` is a member of `viewers` in the entities file; its token
    // adds `operators`. Cedar sees both, so the console's hints must too.
    let h = harness_as(user("viewer-1", &["operators"]), |_| {}).await;
    let cookie = sign_in(&h).await;
    let reply = session(&h, &cookie).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    assert_eq!(reply.json()["groups"], json!(["operators", "viewers"]));
}

#[tokio::test]
async fn with_no_policy_loaded_the_session_groups_are_unknown() {
    // `--access-control none` (development only): groups decide nothing,
    // so the session says it does not know them and the console shows
    // every control.
    let mut config = plain_config(true);
    config.access_control = kavach_api::AccessControlKind::None;
    let h = harness_on(config, admin(), |_| {}).await;
    let cookie = sign_in(&h).await;
    let reply = session(&h, &cookie).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    assert_eq!(reply.json()["groups"], Value::Null);
}

#[tokio::test]
async fn the_proposer_cannot_approve_their_own_change_through_a_second_session() {
    let proposer = user("ops-1", &["admins", "change-approvers"]);
    let h = harness_as(proposer, |_| {}).await;
    let first = sign_in(&h).await;
    let second = sign_in(&h).await;
    assert_ne!(first, second);
    let (status, request) = common::propose(
        &h.app(),
        &console(&first),
        "update_retention",
        json!({ "evidence_retention_days": 30 }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{request}");
    assert_eq!(request["proposer_key"], format!("oidc:{ISSUER}#ops-1"));
    let (status, body) = common::approve(&h.app(), &console(&second), &request).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // Another person, through their own session, may.
    h.idp
        .set(|b| b.user = user("approver-2", &["change-approvers"]));
    let other = sign_in(&h).await;
    let (status, body) = common::approve(&h.app(), &console(&other), &request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// The browser at the IdP with the double's user cookie naming `sub`.
async fn authorize_named(authorization_url: &str, sub: &str) -> reqwest::Response {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
        .get(authorization_url)
        .header("cookie", format!("{}={sub}", oidc_double::USER_COOKIE))
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn the_double_signs_in_the_user_its_cookie_names_and_refuses_an_unknown_one() {
    // The Playwright checks against a live stack pick who signs in this way.
    let h = harness(|_| {}).await;
    let viewer = user("live-viewer", &["viewers"]);
    h.idp
        .set(|b| b.users = HashMap::from([(viewer.sub.clone(), viewer.clone())]));

    let (cookie, url) = begin(&h).await;
    let response = authorize_named(&url, "live-viewer").await;
    assert_eq!(response.status().as_u16(), 303);
    let back = query_of(response.headers()["location"].to_str().unwrap());
    let reply = callback(
        &h,
        Some(&cookie),
        &[("code", &back["code"]), ("state", &back["state"])],
    )
    .await;
    let session_cookie = cookie_value(&reply.set_cookie(SESSION_COOKIE).expect("a session"));
    let reply = session(&h, &session_cookie).await;
    assert_eq!(reply.json()["principal"], "live-viewer", "{}", reply.text());

    let (_, url) = begin(&h).await;
    let response = authorize_named(&url, "nobody-configured").await;
    assert_eq!(response.status().as_u16(), 400);

    // No cookie: the configured user, as before.
    let cookie = sign_in(&h).await;
    assert_eq!(session(&h, &cookie).await.json()["principal"], "ops-1");
}

#[tokio::test]
async fn the_double_in_pick_mode_asks_who_signs_in_and_signs_in_the_one_picked() {
    // scripts/demo.sh runs the double with --pick, for a person at a browser.
    let h = harness(|_| {}).await;
    let viewer = user("live-viewer", &["viewers"]);
    let odd = user("a<b>&\"c'", &["viewers"]);
    h.idp.set(|b| {
        b.users = HashMap::from([
            (viewer.sub.clone(), viewer.clone()),
            (odd.sub.clone(), odd.clone()),
        ]);
        b.pick = true;
    });

    let (cookie, url) = begin(&h).await;
    let state = query_of(&url)["state"].clone();
    // The cookie is not read: the page comes back, not a redirect.
    let page = authorize_named(&url, "live-viewer").await;
    assert_eq!(page.status().as_u16(), 200);
    assert_eq!(page.headers()["cache-control"], "no-store");
    assert!(page.headers()["content-security-policy"]
        .to_str()
        .unwrap()
        .starts_with("default-src 'none'"));
    let html = page.text().await.unwrap();
    assert!(!html.contains("<script"), "{html}");
    // Every user is listed (the default one too), and a sub is escaped.
    assert!(html.contains(">ops-1</a>"), "{html}");
    assert!(html.contains(">live-viewer</a>"), "{html}");
    assert!(html.contains("a&lt;b&gt;&amp;&quot;c&#39;"), "{html}");
    assert!(!html.contains("a<b>"), "{html}");

    let links: Vec<String> = html
        .split("href=\"")
        .skip(1)
        .map(|rest| rest.split('"').next().unwrap().replace("&amp;", "&"))
        .filter(|href| href.contains("/authorize?"))
        .collect();
    assert_eq!(links.len(), 3, "{html}");
    let pick = links
        .iter()
        .find(|link| query_of(link).get("login_as").map(String::as_str) == Some("live-viewer"))
        .expect("a link for live-viewer");
    assert_eq!(query_of(pick)["state"], state, "the link keeps the request");

    let response = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
        .get(pick)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 303);
    let back = query_of(response.headers()["location"].to_str().unwrap());
    let reply = callback(
        &h,
        Some(&cookie),
        &[("code", &back["code"]), ("state", &back["state"])],
    )
    .await;
    let session_cookie = cookie_value(&reply.set_cookie(SESSION_COOKIE).expect("a session"));
    assert_eq!(
        session(&h, &session_cookie).await.json()["principal"],
        "live-viewer"
    );

    // A login_as the double does not know is refused, never the default.
    let (_, url) = begin(&h).await;
    let mut unknown = reqwest::Url::parse(&url).unwrap();
    unknown
        .query_pairs_mut()
        .append_pair("login_as", "nobody-configured");
    let response = reqwest::get(unknown).await.unwrap();
    assert_eq!(response.status().as_u16(), 400);
}

#[tokio::test]
async fn a_session_and_a_cli_token_of_one_person_are_one_identity() {
    let person = user("ops-1", &["admins", "change-approvers"]);
    let retention = json!({ "evidence_retention_days": 30 });

    // Proposed through a session, approved with the person's CLI token: refused.
    let h = harness_as(person.clone(), |_| {}).await;
    let cli = bearer(&h.idp.mint_access_token(&person));
    let cookie = sign_in(&h).await;
    let (status, request) = common::propose(
        &h.app(),
        &console(&cookie),
        "update_retention",
        retention.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{request}");
    let session_key = request["proposer_key"].clone();
    let (status, body) = common::approve(&h.app(), &cli, &request).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // Proposed with the CLI token, approved through a session: refused.
    let h = harness_as(person.clone(), |_| {}).await;
    let cli = bearer(&h.idp.mint_access_token(&person));
    let (status, request) = common::propose(&h.app(), &cli, "update_retention", retention).await;
    assert_eq!(status, StatusCode::CREATED, "{request}");
    assert_eq!(request["proposer_key"], session_key, "one identity key");
    let cookie = sign_in(&h).await;
    let (status, body) = common::approve(&h.app(), &console(&cookie), &request).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

// ---- 8. Logs and responses carry no token material ------------------------------

/// Everything secret the flow handled: every code and token the IdP issued,
/// the client secret and its Basic encoding.
fn secrets(h: &Harness) -> Vec<String> {
    let mut all = h.idp.issued();
    all.push(CLIENT_SECRET.to_string());
    all.push(STANDARD.encode(format!("{CLIENT_ID}:{CLIENT_SECRET}")));
    all
}

/// Runs every `/auth/*` route through success and refusal; returns every reply
/// and the session and login cookie values it saw.
async fn exercise_every_auth_route(h: &Harness) -> (Vec<Reply>, Vec<String>) {
    let mut replies = Vec::new();
    let mut cookies = Vec::new();
    let app = h.app();
    replies.push(send(&app, "GET", "/auth/config", &vec![], None).await);

    // A refused callback (wrong nonce), then a good sign-in.
    h.idp.set(|b| b.id_token_nonce = Some("wrong".into()));
    let (cookie, url) = begin(h).await;
    let (code, state) = authorize(&url).await;
    replies.push(callback(h, Some(&cookie), &[("code", &code), ("state", &state)]).await);
    h.idp.set(|b| b.id_token_nonce = None);
    cookies.push(cookie);

    let login = send(&app, "GET", "/auth/login", &vec![], None).await;
    let login_cookie = cookie_value(&login.set_cookie(LOGIN_COOKIE).unwrap());
    let (code, state) = authorize(login.location()).await;
    replies.push(login);
    let signed_in = callback(
        h,
        Some(&login_cookie),
        &[("code", &code), ("state", &state)],
    )
    .await;
    let session_cookie = cookie_value(&signed_in.set_cookie(SESSION_COOKIE).unwrap());
    replies.push(signed_in);
    cookies.push(login_cookie);
    cookies.push(session_cookie.clone());

    replies.push(session(h, &session_cookie).await);
    replies.push(runtime(h, &console(&session_cookie)).await);
    // Past the refresh point: the refresh is invisible to the browser.
    h.advance(Duration::minutes(5));
    replies.push(session(h, &session_cookie).await);
    replies.push(
        send(
            &app,
            "GET",
            "/auth/session",
            &without(console(&session_cookie), "x-kavach-console"),
            None,
        )
        .await,
    );
    replies.push(
        logout(
            h,
            &with(console(&session_cookie), "authorization", "Bearer x"),
        )
        .await,
    );
    replies.push(logout(h, &console(&session_cookie)).await);
    replies.push(session(h, &session_cookie).await);
    replies.push(logout(h, &console(&session_cookie)).await);
    (replies, cookies)
}

#[tokio::test]
async fn no_auth_response_carries_token_material() {
    let h = harness(|s| s.idp_logout = true).await;
    h.idp.set(|b| b.rotate_refresh = true);
    let (replies, cookies) = exercise_every_auth_route(&h).await;
    assert!(h.idp.refreshes() >= 1, "the run included a refresh");
    let secrets = secrets(&h);
    assert!(secrets.len() > 5, "the scan has something to look for");
    for reply in &replies {
        let text = reply.text();
        for secret in &secrets {
            assert!(
                !text.contains(secret.as_str()),
                "token material in a response:\n{text}"
            );
        }
        // No JWT of any kind (a JOSE header starts with eyJ).
        assert!(!text.contains("eyJ"), "a JWT in a response:\n{text}");
        assert_eq!(reply.headers["cache-control"], "no-store", "{text}");
        assert_eq!(reply.headers["referrer-policy"], "no-referrer", "{text}");
    }
    // The cookie values are random handles, not tokens.
    for cookie in &cookies {
        assert_eq!(URL_SAFE_NO_PAD.decode(cookie).unwrap().len(), 32);
        assert!(!secrets.contains(cookie));
    }
}

#[tokio::test]
async fn logs_carry_no_session_cookie_token_or_client_secret() {
    let h = harness(|s| s.idp_logout = true).await;
    h.idp.set(|b| b.rotate_refresh = true);
    let (_, cookies) = exercise_every_auth_route(&h).await;
    // The full-table refusal revokes at the IdP and logs nothing secret either.
    let text = log_text();
    assert!(
        text.lines()
            .any(|l| l.contains("handled") && l.contains("/auth/callback")),
        "the capture sees this binary's requests:\n{text}"
    );
    for secret in secrets(&h).iter().chain(&cookies) {
        assert!(
            !text.contains(secret.as_str()),
            "a secret in the logs:\n{text}"
        );
    }
    // The redactor is the backstop, not the property: no token may reach the
    // logger at all, so its markers must not appear either. Without this, an
    // access token (a JWT) logged by the flow is masked and the scan passes.
    for marker in [
        "eyJ",
        "Bearer ey",
        "Basic a2F2",
        "[redacted-token]",
        "[redacted]",
    ] {
        assert!(!text.contains(marker), "{marker} in the logs:\n{text}");
    }
}

// ---- Off unless configured ------------------------------------------------------

#[tokio::test]
async fn auth_config_says_whether_login_is_configured() {
    let h = harness(|_| {}).await;
    let reply = send(&h.app(), "GET", "/auth/config", &vec![], None).await;
    assert_eq!(
        reply.json(),
        json!({ "login_configured": true, "pasted_token_allowed": false })
    );
    for (insecure_dev, pasted) in [(false, false), (true, true)] {
        let state = Arc::new(
            AppState::from_config(&plain_config(insecure_dev))
                .await
                .unwrap(),
        );
        let reply = send(
            &contract::router(state),
            "GET",
            "/auth/config",
            &vec![],
            None,
        )
        .await;
        assert_eq!(
            reply.json(),
            json!({ "login_configured": false, "pasted_token_allowed": pasted })
        );
    }
}

#[tokio::test]
async fn without_login_configured_the_cookie_is_never_read() {
    let state = Arc::new(AppState::from_config(&api_config()).await.unwrap());
    let app = contract::router(state);
    let token = agent_fixture::operator_token();
    // A session cookie beside a token: not a 400; the token decides, as before.
    let creds = with(
        console("anything"),
        "authorization",
        &format!("Bearer {token}"),
    );
    assert_eq!(
        send(&app, "GET", "/v1/runtime", &creds, None).await.status,
        StatusCode::OK
    );
    // The cookie alone is no credential.
    let reply = send(&app, "GET", "/v1/runtime", &console("anything"), None).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    // The routes answer "not configured".
    let login = send(&app, "GET", "/auth/login", &vec![], None).await;
    assert_eq!(login.location(), "/signin?error=login_unavailable");
    assert!(login.set_cookie(LOGIN_COOKIE).is_none());
    let reply = send(&app, "GET", "/auth/session", &console("anything"), None).await;
    assert_problem(&reply, StatusCode::UNAUTHORIZED, "unauthorized");
}

// ---- 9. Startup refusals (Decision 6.2) -------------------------------------------

fn refused(settings: &ConsoleLoginSettings, config: &ApiConfig) -> String {
    console_login::validate(settings, config).expect_err("refused")
}

#[test]
fn session_limits_just_outside_each_bound_are_refused() {
    let config = api_config();
    let mut s = settings();
    for (idle, absolute, max_sessions, ok) in [
        (5, 5, 1, true),
        (60, 720, 10_000, true),
        (15, 480, 1000, true),
        (4, 480, 1000, false),
        (61, 480, 1000, false),
        (15, 721, 1000, false),
        (30, 29, 1000, false),
        (15, 480, 0, false),
        (15, 480, 10_001, false),
    ] {
        s.idle_minutes = idle;
        s.absolute_minutes = absolute;
        s.max_sessions = max_sessions;
        assert_eq!(
            console_login::validate(&s, &config).is_ok(),
            ok,
            "idle {idle}, absolute {absolute}, max {max_sessions}"
        );
    }
}

#[test]
fn d17_step_up_acr_is_bounded_and_rejects_controls_or_surrounding_space() {
    let config = api_config();
    for acr in ["webauthn-2", "urn:kavach:acr:webauthn"] {
        let mut s = settings();
        s.step_up_acr = Some(acr.into());
        console_login::validate(&s, &config).expect("valid configured ACR");
    }
    let too_long = "a".repeat(129);
    for acr in [
        "",
        " webauthn-2",
        "webauthn-2 ",
        "weak\nacr",
        too_long.as_str(),
    ] {
        let mut s = settings();
        s.step_up_acr = Some(acr.into());
        assert!(
            refused(&s, &config).contains("--console-step-up-acr"),
            "ACR {acr:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn d17_live_step_up_decision_and_approved_agent_execution_in_memory() {
    d17_live_step_up_decision_and_approved_agent_execution(EvidenceStoreKind::Memory, None).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn d17_live_step_up_decision_and_approved_agent_execution_on_postgres() {
    let Some((owner, runtime)) = kavach_storage::testing::isolated_database_urls().await else {
        return;
    };
    d17_live_step_up_decision_and_approved_agent_execution(
        EvidenceStoreKind::Postgres {
            database_url: runtime,
        },
        Some(owner),
    )
    .await;
}

async fn d17_live_step_up_decision_and_approved_agent_execution(
    store: EvidenceStoreKind,
    migration_database_url: Option<String>,
) {
    const ACR: &str = "urn:kavach:test:webauthn";
    let at = Utc::now() - Duration::seconds(5);
    let clock = Arc::new(FakeClock::synced_at(at));
    let mut config = agent_fixture::config(store, true, 50);
    config.migration_database_url = migration_database_url;
    config.dataplane.as_mut().unwrap().test_clock = Some(TestClock(clock));
    agent_fixture::enable_review_snapshots(&mut config);
    // Exercise the production Cedar path with a bootstrapped superadmin,
    // including the exact-action review permission used by step-up.
    config.roles.bootstrap_superadmins = vec![
        kavach_storage::BindingSubject {
            kind: kavach_storage::SubjectKind::Principal,
            issuer: ISSUER.into(),
            value: "ops-1".into(),
        },
        kavach_storage::BindingSubject {
            kind: kavach_storage::SubjectKind::Principal,
            issuer: ISSUER.into(),
            value: "ops-2".into(),
        },
    ];
    let h = harness_on(config, admin(), |settings| {
        settings.step_up_acr = Some(ACR.into());
    })
    .await;

    let session_cookie = sign_in(&h).await;
    let mandate = agent_fixture::issue_at(&h.state, "d17-live-review", at).await;
    let request_id = "d17-live-request";
    let action = json!({
        "mandate_id": mandate,
        "request_id": request_id,
        "params": { "subject_ref": agent_fixture::SUBJECT, "waiver_bps": 3500 }
    });
    let (status, review) = agent_fixture::send(
        contract::agent_router(h.state.clone()),
        "/v1/tools/propose_plan",
        &[(
            "authorization",
            format!("Bearer {}", agent_fixture::agent_token(AGENT)),
        )],
        action.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{review}");
    assert_eq!(review["decision"], "HUMAN_REVIEW");
    let record_id = review["record_id"].as_str().expect("review record id");

    let started = send(
        &h.app(),
        "POST",
        &format!("/auth/step-up/{record_id}"),
        &console(&session_cookie),
        None,
    )
    .await;
    assert_eq!(started.status, StatusCode::OK, "{}", started.text());
    let step_up_cookie = cookie_value(
        &started
            .set_cookie(STEP_UP_COOKIE)
            .expect("opaque step-up callback cookie"),
    );
    let started_body = started.json();
    let authorization_url = started_body["authorization_url"]
        .as_str()
        .expect("step-up authorization URL");
    let (code, state) = authorize_step_up(authorization_url).await;
    let mut callback_url =
        reqwest::Url::parse("http://console.invalid/auth/step-up/callback").unwrap();
    callback_url
        .query_pairs_mut()
        .append_pair("code", &code)
        .append_pair("state", &state);
    let callback_creds = vec![(
        "cookie",
        format!("{SESSION_COOKIE}={session_cookie}; {STEP_UP_COOKIE}={step_up_cookie}"),
    )];
    let callback = send(
        &h.app(),
        "GET",
        &format!("{}?{}", callback_url.path(), callback_url.query().unwrap()),
        &callback_creds,
        None,
    )
    .await;
    assert_eq!(
        (callback.status, callback.location()),
        (StatusCode::SEE_OTHER, "/"),
        "{}",
        callback.text()
    );

    let approval = send(
        &h.app(),
        "POST",
        &format!("/auth/human-review/{record_id}/approval"),
        &console(&session_cookie),
        Some(json!({ "decision": "approve" })),
    )
    .await;
    assert_eq!(approval.status, StatusCode::OK, "{}", approval.text());
    assert_eq!(approval.json()["decision"], "approve");
    let approval_body = approval.json();
    let approval_id = approval_body["approval_id"].as_str().unwrap().to_owned();
    let execution_id = approval_body["execution_id"].as_str().unwrap().to_owned();

    let mut approved_action = action;
    approved_action["approval_id"] = json!(approval_id);
    approved_action["execution_id"] = json!(execution_id);
    let (status, authorized) = agent_fixture::send(
        contract::agent_router(h.state.clone()),
        "/v1/tools/propose_plan",
        &[(
            "authorization",
            format!("Bearer {}", agent_fixture::agent_token(AGENT)),
        )],
        approved_action.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{authorized}");
    assert_eq!(authorized["decision"], "PASS");
    assert_eq!(authorized["outcome_recorded"], false);
    let approved_record_id = authorized["record_id"].as_str().unwrap();
    let records = h
        .state
        .dataplane()
        .unwrap()
        .core()
        .store()
        .records("default", 0)
        .await
        .expect("signed agent evidence");
    let approved_record = records
        .into_iter()
        .filter_map(kavach_ports::chain_record::ChainRecord::into_decision)
        .find(|record| record.payload.record_id == approved_record_id)
        .expect("approved action record");
    let source = h
        .state
        .dataplane()
        .unwrap()
        .core()
        .store()
        .get_by_request("default", AGENT, request_id)
        .await
        .expect("source review evidence")
        .expect("source review evidence exists");
    let action_hash = source
        .payload
        .review_action_hash
        .as_deref()
        .expect("source action digest");
    let release = h
        .state
        .review_approval_store()
        .release(
            "default",
            &approval_id,
            &execution_id,
            action_hash,
            Utc::now(),
        )
        .await
        .expect("release retry")
        .expect("durable release");
    assert_eq!(
        approved_record.payload.policy_decision,
        kavach_domain::Decision::HumanReview
    );
    assert_eq!(
        approved_record.payload.returned_decision,
        kavach_domain::Decision::Pass
    );
    assert_eq!(
        approved_record.payload.credential_id.as_deref(),
        Some(release.single_use_credential_id.as_str())
    );

    let (status, replay) = agent_fixture::send(
        contract::agent_router(h.state.clone()),
        "/v1/tools/propose_plan",
        &[(
            "authorization",
            format!("Bearer {}", agent_fixture::agent_token(AGENT)),
        )],
        approved_action.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{replay}");
    assert_eq!(replay["record_id"], approved_record_id);
    assert_eq!(replay["replayed"], true);

    let mut altered_action = approved_action.clone();
    altered_action["params"]["waiver_bps"] = json!(3400);
    let (status, altered) = agent_fixture::send(
        contract::agent_router(h.state.clone()),
        "/v1/tools/propose_plan",
        &[(
            "authorization",
            format!("Bearer {}", agent_fixture::agent_token(AGENT)),
        )],
        altered_action,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{altered}");

    let mut without_release = approved_action;
    without_release
        .as_object_mut()
        .unwrap()
        .remove("approval_id");
    without_release
        .as_object_mut()
        .unwrap()
        .remove("execution_id");
    let (status, session_only) = agent_fixture::send(
        contract::agent_router(h.state.clone()),
        "/v1/tools/propose_plan",
        &[(
            "authorization",
            format!("Bearer {}", agent_fixture::agent_token(AGENT)),
        )],
        without_release,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{session_only}");
    assert_eq!(session_only["decision"], "HUMAN_REVIEW");
    assert_eq!(session_only["record_id"], record_id);
}

#[test]
fn console_login_without_operator_oidc_is_refused() {
    let mut config = api_config();
    config.oidc = None;
    assert!(refused(&settings(), &config).contains("operator OIDC"));
}

#[test]
fn a_client_id_equal_to_the_operator_or_agent_audience_is_refused() {
    let config = agents_config();
    for audience in ["kavach-api", "kavach-agents"] {
        let s = ConsoleLoginSettings::new(audience, PathBuf::from("x"), REDIRECT_URI);
        assert!(refused(&s, &config).contains("must differ"), "{audience}");
    }
    let s = ConsoleLoginSettings::new(" kavach-console", PathBuf::from("x"), REDIRECT_URI);
    refused(&s, &config);
}

#[test]
fn a_non_https_redirect_uri_is_refused_outside_insecure_dev() {
    let mut config = api_config();
    for uri in [
        "http://console.kavach.test/auth/callback",
        "http://localhost:8080/auth/callback",
        "https://console.kavach.test/auth/other",
        "https://console.kavach.test/auth/callback?next=/",
    ] {
        let s = ConsoleLoginSettings::new(CLIENT_ID, PathBuf::from("x"), uri);
        refused(&s, &config);
    }
    // --insecure-dev allows plain HTTP on loopback only.
    config.insecure_dev = true;
    for uri in [
        "http://localhost:8080/auth/callback",
        "http://127.0.0.1:8080/auth/callback",
    ] {
        let s = ConsoleLoginSettings::new(CLIENT_ID, PathBuf::from("x"), uri);
        console_login::validate(&s, &config).expect(uri);
    }
    let s = ConsoleLoginSettings::new(
        CLIENT_ID,
        PathBuf::from("x"),
        "http://console.kavach.test/auth/callback",
    );
    refused(&s, &config);
}

#[test]
fn plain_http_idp_endpoints_and_unsafe_scopes_are_refused() {
    let mut config = api_config();
    let endpoints = |base: &str| IdpEndpoints {
        authorization: format!("{base}/authorize"),
        token: format!("{base}/token"),
        revocation: None,
        end_session: None,
    };
    let mut s = settings();
    s.endpoints = Some(endpoints("http://idp.test"));
    refused(&s, &config);
    s.endpoints = Some(endpoints("https://user:pw@idp.test"));
    refused(&s, &config);
    s.endpoints = Some(endpoints("https://idp.test"));
    console_login::validate(&s, &config).unwrap();
    config.insecure_dev = true;
    s.endpoints = Some(endpoints("http://127.0.0.1:9999"));
    console_login::validate(&s, &config).unwrap();

    let config = api_config();
    for scope in ["profile", "openid offline_access", "openid  groups", ""] {
        let mut s = settings();
        s.scope = scope.into();
        refused(&s, &config);
    }
}

#[tokio::test]
async fn discovery_naming_another_issuer_is_refused() {
    // This double names ISSUER, not its own URL.
    let other = double(admin()).await;
    let error = console_login::discover(&other.url, true).await.unwrap_err();
    assert!(error.contains("another issuer"), "{error}");
    // Plain HTTP discovery outside --insecure-dev.
    assert!(console_login::discover(&other.url, false).await.is_err());

    // A double that names itself: the endpoints come from its document.
    let own = OidcDouble::start(DoubleConfig {
        issuer: None,
        seed: IDP_SEED,
        kid: KID.into(),
        client_id: CLIENT_ID.into(),
        client_secret: CLIENT_SECRET.into(),
        audience: "kavach-api".into(),
        user: admin(),
        listen: "127.0.0.1:0".parse().unwrap(),
    })
    .await;
    let found = console_login::discover(&own.url, true).await.unwrap();
    assert_eq!(found.token, own.token_endpoint());
    assert_eq!(found.revocation, Some(own.revocation_endpoint()));
}

fn temp_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("kcl-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

#[cfg(unix)]
#[test]
fn require_hardening_checks_the_client_secret_file_mode() {
    let dir = temp_dir();
    let path = dir.join("console.secret");
    owner_only(&path, CLIENT_SECRET);
    let mut s = settings();
    s.client_secret_file = path.clone();
    assert_eq!(console_login_violations(Some(&s)), vec![]);
    set_mode(&path, 0o640);
    assert_eq!(
        console_login_violations(Some(&s)),
        vec![Violation::SecretFileMode {
            flag: "--console-client-secret-file",
            mode: 0o640
        }]
    );
    std::fs::remove_file(&path).unwrap();
    assert_eq!(
        console_login_violations(Some(&s)),
        vec![Violation::SecretFileUnreadable {
            flag: "--console-client-secret-file"
        }]
    );
    assert_eq!(console_login_violations(None), vec![]);
}

#[test]
fn the_client_secret_file_holds_one_line_and_is_never_printed() {
    let dir = temp_dir();
    let path = dir.join("secret");
    std::fs::write(&path, "  s3cret-value \n").unwrap();
    assert_eq!(
        console_login::read_client_secret(&path).unwrap().expose(),
        "s3cret-value"
    );
    for bad in ["", "   \n", "s3cret-one\ns3cret-two\n"] {
        std::fs::write(&path, bad).unwrap();
        let error = console_login::read_client_secret(&path).unwrap_err();
        assert!(!error.contains("s3cret"), "{error}");
    }
    let error = console_login::read_client_secret(&dir.join("missing")).unwrap_err();
    assert!(!error.contains(dir.to_str().unwrap()), "{error}");
}

#[cfg(unix)]
mod process {
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output, Stdio};

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    /// As `tests/require_hardening.rs`: a development process (no Cedar
    /// files needed), so each test meets only the refusal it is about.
    fn run(extra: &[&str]) -> Output {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        Command::new(env!("CARGO_BIN_EXE_kavach-api"))
            .args([
                "--insecure-dev",
                "--access-control",
                "none",
                "--pack",
                root.join("packs/finance/v0.yaml").to_str().unwrap(),
                "--model",
                root.join("models/finance/credit-underwriting-v1.yaml")
                    .to_str()
                    .unwrap(),
                "--listen",
                &format!("127.0.0.1:{}", free_port()),
                "--grpc-listen",
                &format!("127.0.0.1:{}", free_port()),
            ])
            .args(extra)
            .env("NO_COLOR", "1")
            .stdin(Stdio::null())
            .output()
            .expect("run kavach-api")
    }

    /// Operator OIDC and a console login configuration that passes every
    /// check but the one a test changes.
    fn login_args(dir: &Path, secret: &Path) -> Vec<String> {
        let jwks = dir.join("jwks.json");
        std::fs::write(
            &jwks,
            super::oidc_double::jwks_for(&super::IDP_SEED, super::KID).to_string(),
        )
        .unwrap();
        [
            "--oidc-issuer",
            super::ISSUER,
            "--oidc-audience",
            "kavach-api",
            "--oidc-jwks-file",
            jwks.to_str().unwrap(),
            "--console-client-id",
            super::CLIENT_ID,
            "--console-client-secret-file",
            secret.to_str().unwrap(),
            "--console-redirect-uri",
            super::REDIRECT_URI,
            "--console-authorization-endpoint",
            "https://idp.test/authorize",
            "--console-token-endpoint",
            "https://idp.test/token",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect()
    }

    fn secret_file(mode: u32) -> (PathBuf, PathBuf) {
        let dir = super::temp_dir();
        let secret = dir.join("s3cret-dir-console.secret");
        super::owner_only(&secret, "s3cret-value");
        super::set_mode(&secret, mode);
        (dir, secret)
    }

    fn strs(v: &[String]) -> Vec<&str> {
        v.iter().map(String::as_str).collect()
    }

    #[test]
    fn the_pasted_token_fallback_is_refused_under_require_hardening() {
        let out = run(&["--require-hardening"]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(78), "{stderr}");
        assert!(stderr.contains("insecure_dev"), "{stderr}");
        assert!(stderr.contains("pasted-token"), "{stderr}");
    }

    #[test]
    fn a_client_secret_file_open_to_others_is_refused_under_require_hardening() {
        let (dir, secret) = secret_file(0o644);
        let mut args = login_args(&dir, &secret);
        args.push("--require-hardening".into());
        let out = run(&strs(&args));
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(78), "{stderr}");
        assert!(stderr.contains("secret_file_mode"), "{stderr}");
        assert!(stderr.contains("--console-client-secret-file"), "{stderr}");
        assert!(
            !stderr.contains("s3cret"),
            "a secret or its path is printed: {stderr}"
        );
    }

    #[test]
    fn session_limits_outside_their_bounds_stop_the_process() {
        let (dir, secret) = secret_file(0o600);
        for (flag, value, message) in [
            (
                "--console-session-idle-minutes",
                "4",
                "--console-session-idle-minutes must be 5-60",
            ),
            (
                "--console-session-idle-minutes",
                "61",
                "--console-session-idle-minutes must be 5-60",
            ),
            (
                "--console-session-absolute-minutes",
                "721",
                "--console-session-absolute-minutes must be at most 720",
            ),
            (
                "--console-max-sessions",
                "10001",
                "--console-max-sessions must be 1-10000",
            ),
        ] {
            let mut args = login_args(&dir, &secret);
            args.extend([flag.to_string(), value.to_string()]);
            let out = run(&strs(&args));
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(!out.status.success(), "{flag} {value}: {stderr}");
            assert!(stderr.contains(message), "{flag} {value}: {stderr}");
        }
    }

    #[test]
    fn a_partial_or_unsafe_console_login_configuration_stops_the_process() {
        let (dir, secret) = secret_file(0o600);
        let out = run(&["--console-client-id", super::CLIENT_ID]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{stderr}");
        assert!(stderr.contains("--console-client-secret-file"), "{stderr}");

        let mut args = login_args(&dir, &secret);
        let at = args.iter().position(|a| a == super::CLIENT_ID).unwrap();
        args[at] = "kavach-api".into();
        let out = run(&strs(&args));
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{stderr}");
        assert!(
            stderr.contains("must differ from --oidc-audience"),
            "{stderr}"
        );

        let mut args = login_args(&dir, &secret);
        let at = args.iter().position(|a| a == super::REDIRECT_URI).unwrap();
        args[at] = "http://console.kavach.test/auth/callback".into();
        let out = run(&strs(&args));
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{stderr}");
        assert!(stderr.contains("--console-redirect-uri"), "{stderr}");
    }
}

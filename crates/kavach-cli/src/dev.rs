//! `kavach dev up`: Kavach and a mock resource provider, in this process,
//! on loopback only.
//!
//! The API runs as the dev stack does: `--insecure-dev`, `dev-` keys,
//! memory stores (or the project's Postgres), the signed tool registry and
//! the bundled policy pack. The mock provider serves HTTPS with the
//! bundle's dev CA, and the gateway trusts only that CA. Nothing listens
//! beyond 127.0.0.1.

use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use chrono::{DateTime, FixedOffset, NaiveTime, TimeZone, Utc};
use kavach_api::dataplane::{agent_router, sor_router, DataplaneConfig};
use kavach_api::dev_clock::{DevClock, DevClockKind};
use kavach_api::{
    router, serve_http_on, AccessControlKind, ApiConfig, AppState, DatabaseTls, EvidenceStoreKind,
    JwksSource, OidcConfig, DEFAULT_POOL_SIZE,
};
use kavach_ports::{KeyAlgorithm, PublicKey, SyncStatus, TimeSource, TrustedNow};
use serde_json::{json, Value};

use crate::init::{MODEL_FILE, PACK_FILE};
use crate::output::{CliError, Status, Style, Ui};
use crate::project::Project;
use crate::run::RunFile;

/// A clock that starts at a chosen time and runs at real speed (`--at`).
pub(crate) struct StartedAt {
    at: DateTime<Utc>,
    since: Instant,
}

impl StartedAt {
    pub(crate) fn new(at: DateTime<Utc>) -> Self {
        Self {
            at,
            since: Instant::now(),
        }
    }
}

impl TimeSource for StartedAt {
    fn now(&self) -> TrustedNow {
        let elapsed = chrono::Duration::from_std(self.since.elapsed()).unwrap_or_default();
        TrustedNow {
            utc: self.at + elapsed,
            sync: SyncStatus::Synced { max_error_ms: 0 },
        }
    }
}

/// `HH:MM` in IST, today.
/// Validates `--at` while the command line is parsed (a bad value is a
/// usage error, exit 64).
pub fn parse_hhmm(text: &str) -> Result<String, String> {
    NaiveTime::parse_from_str(text, "%H:%M")
        .map(|_| text.to_string())
        .map_err(|_| "use HH:MM in IST, e.g. --at 11:00".to_string())
}

pub(crate) fn parse_at(text: &str) -> Result<DateTime<Utc>, CliError> {
    let time = NaiveTime::parse_from_str(text, "%H:%M").map_err(|e| {
        CliError::new(format!("--at {text:?} is not a time"), e)
            .fix("use HH:MM in IST, e.g. --at 11:00")
    })?;
    let ist =
        FixedOffset::east_opt(5 * 3600 + 1800).ok_or_else(|| CliError::new("IST", "offset"))?;
    let today = Utc::now().with_timezone(&ist).date_naive();
    ist.from_local_datetime(&today.and_time(time))
        .single()
        .map(|t| t.with_timezone(&Utc))
        .ok_or_else(|| CliError::new(format!("--at {text}"), "ambiguous local time"))
}

fn read(path: &Path) -> Result<String, CliError> {
    std::fs::read_to_string(path).map_err(|e| {
        CliError::new(format!("cannot read {}", path.display()), e).fix("run `kavach doctor`")
    })
}

/// Points the gateway at the provider's current address.
fn point_providers(project: &Project) -> Result<(), CliError> {
    let path = project.kavach_dir().join("providers.json");
    let mut providers: Value = serde_json::from_str(&read(&path)?)
        .map_err(|e| CliError::new("providers.json is not valid", e))?;
    providers["providers"][0]["endpoint"] = json!(format!(
        "https://localhost:{}",
        project.file.listen.provider.port()
    ));
    std::fs::write(&path, providers.to_string())
        .map_err(|e| CliError::new("cannot update providers.json", e))
}

fn api_config(project: &Project, clock: Option<Arc<DevClock>>) -> ApiConfig {
    let kavach = project.kavach_dir();
    let operator = operator_oidc(&kavach);
    let evidence_store = match &project.file.database {
        Some(db) => EvidenceStoreKind::Postgres {
            database_url: db.url.clone(),
        },
        None => EvidenceStoreKind::Memory,
    };
    ApiConfig {
        pack_path: project.bundle().join(PACK_FILE),
        model_path: project.bundle().join(MODEL_FILE),
        hmac_secret: None,
        evidence_store,
        // The operator API needs the project's operator token (Cedar, the
        // bundled policies); nothing on this machine reaches it without.
        access_control: AccessControlKind::Cedar {
            policy_path: project.kavach_dir().join(CEDAR_POLICIES),
            entities_path: project.kavach_dir().join(CEDAR_ENTITIES),
        },
        tls: None,
        pack_sha256: None,
        // With Postgres, re-pin the bundled pack and model at each start (an
        // audited dev convenience); memory mode has nothing to pin.
        bootstrap_pack: project.file.database.is_some(),
        bootstrap_model: project.file.database.is_some(),
        pack_signers: None,
        oidc: Some(operator.clone()),
        insecure_dev: true,
        mtls_principal_san: None,
        change_ttl_seconds: 3600,
        migration_database_url: None,
        database_tls: DatabaseTls::development(),
        database_pool_size: DEFAULT_POOL_SIZE,
        dataplane: Some(dataplane_config(project, clock)),
    }
}

/// Operator tokens from the bundle's dev identity provider.
fn operator_oidc(kavach: &Path) -> OidcConfig {
    OidcConfig {
        issuer: kavach_devkit::ISSUER.into(),
        audience: kavach_devkit::OPERATOR_AUDIENCE.into(),
        jwks: JwksSource::File(kavach.join("jwks.json")),
        principal_claim: "sub".into(),
        groups_claim: "groups".into(),
        leeway_seconds: 30,
    }
}

/// `run.json` for as long as the stack runs; removed however `up` returns.
struct RunGuard(std::path::PathBuf);

impl RunGuard {
    fn write(project: &Project, run: &RunFile) -> Result<Self, CliError> {
        let path = crate::run::path(project);
        run.write(&path)?;
        Ok(Self(path))
    }
}

impl Drop for RunGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Ctrl-C, or (Unix) SIGTERM from a process manager.
async fn stop_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut term) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

/// The agent data plane's settings for the project's bundle.
pub(crate) fn dataplane_config(project: &Project, clock: Option<Arc<DevClock>>) -> DataplaneConfig {
    let kavach = project.kavach_dir();
    let keys = kavach.join("keys");
    DataplaneConfig {
        agent_oidc: OidcConfig {
            audience: kavach_devkit::AGENT_AUDIENCE.into(),
            principal_claim: "azp".into(),
            ..operator_oidc(&kavach)
        },
        mandate_config: kavach.join("mandate-config.json"),
        mandate_keys_dir: keys.clone(),
        evidence_keys_dir: keys.clone(),
        evidence_key_id: kavach_devkit::EVIDENCE_KID.into(),
        checkpoint_keys_dir: keys.clone(),
        checkpoint_key_id: kavach_devkit::CHECKPOINT_KID.into(),
        checkpoint_interval_seconds: 60,
        checkpoint_stall_seconds: 600,
        subject_pseudonym_key: kavach.join("pseudonym.key"),
        consents: kavach.join("consents.json"),
        tenant_id: kavach_devkit::TENANT.into(),
        sor_rate_per_second: 20,
        tool_registry: kavach.join("tools/agent-tools.yaml"),
        tool_registry_sha256: None,
        tool_signers: Some(kavach.join("tool-signers.json")),
        credential_keys_dir: keys,
        credential_key_id: kavach_devkit::CREDENTIAL_KID.into(),
        providers: kavach.join("providers.json"),
        references: kavach.join("references.json"),
        provider_connect_timeout_ms: 2_000,
        provider_timeout_ms: 5_000,
        provider_ca: Some(kavach.join("tls/ca.pem")),
        test_clock: None,
        dev_clock: clock,
        hsm: None,
    }
}

/// The development clock `--at` or `--clock` asks for (dev keys only).
fn dev_clock_for(
    project: &Project,
    at: Option<&str>,
    fixed: Option<&str>,
) -> Result<Option<Arc<DevClock>>, CliError> {
    let clock = match (at, fixed) {
        (Some(t), _) => Some(DevClock::started_at(parse_at(t)?)),
        (None, Some(t)) => Some(DevClock::fixed(
            crate::policy_test::parse_time(t)
                .map_err(|e| crate::authorize::usage("--clock is not a time", e))?,
        )),
        (None, None) => None,
    };
    if clock.is_some() {
        refuse_unless_dev_bundle(project)?;
    }
    Ok(clock)
}

/// The `dev up` banner's clock line.
fn clock_line(clock: Option<&DevClock>) -> String {
    let ist = FixedOffset::east_opt(5 * 3600 + 1800);
    let shown = |t: DateTime<Utc>| {
        ist.map(|o| {
            t.with_timezone(&o)
                .format("%H:%M IST on %d %b %Y")
                .to_string()
        })
        .unwrap_or_default()
    };
    match clock {
        None => "system time".into(),
        Some(c) if c.kind() == DevClockKind::Fixed => format!(
            "fixed at {} (dev only; move it forward with `kavach dev clock <time>`)",
            shown(c.time())
        ),
        Some(c) => format!("started at {}, then runs (dev only)", shown(c.time())),
    }
}

/// A development clock runs with development keys only.
fn refuse_unless_dev_bundle(project: &Project) -> Result<(), CliError> {
    let text = read(&project.kavach_dir().join("mandate-config.json"))?;
    let config: Value = serde_json::from_str(&text)
        .map_err(|e| CliError::new("the mandate configuration is not JSON", e))?;
    let kid = config["signing_kid"].as_str().unwrap_or_default();
    if kavach_ports::agent_evidence::is_dev_key(kid) {
        Ok(())
    } else {
        Err(CliError::new(
            "a development clock runs with development keys only",
            format!("the mandate key is {kid:?}"),
        ))
    }
}

/// `kavach dev clock <time>`: moves the running stack's fixed clock forward.
/// `HH:MM` is the next such IST time after the stack's time; RFC 3339 is
/// taken as given (and must be later).
pub async fn move_clock(ui: &Ui, dir: &Path, time: &str) -> Result<i32, CliError> {
    let project = Project::find(dir)?;
    let run = crate::run::RunFile::live(&project)?;
    let token = read(&project.bundle().join("operator.jwt"))?;
    let now = run.stack_now(&project).await?;
    let to = if let Ok(t) = DateTime::parse_from_rfc3339(time) {
        t.with_timezone(&Utc)
    } else {
        let hhmm = NaiveTime::parse_from_str(time, "%H:%M").map_err(|_| {
            crate::authorize::usage(
                format!("{time:?} is not a time"),
                "use HH:MM (IST) or RFC 3339",
            )
        })?;
        next_ist(now, hhmm)?
    };
    let response = reqwest::Client::new()
        .post(format!("http://{}/v1/dev/clock", run.operator))
        .bearer_auth(token.trim())
        .json(&json!({ "at": to }))
        .send()
        .await
        .map_err(|e| CliError::new("the operator listener did not answer", e))?;
    let status = response.status().as_u16();
    let body: Value = response.json().await.unwrap_or(Value::Null);
    match status {
        200 => {}
        404 => {
            return Err(
                crate::problem::error("this stack has no fixed clock", status, &body)
                    .fix("start it with `kavach dev up --clock <time>`"),
            )
        }
        409 => {
            return Err(crate::authorize::usage(
                "the development clock only moves forward",
                crate::problem::detail(status, &body),
            )
            .fix("give a later time, or HH:MM for its next occurrence"))
        }
        _ => {
            return Err(crate::problem::error(
                format!("the stack refused the clock change ({status})"),
                status,
                &body,
            ))
        }
    }
    let line = clock_line(Some(&*DevClock::fixed(to)));
    let data = json!({ "from": now, "to": to, "clock": body });
    Ok(ui.finish("dev clock", Status::Ok, &data, &format!("clock {line}")))
}

/// The next IST `time` strictly after `after`.
pub(crate) fn next_ist(after: DateTime<Utc>, time: NaiveTime) -> Result<DateTime<Utc>, CliError> {
    let ist =
        FixedOffset::east_opt(5 * 3600 + 1800).ok_or_else(|| CliError::new("IST", "offset"))?;
    let mut day = after.with_timezone(&ist).date_naive();
    for _ in 0..3 {
        if let Some(t) = ist.from_local_datetime(&day.and_time(time)).single() {
            let t = t.with_timezone(&Utc);
            if t > after {
                return Ok(t);
            }
        }
        day += chrono::Duration::days(1);
    }
    Err(CliError::new("cannot compute the next IST time", time))
}

/// The operator API's Cedar policies and entities, in the bundle.
pub(crate) const CEDAR_POLICIES: &str = "cedar/kavach.cedar";
pub(crate) const CEDAR_ENTITIES: &str = "cedar/entities.json";

/// Writes the operator API's access control files. The policies are the
/// bundled ones, rewritten on every start so they never go stale; the
/// entities file is written only if it is missing.
pub(crate) fn ensure_cedar(kavach_dir: &Path) -> Result<(), CliError> {
    let entities = json!([
        { "uid": { "type": "Kavach::System", "id": "api" }, "attrs": {}, "parents": [] },
        { "uid": { "type": "Kavach::Group", "id": "admins" }, "attrs": {}, "parents": [] },
        { "uid": { "type": "Kavach::Group", "id": "operators" }, "attrs": {}, "parents": [] },
        { "uid": { "type": "Kavach::Group", "id": "viewers" }, "attrs": {}, "parents": [] },
        { "uid": { "type": "Kavach::Group", "id": "change-approvers" }, "attrs": {}, "parents": [] }
    ]);
    for (file, text) in [
        (CEDAR_POLICIES, kavach_auth::API_POLICIES.to_string()),
        (
            CEDAR_ENTITIES,
            serde_json::to_string_pretty(&entities).unwrap_or_default() + "\n",
        ),
    ] {
        let path = kavach_dir.join(file);
        if file == CEDAR_ENTITIES && path.exists() {
            continue;
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| CliError::new(format!("cannot create {}", parent.display()), e))?;
        }
        std::fs::write(&path, text)
            .map_err(|e| CliError::new(format!("cannot write {}", path.display()), e))?;
    }
    Ok(())
}

/// Whether `host` (a Host header) names this machine: `localhost`,
/// `127.0.0.1` or `[::1]`, with or without a port. Anything else, as a web
/// page using DNS rebinding would send, is refused.
fn local_host(host: &str) -> bool {
    let name = if let Some(rest) = host.strip_prefix('[') {
        rest.split(']').next().map(|h| format!("[{h}]"))
    } else {
        host.split(':').next().map(str::to_string)
    };
    matches!(
        name.as_deref().map(str::to_ascii_lowercase).as_deref(),
        Some("localhost" | "127.0.0.1" | "[::1]")
    )
}

/// Every `dev up` listener: refuses a foreign Host header (421) and the
/// self-asserted `X-Kavach-Principal` header (401), which `--insecure-dev`
/// would otherwise accept as an identity.
async fn dev_guard(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    let host = request
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    if !local_host(host) {
        return (
            StatusCode::MISDIRECTED_REQUEST,
            axum::Json(json!({ "error": "kavach dev up answers only to localhost and 127.0.0.1" })),
        )
            .into_response();
    }
    if request.headers().contains_key("x-kavach-principal") {
        return (
            StatusCode::UNAUTHORIZED,
            axum::Json(
                json!({ "error": "X-Kavach-Principal is not accepted: send a bearer token" }),
            ),
        )
            .into_response();
    }
    next.run(request).await
}

fn guarded(router: axum::Router) -> axum::Router {
    router.layer(axum::middleware::from_fn(dev_guard))
}

/// The mock provider: trusts the bundle's credential key, serves HTTPS.
async fn provider(
    project: &Project,
    listener: TcpListener,
    inspect: TcpListener,
    clock: Arc<dyn TimeSource + Send + Sync>,
) -> Result<tokio::task::JoinHandle<()>, CliError> {
    let dir = project.bundle().join("provider");
    let secret: [u8; 32] = hex::decode(read(&dir.join("encryption.key"))?.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| {
            CliError::new(
                "the provider's encryption key is not valid",
                "expected 32 bytes hex",
            )
        })?;
    let trusted: Value = serde_json::from_str(&read(&dir.join("credential-keys.json"))?)
        .map_err(|e| CliError::new("credential-keys.json is not valid", e))?;
    let keys = trusted["keys"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|key| {
            Some(PublicKey {
                kid: key["kid"].as_str()?.into(),
                algorithm: KeyAlgorithm::Ed25519,
                bytes: hex::decode(key["public_key"].as_str()?)
                    .ok()?
                    .try_into()
                    .ok()?,
            })
        })
        .collect::<Vec<_>>();
    let config = kavach_mock_provider::ProviderConfig::new(
        kavach_devkit::PROVIDER_AUDIENCE,
        kavach_credential::DecryptionKey::from_bytes(kavach_devkit::PROVIDER_KID, secret),
        kavach_jws::KeySet::new(keys),
    );
    let mock = kavach_mock_provider::MockProvider::new(config, Arc::new(move || clock.now().utc));
    let _ = rustls::crypto::ring::default_provider().install_default();
    let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(
        dir.join("tls.pem"),
        dir.join("tls-key.pem"),
    )
    .await
    .map_err(|e| CliError::new("cannot load the provider's TLS certificate", e))?;
    let server = axum_server::from_tcp_rustls(listener, tls);
    // The inbox, on its own loopback listener (never on the provider's).
    let inspect = tokio::net::TcpListener::from_std(inspect)
        .map_err(|e| CliError::new("cannot start the provider inbox listener", e))?;
    let inbox = guarded(kavach_mock_provider::inspect_router(Arc::clone(&mock)));
    tokio::spawn(async move {
        let _ = axum::serve(inspect, inbox).await;
    });
    Ok(tokio::spawn(async move {
        let _ = server
            .serve(guarded(kavach_mock_provider::router(mock)).into_make_service())
            .await;
    }))
}

/// Binds every port first, so a busy one is reported before anything starts.
fn bind_all(project: &Project) -> Result<[TcpListener; 5], CliError> {
    let l = &project.file.listen;
    let bind = |name: &str, addr: SocketAddr| {
        if !addr.ip().is_loopback() {
            return Err(CliError::new(
                format!("the {name} address {addr} is not loopback"),
                "a dev project listens on 127.0.0.1 only",
            )
            .fix("fix [listen] in kavach.toml"));
        }
        let listener = TcpListener::bind(addr).map_err(|e| {
            CliError::new(format!("port {} ({name}) is in use", addr.port()), e)
                .fix("stop what uses it, or change [listen] in kavach.toml")
        })?;
        listener
            .set_nonblocking(true)
            .map_err(|e| CliError::new("cannot configure a listener", e))?;
        Ok(listener)
    };
    Ok([
        bind("operator", l.operator)?,
        bind("agent", l.agent)?,
        bind("sor", l.sor)?,
        bind("provider", l.provider)?,
        bind("inspect", l.inspect)?,
    ])
}

pub async fn up(
    ui: &Ui,
    dir: &Path,
    at: Option<&str>,
    fixed: Option<&str>,
    exit_when_ready: bool,
) -> Result<i32, CliError> {
    let project = Project::find(dir)?;
    let dev_clock = dev_clock_for(&project, at, fixed)?;
    let [operator, agent, sor, provider_listener, inspect_listener] = bind_all(&project)?;
    let clock: Arc<dyn TimeSource + Send + Sync> = match &dev_clock {
        Some(dev) => Arc::clone(dev) as Arc<dyn TimeSource + Send + Sync>,
        None => Arc::new(kavach_ports::SystemClock),
    };
    point_providers(&project)?;
    ensure_cedar(&project.kavach_dir())?;
    let provider_task =
        provider(&project, provider_listener, inspect_listener, clock.clone()).await?;
    let config = api_config(&project, dev_clock.clone());
    let state = Arc::new(
        AppState::from_config(&config)
            .await
            .map_err(|e| CliError::new("Kavach did not start", e).fix("run `kavach doctor`"))?,
    );

    let l = &project.file.listen;
    let bundle = project.bundle();
    let data = json!({
        "running": !exit_when_ready,
        "profile": "dev",
        "store": if project.file.database.is_some() { "postgres" } else { "memory" },
        "clock": dev_clock.as_ref().map_or_else(|| json!("system"), |c| c.view()),
        "endpoints": {
            "operator": format!("http://{}", l.operator),
            "agent": format!("http://{}", l.agent),
            "sor": format!("http://{}", l.sor),
            "provider": format!("https://localhost:{}", l.provider.port()),
        },
        "tokens": {
            "operator": bundle.join("operator.jwt"),
            "agent": bundle.join("agents/collections-agent.jwt"),
        },
    });
    let human = format!(
        "{} Kavach dev stack {}\n\n  operator  http://{}   (/v1/runtime, /metrics)\n  agent     http://{}   (/v1/authorize, /v1/tools/{{tool}})\n  sor       http://{}   (/v1/sor/events)\n  provider  https://localhost:{}  (mock, dev CA)\n\n  store     {}\n  clock     {}\n  tokens    {}/agents/<id>.jwt, {}/operator.jwt\n\n{}",
        ui.paint(Style::Ok, "●"),
        if exit_when_ready { "is ready (exiting: --exit-when-ready)" } else { "is running. Ctrl-C stops it." },
        l.operator,
        l.agent,
        l.sor,
        l.provider.port(),
        if project.file.database.is_some() { "Postgres (kavach.toml)" } else { "memory (lost on exit)" },
        clock_line(dev_clock.as_deref()),
        bundle.display(),
        bundle.display(),
        ui.paint(
            Style::Warn,
            "DEVELOPMENT ONLY: --insecure-dev, dev- keys, loopback. The operator API needs .kavach/operator.jwt."
        ),
    );
    if exit_when_ready {
        let code = ui.finish("dev up", Status::Ok, &data, &human);
        provider_task.abort();
        return Ok(code);
    }
    // Before the banner, so whatever waits for it finds the file.
    let _run = RunGuard::write(
        &project,
        &RunFile {
            version: 1,
            pid: std::process::id(),
            clock_offset_ms: dev_clock
                .as_ref()
                .map_or(0, |c| (c.time() - Utc::now()).num_milliseconds()),
            clock: dev_clock.as_ref().map(|c| c.kind()),
            operator: l.operator,
            agent: l.agent,
            sor: l.sor,
            provider: l.provider,
            inspect: l.inspect,
        },
    )?;
    let code = ui.finish("dev up", Status::Ok, &data, &human);

    let serve = |app: axum::Router, listener: TcpListener| async move {
        serve_http_on(app, listener, None)
            .await
            .map_err(|e| e.to_string())
    };
    tokio::select! {
        r = serve(guarded(router(state.clone())), operator) => r.map_err(|e| CliError::new("the operator listener stopped", e))?,
        r = serve(guarded(agent_router(state.clone())), agent) => r.map_err(|e| CliError::new("the agent listener stopped", e))?,
        r = serve(guarded(sor_router(state.clone())), sor) => r.map_err(|e| CliError::new("the sor listener stopped", e))?,
        () = stop_signal() => {}
    }
    provider_task.abort();
    if !ui.json {
        crate::output::print_redacted("Stopped.");
    }
    Ok(code)
}

#[cfg(test)]
mod guard_tests {
    use super::local_host;

    #[test]
    fn only_this_machine_is_a_local_host() {
        for ok in [
            "localhost",
            "localhost:8080",
            "127.0.0.1",
            "127.0.0.1:8091",
            "[::1]:8080",
            "LOCALHOST:1",
        ] {
            assert!(local_host(ok), "{ok}");
        }
        for bad in [
            "",
            "evil.example",
            "evil.example:8080",
            "127.0.0.1.evil.example",
            "localhost.evil.example:80",
            "[::2]:8080",
            "10.0.0.1",
        ] {
            assert!(!local_host(bad), "{bad}");
        }
    }
}

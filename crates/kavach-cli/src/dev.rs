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
use kavach_api::dataplane::{agent_router, sor_router, DataplaneConfig, TestClock};
use kavach_api::{
    router, serve_http_on, AccessControlKind, ApiConfig, AppState, DatabaseTls, EvidenceStoreKind,
    JwksSource, OidcConfig, DEFAULT_POOL_SIZE,
};
use kavach_ports::{KeyAlgorithm, PublicKey, SyncStatus, TimeSource, TrustedNow};
use serde_json::{json, Value};

use crate::init::{MODEL_FILE, PACK_FILE};
use crate::output::{CliError, Status, Style, Ui};
use crate::project::Project;

/// A clock that starts at a chosen time and runs at real speed (`--at`).
struct StartedAt {
    at: DateTime<Utc>,
    since: Instant,
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

fn parse_at(text: &str) -> Result<DateTime<Utc>, CliError> {
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

fn api_config(project: &Project, clock: Option<TestClock>) -> ApiConfig {
    let kavach = project.kavach_dir();
    let keys = kavach.join("keys");
    let operator = OidcConfig {
        issuer: kavach_devkit::ISSUER.into(),
        audience: kavach_devkit::OPERATOR_AUDIENCE.into(),
        jwks: JwksSource::File(kavach.join("jwks.json")),
        principal_claim: "sub".into(),
        groups_claim: "groups".into(),
        leeway_seconds: 30,
    };
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
        access_control: AccessControlKind::None,
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
        dataplane: Some(DataplaneConfig {
            agent_oidc: OidcConfig {
                audience: kavach_devkit::AGENT_AUDIENCE.into(),
                principal_claim: "azp".into(),
                ..operator
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
            test_clock: clock,
            hsm: None,
        }),
    }
}

/// The mock provider: trusts the bundle's credential key, serves HTTPS.
async fn provider(
    project: &Project,
    listener: TcpListener,
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
    Ok(tokio::spawn(async move {
        let _ = server
            .serve(kavach_mock_provider::router(mock).into_make_service())
            .await;
    }))
}

/// Binds every port first, so a busy one is reported before anything starts.
fn bind_all(project: &Project) -> Result<[TcpListener; 4], CliError> {
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
    ])
}

pub async fn up(
    ui: &Ui,
    dir: &Path,
    at: Option<&str>,
    exit_when_ready: bool,
) -> Result<i32, CliError> {
    let project = Project::find(dir)?;
    let [operator, agent, sor, provider_listener] = bind_all(&project)?;
    let started_at = at.map(parse_at).transpose()?;
    let clock: Arc<dyn TimeSource + Send + Sync> = match started_at {
        Some(at) => Arc::new(StartedAt {
            at,
            since: Instant::now(),
        }),
        None => Arc::new(kavach_ports::SystemClock),
    };
    point_providers(&project)?;
    let provider_task = provider(&project, provider_listener, clock.clone()).await?;
    let config = api_config(&project, started_at.map(|_| TestClock(clock.clone())));
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
        "clock": at.map_or_else(|| "system".to_string(), |t| format!("{t} IST")),
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
        at.map_or_else(|| "system time".to_string(), |t| format!("starts at {t} IST today (--at), then runs")),
        bundle.display(),
        bundle.display(),
        ui.paint(
            Style::Warn,
            "DEVELOPMENT ONLY: --insecure-dev, dev- keys, open operator API on loopback."
        ),
    );
    let code = ui.finish("dev up", Status::Ok, &data, &human);
    if exit_when_ready {
        provider_task.abort();
        return Ok(code);
    }

    let serve = |app: axum::Router, listener: TcpListener| async move {
        serve_http_on(app, listener, None)
            .await
            .map_err(|e| e.to_string())
    };
    tokio::select! {
        r = serve(router(state.clone()), operator) => r.map_err(|e| CliError::new("the operator listener stopped", e))?,
        r = serve(agent_router(state.clone()), agent) => r.map_err(|e| CliError::new("the agent listener stopped", e))?,
        r = serve(sor_router(state.clone()), sor) => r.map_err(|e| CliError::new("the sor listener stopped", e))?,
        _ = tokio::signal::ctrl_c() => {}
    }
    provider_task.abort();
    if !ui.json {
        crate::output::print_redacted("Stopped.");
    }
    Ok(code)
}

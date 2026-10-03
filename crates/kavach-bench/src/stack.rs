//! An in-process Kavach stack for benchmarking: the real API (agent and
//! system-of-record listeners on loopback HTTP), the real gateway path, the
//! real mock provider, and Postgres (or the memory store, for a smoke run).
//!
//! It runs with `--insecure-dev` and a fixed trusted clock at 11:00 IST, so
//! the contact window never closes mid-run, and with a mandate template
//! whose daily contact cap is effectively unlimited: the cap is still
//! checked (and its counter row locked) on every call, it just never
//! blocks. Everything is synthetic: development keys from `kavach-devkit`
//! and `+910…` numbers.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, TimeZone, Utc};
use kavach_api::dataplane::{agent_router, sor_router, DataplaneConfig, TestClock};
use kavach_api::{
    AccessControlKind, ApiConfig, AppState, DatabaseTls, EvidenceStoreKind, JwksSource, OidcConfig,
};
use kavach_domain::mandate::{ConsentRecord, SorEvent};
use kavach_ports::{KeyAlgorithm, PublicKey, TimeSource};
use kavach_ports_testkit::FakeClock;
use serde_json::{json, Value};

pub const TENANT: &str = "default";
pub const AGENT: &str = "collections-agent";

/// Where the evidence lives.
#[derive(Debug, Clone)]
pub enum Store {
    /// A smoke run: no database, numbers not meaningful.
    Memory,
    /// Postgres. A fresh schema is created for the run (and dropped
    /// afterwards unless kept), so runs are independent.
    Postgres {
        database_url: String,
        tls: DatabaseTls,
        keep_schema: bool,
    },
}

#[derive(Debug, Clone)]
pub struct StackOptions {
    pub store: Store,
    pub subjects: usize,
    /// Added to every provider response.
    pub provider_delay: Duration,
    /// Connections in the API's Postgres pool (and the micro-benchmarks').
    pub pool_size: u32,
    /// Scratch directory for the development bundle and configuration.
    pub work: PathBuf,
}

/// One subject: its reference, its mandate.
#[derive(Debug, Clone)]
pub struct Subject {
    pub subject_ref: String,
    pub mandate_id: String,
}

pub struct Stack {
    pub agent_url: String,
    pub agent_token: String,
    pub subjects: Vec<Subject>,
    /// A reference no mandate covers (for blocked calls).
    pub stranger: String,
    pub database: Option<DatabaseInfo>,
    /// Direct storage for the micro-benchmarks (Postgres only), with a pool
    /// of the same size as the API's.
    pub storage: Option<kavach_storage::StoragePool>,
    pub clock: Arc<FakeClock>,
    pool_size: u32,
    state: Arc<AppState>,
    cleanup: Option<(String, DatabaseTls, String)>,
}

/// What the report says about the database.
#[derive(Debug, Clone)]
pub struct DatabaseInfo {
    pub version: String,
    /// The `sslmode` the connections use (`VerifyFull`, `Disable`, …).
    pub sslmode: String,
}

/// 11:00 IST today: inside the 08:00–19:00 contact window.
fn bench_time() -> DateTime<Utc> {
    let ist = chrono::FixedOffset::east_opt(5 * 3600 + 1800).expect("valid offset");
    let today = Utc::now().with_timezone(&ist).date_naive();
    ist.from_local_datetime(&today.and_hms_opt(11, 0, 0).expect("valid time"))
        .single()
        .expect("unambiguous")
        .with_timezone(&Utc)
}

fn subject_ref(i: usize) -> String {
    format!("ref:borrower:BENCH-{i:06}")
}

/// A synthetic number (`+910` and nine digits, never assigned).
fn number(i: usize) -> String {
    format!("+910{:09}", 100_000 + i)
}

fn write_json(path: &Path, value: &Value) -> Result<(), String> {
    std::fs::write(path, value.to_string()).map_err(|e| format!("{}: {e}", path.display()))
}

fn read(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))
}

/// Rewrites the bundle's mandate configuration, consents and references for
/// `n` subjects, and points the provider at `provider_url`.
fn write_workload(kavach: &Path, n: usize, provider_url: &str) -> Result<(), String> {
    let mut config: Value = serde_json::from_str(&read(&kavach.join("mandate-config.json"))?)
        .map_err(|e| e.to_string())?;
    // The cap is checked (and its counter row locked) on every call; set to
    // its maximum so a run does not reach it. Each hot-subject run uses its
    // own subject for the same reason.
    config["templates"][0]["window"]["max_per_day"] = json!(u16::MAX);
    config["event_freshness_seconds"] = json!(86_400);
    write_json(&kavach.join("mandate-config.json"), &config)?;

    let consents: Vec<ConsentRecord> = (0..n)
        .map(|i| ConsentRecord {
            consent_id: format!("C-bench-{i}"),
            tenant_id: TENANT.into(),
            subject_ref: subject_ref(i),
            purposes: ["loan_recovery".to_string()].into(),
            expires_at: Utc::now() + chrono::Duration::days(30),
            active: true,
        })
        .collect();
    write_json(
        &kavach.join("consents.json"),
        &serde_json::to_value(consents).map_err(|e| e.to_string())?,
    )?;
    let references: Vec<Value> = (0..=n)
        .map(|i| {
            json!({ "tenant_id": TENANT, "subject_ref": subject_ref(i),
                "destinations": { "whatsapp": number(i), "sms": number(i) } })
        })
        .collect();
    write_json(
        &kavach.join("references.json"),
        &json!({ "references": references }),
    )?;

    let mut providers: Value =
        serde_json::from_str(&read(&kavach.join("providers.json"))?).map_err(|e| e.to_string())?;
    providers["providers"][0]["endpoint"] = json!(provider_url);
    write_json(&kavach.join("providers.json"), &providers)
}

fn api_config(
    bundle: &Path,
    store: EvidenceStoreKind,
    tls: DatabaseTls,
    pool_size: u32,
    clock: TestClock,
) -> ApiConfig {
    let kavach = bundle.join("kavach");
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let operator = OidcConfig {
        issuer: kavach_devkit::ISSUER.into(),
        audience: kavach_devkit::OPERATOR_AUDIENCE.into(),
        jwks: JwksSource::File(kavach.join("jwks.json")),
        principal_claim: "sub".into(),
        groups_claim: "groups".into(),
        leeway_seconds: 30,
    };
    let keys = kavach.join("keys");
    ApiConfig {
        pack_path: repo.join("packs/finance/v0.yaml"),
        model_path: repo.join("models/finance/credit-underwriting-v1.yaml"),
        hmac_secret: None,
        evidence_store: store,
        access_control: AccessControlKind::None,
        tls: None,
        pack_sha256: None,
        bootstrap_pack: false,
        bootstrap_model: false,
        pack_signers: None,
        oidc: Some(operator.clone()),
        insecure_dev: true,
        mtls_principal_san: None,
        change_ttl_seconds: 3600,
        migration_database_url: None,
        database_tls: tls,
        database_pool_size: pool_size,
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
            tenant_id: TENANT.into(),
            sor_rate_per_second: 1_000_000,
            tool_registry: kavach.join("tools/agent-tools.yaml"),
            tool_registry_sha256: None,
            tool_signers: Some(kavach.join("tool-signers.json")),
            credential_keys_dir: keys,
            credential_key_id: kavach_devkit::CREDENTIAL_KID.into(),
            providers: kavach.join("providers.json"),
            references: kavach.join("references.json"),
            provider_connect_timeout_ms: 2_000,
            provider_timeout_ms: 5_000,
            provider_ca: None,
            test_clock: Some(clock),
        }),
    }
}

/// The mock provider on loopback HTTP, trusting the bundle's credential key.
async fn start_provider(
    bundle: &Path,
    clock: Arc<FakeClock>,
    delay: Duration,
) -> Result<String, String> {
    let provider = bundle.join("provider");
    let secret: [u8; 32] = hex::decode(read(&provider.join("encryption.key"))?.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or("provider encryption key")?;
    let trusted: Value = serde_json::from_str(&read(&provider.join("credential-keys.json"))?)
        .map_err(|e| e.to_string())?;
    let keys = trusted["keys"]
        .as_array()
        .ok_or("credential keys")?
        .iter()
        .map(|key| -> Result<PublicKey, String> {
            Ok(PublicKey {
                kid: key["kid"].as_str().ok_or("kid")?.into(),
                algorithm: KeyAlgorithm::Ed25519,
                bytes: hex::decode(key["public_key"].as_str().ok_or("public_key")?)
                    .ok()
                    .and_then(|b| b.try_into().ok())
                    .ok_or("public key bytes")?,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut config = kavach_mock_provider::ProviderConfig::new(
        kavach_devkit::PROVIDER_AUDIENCE,
        kavach_credential::DecryptionKey::from_bytes(kavach_devkit::PROVIDER_KID, secret),
        kavach_jws::KeySet::new(keys),
    );
    config.capacity = 10_000_000;
    config.delay = delay;
    let provider =
        kavach_mock_provider::MockProvider::new(config, Arc::new(move || clock.now().utc));
    serve(kavach_mock_provider::router(provider)).await
}

/// Serves `app` on an ephemeral loopback port; returns its base URL.
async fn serve(app: axum::Router) -> Result<String, String> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| e.to_string())?;
    let address = listener.local_addr().map_err(|e| e.to_string())?;
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(format!("http://{address}"))
}

/// A fresh schema for the run; returns the URL that uses it.
async fn create_schema(
    url: &str,
    tls: &DatabaseTls,
) -> Result<(String, String, DatabaseInfo), String> {
    let options = kavach_storage::connect_options(url, tls).map_err(|e| e.to_string())?;
    let sslmode = format!("{:?}", options.get_ssl_mode());
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .map_err(|e| format!("database: {e}"))?;
    let schema = format!("bench_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&pool)
        .await
        .map_err(|e| format!("create schema: {e}"))?;
    let version: String = sqlx::query_scalar("SELECT version()")
        .fetch_one(&pool)
        .await
        .map_err(|e| format!("version: {e}"))?;
    pool.close().await;
    let separator = if url.contains('?') { '&' } else { '?' };
    let scoped = format!("{url}{separator}options=-c%20search_path%3D{schema}");
    Ok((scoped, schema, DatabaseInfo { version, sslmode }))
}

async fn drop_schema(url: &str, tls: &DatabaseTls, schema: &str) {
    let Ok(options) = kavach_storage::connect_options(url, tls) else {
        return;
    };
    if let Ok(pool) = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
    {
        let _ = sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&pool)
            .await;
        pool.close().await;
    }
}

/// Issues a mandate for subject `i` through the system-of-record listener.
async fn issue(
    client: &reqwest::Client,
    sor_url: &str,
    bundle: &Path,
    i: usize,
    at: DateTime<Utc>,
) -> Result<String, String> {
    let event = SorEvent {
        event_id: format!("bench-{i}"),
        tenant_id: TENANT.into(),
        system: "lms".into(),
        event_type: "loan.dpd30".into(),
        record_ref: format!("lms:loan/BENCH-{i}"),
        subject_ref: subject_ref(i),
        principal: "nbfc-collections-system".into(),
        consent_refs: [format!("C-bench-{i}")].into(),
        assigned_agent: AGENT.into(),
        occurred_at: at,
        nonce: format!("n-bench-{i}"),
    };
    let keys = kavach_keys::LocalFileKeyProvider::new(bundle.join("sor"));
    let token = kavach_mandate::jws::sign(
        &keys,
        kavach_devkit::SOR_KID,
        kavach_mandate::jws::TYP_SOR_EVENT,
        &event,
    )
    .await
    .map_err(|e| e.to_string())?;
    let response = client
        .post(format!("{sor_url}/v1/sor/events"))
        .json(&json!({ "event": token }))
        .send()
        .await
        .map_err(|e| format!("issue mandate {i}: {e}"))?;
    let status = response.status();
    let body: Value = response.json().await.unwrap_or(Value::Null);
    body["mandate_id"]
        .as_str()
        .map(ToString::to_string)
        .ok_or_else(|| format!("issue mandate {i}: {status} {body}"))
}

impl Stack {
    pub async fn start(opts: &StackOptions) -> Result<Self, String> {
        let bundle = opts.work.join("bundle");
        kavach_devkit::generate(&kavach_devkit::Options {
            out: bundle.clone(),
            kavach_mount: bundle.join("kavach").display().to_string(),
            provider_endpoint: "https://mock-provider:8443".into(),
            provider_hosts: vec!["mock-provider".into()],
            database_hosts: vec!["postgres".into()],
            token_hours: 24,
        })
        .await?;
        let at = bench_time();
        let clock = Arc::new(FakeClock::synced_at(at));
        let provider_url = start_provider(&bundle, Arc::clone(&clock), opts.provider_delay).await?;
        write_workload(&bundle.join("kavach"), opts.subjects, &provider_url)?;

        let (store, tls, database, cleanup) = match &opts.store {
            Store::Memory => (
                EvidenceStoreKind::Memory,
                DatabaseTls::development(),
                None,
                None,
            ),
            Store::Postgres {
                database_url,
                tls,
                keep_schema,
            } => {
                let (scoped, schema, info) = create_schema(database_url, tls).await?;
                let cleanup = (!keep_schema).then(|| (database_url.clone(), tls.clone(), schema));
                (
                    EvidenceStoreKind::Postgres {
                        database_url: scoped,
                    },
                    tls.clone(),
                    Some(info),
                    cleanup,
                )
            }
        };
        let storage = match &store {
            EvidenceStoreKind::Postgres { database_url } => Some(
                kavach_storage::StoragePool::connect_with_roles_sized(
                    database_url,
                    None,
                    &tls,
                    opts.pool_size,
                )
                .await
                .map_err(|e| format!("storage: {e}"))?,
            ),
            EvidenceStoreKind::Memory => None,
        };
        let test_clock = TestClock(Arc::clone(&clock) as Arc<dyn TimeSource + Send + Sync>);
        let config = api_config(&bundle, store, tls, opts.pool_size, test_clock);
        let state = Arc::new(
            AppState::from_config(&config)
                .await
                .map_err(|e| format!("kavach-api: {e:?}"))?,
        );
        let agent_url = serve(agent_router(Arc::clone(&state))).await?;
        let sor_url = serve(sor_router(Arc::clone(&state))).await?;

        let client = reqwest::Client::new();
        let mut subjects = Vec::with_capacity(opts.subjects);
        for i in 0..opts.subjects {
            subjects.push(Subject {
                subject_ref: subject_ref(i),
                mandate_id: issue(&client, &sor_url, &bundle, i, at).await?,
            });
        }
        Ok(Self {
            agent_url,
            agent_token: read(&bundle.join(format!("agents/{AGENT}.jwt")))?
                .trim()
                .into(),
            subjects,
            stranger: subject_ref(opts.subjects),
            database,
            storage,
            clock,
            pool_size: opts.pool_size,
            state,
            cleanup,
        })
    }

    /// The Postgres pool size, when there is a database.
    #[must_use]
    pub fn database_pool(&self) -> Option<u32> {
        self.database.as_ref().map(|_| self.pool_size)
    }

    /// Drops the run's schema (unless it was kept).
    pub async fn finish(self) {
        drop(self.state);
        if let Some(storage) = self.storage {
            storage.pool.close().await;
        }
        if let Some((url, tls, schema)) = &self.cleanup {
            drop_schema(url, tls, schema).await;
        }
    }
}

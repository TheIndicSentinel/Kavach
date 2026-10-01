//! Agent surfaces (ADR-007, H5a-5): `POST /v1/authorize` (pre-check) for
//! agents, and `POST /v1/sor/events` for systems of record on a separate
//! listener.
//!
//! - Agents authenticate only with access tokens for the **agent audience**
//!   (a verifier separate from the operator one); `X-Kavach-Principal` is
//!   never accepted here, not even with `--insecure-dev`. The agent id comes
//!   from a configurable claim (default `azp`); an agent without a passport
//!   is refused.
//! - Without `--insecure-dev`, startup refuses development stand-ins: the
//!   agent surfaces need Postgres and a readable kernel clock.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::extract::rejection::JsonRejection;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use chrono::{DateTime, NaiveDate, Utc};
use kavach_credential::{JoseCredentialBroker, RecipientKey};
use kavach_dataplane::{
    AgentIdentity, AuthorizeConfig, AuthorizeCore, Mode, RegistryTrust, ToolRegistry, ToolRequest,
};
use kavach_domain::mandate::{AgentPassport, ConsentRecord, MandateTemplate, RevocationReason};
use kavach_domain::Decision;
use kavach_keys::{Ed25519EvidenceSigner, LocalFileKeyProvider, SubjectKeys, TrustedSigners};
use kavach_mandate::jws::KeySet;
use kavach_mandate::memory::{InMemoryConsentSource, InMemoryEventBus, InMemoryMandateStore};
use kavach_mandate::{MandateConfig, MandateDeps, MandateService, SorIssuer};
use kavach_ports::agent_evidence::{
    AgentDecisionRecord, AgentEvidenceStore, CommitRequest, CommitResult, EvidenceSigner,
    OutcomeRecord,
};
use kavach_ports::CredentialBroker;
use kavach_ports::{
    ErrorClass, KeyAlgorithm, KeyProvider, MandateStore, PortError, PublicKey, ReplayGuard,
    StoredMandate, SyncStatus, TimeSource, TrustedNow,
};
use kavach_storage::{
    MemoryAgentEvidenceStore, PostgresAgentEvidenceStore, PostgresMandateStore,
    PostgresReplayGuard, StoragePool,
};
use serde::{Deserialize, Serialize};

use crate::oidc::{OidcConfig, OidcError, OidcVerifier};
use crate::state::AppState;

/// Size limit for a system-of-record event request.
pub const SOR_BODY_LIMIT: usize = 16 * 1024;

#[derive(Debug, Clone)]
pub struct DataplaneConfig {
    /// Agent tokens: same IdP, **different audience** than operators;
    /// `principal_claim` is the agent id claim (default `azp`).
    pub agent_oidc: OidcConfig,
    /// Mandate configuration (JSON): issuer, SoR issuers, templates, passports.
    pub mandate_config: PathBuf,
    /// Directory with the mandate signing key (`<signing_kid>.ed25519`).
    pub mandate_keys_dir: PathBuf,
    /// Directory and id of the evidence signing key (signs evidence only).
    pub evidence_keys_dir: PathBuf,
    pub evidence_key_id: String,
    /// 32-byte hex secret for subject pseudonyms and parameter MACs.
    pub subject_pseudonym_key: PathBuf,
    /// Consent fixture (JSON list of consent records; PRD D7).
    pub consents: PathBuf,
    pub tenant_id: String,
    /// System-of-record events accepted per second (token bucket).
    pub sor_rate_per_second: u32,
    /// Agent tool registry (YAML, signed: `<path>.sig`).
    pub tool_registry: PathBuf,
    /// Expected registry digest (`sha256:<hex>`), checked before the signature.
    pub tool_registry_sha256: Option<String>,
    /// Trusted signers for the registry (`tool` role). Defaults to the pack
    /// signers file; one `signers.json` with roles can serve both.
    pub tool_signers: Option<PathBuf>,
    /// Directory and id of the credential signing key (signs resource
    /// credentials only; must differ from the mandate and evidence keys).
    pub credential_keys_dir: PathBuf,
    pub credential_key_id: String,
    /// Resource providers (JSON): each audience's X25519 encryption key.
    pub providers: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProvidersFile {
    providers: Vec<ProviderEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderEntry {
    /// The credential audience (a tool registry `provider`).
    audience: String,
    /// The provider's encryption key id.
    kid: String,
    /// Hex X25519 public key.
    x25519_public_key: String,
}

pub type Broker = JoseCredentialBroker<LocalFileKeyProvider>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SorIssuerFile {
    system: String,
    kid: String,
    /// Hex Ed25519 public key.
    public_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MandateConfigFile {
    issuer_id: String,
    signing_kid: String,
    sor_issuers: Vec<SorIssuerFile>,
    templates: Vec<MandateTemplate>,
    passports: Vec<AgentPassport>,
    event_freshness_seconds: i64,
    replay_window_seconds: i64,
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path, what: &str) -> Result<T, String> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("{what} {}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("{what} {}: {e}", path.display()))
}

// ---- adapters selected at startup (ADR-006 §5) ----

pub enum MandateStoreBackend {
    Memory(InMemoryMandateStore),
    Postgres(PostgresMandateStore),
}

impl MandateStore for MandateStoreBackend {
    async fn insert(&self, record: StoredMandate) -> Result<(), PortError> {
        match self {
            Self::Memory(s) => s.insert(record).await,
            Self::Postgres(s) => s.insert(record).await,
        }
    }
    async fn insert_child(&self, record: StoredMandate) -> Result<(), PortError> {
        match self {
            Self::Memory(s) => s.insert_child(record).await,
            Self::Postgres(s) => s.insert_child(record).await,
        }
    }
    async fn get(&self, tenant_id: &str, id: &str) -> Result<Option<StoredMandate>, PortError> {
        match self {
            Self::Memory(s) => s.get(tenant_id, id).await,
            Self::Postgres(s) => s.get(tenant_id, id).await,
        }
    }
    async fn root_for_event(
        &self,
        tenant_id: &str,
        system: &str,
        event_id: &str,
    ) -> Result<Option<StoredMandate>, PortError> {
        match self {
            Self::Memory(s) => s.root_for_event(tenant_id, system, event_id).await,
            Self::Postgres(s) => s.root_for_event(tenant_id, system, event_id).await,
        }
    }
    async fn ancestors(
        &self,
        tenant_id: &str,
        id: &str,
        limit: usize,
    ) -> Result<Vec<StoredMandate>, PortError> {
        match self {
            Self::Memory(s) => s.ancestors(tenant_id, id, limit).await,
            Self::Postgres(s) => s.ancestors(tenant_id, id, limit).await,
        }
    }
    async fn revoke_tree(
        &self,
        tenant_id: &str,
        id: &str,
        reason: RevocationReason,
    ) -> Result<Vec<(String, RevocationReason)>, PortError> {
        match self {
            Self::Memory(s) => s.revoke_tree(tenant_id, id, reason).await,
            Self::Postgres(s) => s.revoke_tree(tenant_id, id, reason).await,
        }
    }
}

/// Development replay memory (single process); production uses Postgres.
#[derive(Default)]
pub struct DevReplayGuard {
    seen: Mutex<std::collections::HashMap<(String, String), DateTime<Utc>>>,
}

pub enum ReplayBackend {
    Dev(DevReplayGuard),
    Postgres(PostgresReplayGuard),
}

impl ReplayGuard for ReplayBackend {
    async fn check_and_record(
        &self,
        tenant_id: &str,
        key: &str,
        now: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<(), PortError> {
        match self {
            Self::Postgres(g) => g.check_and_record(tenant_id, key, now, expires_at).await,
            Self::Dev(g) => {
                let mut seen = g
                    .seen
                    .lock()
                    .map_err(|_| PortError::unavailable("replay lock poisoned"))?;
                let k = (tenant_id.to_string(), key.to_string());
                if seen.get(&k).is_some_and(|exp| *exp > now) {
                    return Err(PortError::rejected(format!("replayed identifier {key}")));
                }
                seen.insert(k, expires_at);
                Ok(())
            }
        }
    }
}

pub enum EvidenceBackend {
    Memory(Box<MemoryAgentEvidenceStore>),
    Postgres(PostgresAgentEvidenceStore),
}

impl AgentEvidenceStore for EvidenceBackend {
    async fn commit(
        &self,
        request: CommitRequest,
        clock: &dyn TimeSource,
        signer: &dyn EvidenceSigner,
    ) -> Result<CommitResult, PortError> {
        match self {
            Self::Memory(s) => s.commit(request, clock, signer).await,
            Self::Postgres(s) => s.commit(request, clock, signer).await,
        }
    }
    async fn get_by_request(
        &self,
        tenant_id: &str,
        agent_id: &str,
        request_id: &str,
    ) -> Result<Option<AgentDecisionRecord>, PortError> {
        match self {
            Self::Memory(s) => s.get_by_request(tenant_id, agent_id, request_id).await,
            Self::Postgres(s) => s.get_by_request(tenant_id, agent_id, request_id).await,
        }
    }
    async fn record_outcome(&self, outcome: OutcomeRecord) -> Result<(), PortError> {
        match self {
            Self::Memory(s) => s.record_outcome(outcome).await,
            Self::Postgres(s) => s.record_outcome(outcome).await,
        }
    }
    async fn outcome(
        &self,
        tenant_id: &str,
        credential_id: &str,
    ) -> Result<Option<OutcomeRecord>, PortError> {
        match self {
            Self::Memory(s) => s.outcome(tenant_id, credential_id).await,
            Self::Postgres(s) => s.outcome(tenant_id, credential_id).await,
        }
    }
    async fn records(
        &self,
        tenant_id: &str,
        partition_id: i32,
    ) -> Result<Vec<AgentDecisionRecord>, PortError> {
        match self {
            Self::Memory(s) => s.records(tenant_id, partition_id).await,
            Self::Postgres(s) => s.records(tenant_id, partition_id).await,
        }
    }
    async fn contacts_on(
        &self,
        tenant_id: &str,
        subject_pseudonym: &str,
        ist_date: NaiveDate,
    ) -> Result<u32, PortError> {
        match self {
            Self::Memory(s) => s.contacts_on(tenant_id, subject_pseudonym, ist_date).await,
            Self::Postgres(s) => s.contacts_on(tenant_id, subject_pseudonym, ist_date).await,
        }
    }
}

/// Trusted time: the kernel clock, or — only with `--insecure-dev` — the
/// system clock declared synced (development machines without NTP status).
#[derive(Clone, Copy)]
pub enum ClockBackend {
    Kernel(kavach_clocksync::KernelClock),
    InsecureDev,
}

impl TimeSource for ClockBackend {
    fn now(&self) -> TrustedNow {
        match self {
            Self::Kernel(clock) => clock.now(),
            Self::InsecureDev => TrustedNow {
                utc: Utc::now(),
                sync: SyncStatus::Synced { max_error_ms: 0 },
            },
        }
    }
}

pub type Mandates = MandateService<
    LocalFileKeyProvider,
    ReplayBackend,
    InMemoryConsentSource,
    MandateStoreBackend,
    InMemoryEventBus,
    ClockBackend,
>;

struct TokenBucket {
    rate: f64,
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    fn take(&mut self) -> bool {
        let now = Instant::now();
        self.tokens =
            (self.tokens + now.duration_since(self.last).as_secs_f64() * self.rate).min(self.rate);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

pub struct Dataplane {
    mandates: Arc<Mandates>,
    core: AuthorizeCore<Arc<Mandates>, EvidenceBackend>,
    agents: Arc<OidcVerifier>,
    passports: BTreeSet<(String, String)>,
    tenant: String,
    sor_limiter: Mutex<TokenBucket>,
    broker: Broker,
}

impl Dataplane {
    /// Builds the agent surfaces. Without `insecure_dev`, refuses the
    /// development stand-ins (memory stores, an unreadable kernel clock).
    pub async fn build(
        config: &DataplaneConfig,
        pool: Option<&StoragePool>,
        insecure_dev: bool,
        operator_audience: Option<&str>,
        pack_signers: Option<&Path>,
    ) -> Result<Self, String> {
        if operator_audience == Some(config.agent_oidc.audience.as_str()) {
            return Err("the agent token audience must differ from the operator audience".into());
        }
        let tools = Arc::new(load_tools(config, pack_signers, insecure_dev)?);
        let clock = select_clock(insecure_dev)?;
        let (store, replay, evidence) = select_stores(pool, insecure_dev)?;

        let keys = LocalFileKeyProvider::new(&config.mandate_keys_dir);
        let (mandate_config, passports) =
            load_mandate_config(&config.mandate_config, &keys).await?;
        let mandate_kid = mandate_config.signing_kid.clone();
        let consents: Vec<ConsentRecord> = read_json(&config.consents, "consents")?;
        let mandates = Arc::new(
            MandateService::new(
                MandateDeps {
                    keys,
                    replay,
                    consents: InMemoryConsentSource::new(consents),
                    store,
                    events: InMemoryEventBus::new(),
                    clock,
                },
                mandate_config,
            )
            .map_err(|e| format!("mandate config: {e}"))?,
        );
        let signer =
            Ed25519EvidenceSigner::from_key_dir(&config.evidence_keys_dir, &config.evidence_key_id)
                .map_err(|e| format!("evidence key: {e}"))?;
        let broker = build_broker(config, &tools, &mandate_kid, insecure_dev).await?;
        let subject_keys = SubjectKeys::from_file(&config.subject_pseudonym_key)
            .map_err(|e| format!("subject pseudonym key: {e}"))?;
        let core = AuthorizeCore::new(
            Arc::clone(&mandates),
            Arc::new(evidence),
            tools,
            subject_keys,
            Box::new(signer),
            Box::new(clock),
            AuthorizeConfig {
                tenant_id: config.tenant_id.clone(),
                ..AuthorizeConfig::default()
            },
        )
        .map_err(|e| format!("authorization core: {e}"))?;
        let agents = OidcVerifier::load(config.agent_oidc.clone())
            .await
            .map_err(|e| format!("agent token verifier: {e}"))?;
        agents.spawn_refresher();
        let rate = f64::from(config.sor_rate_per_second.max(1));
        Ok(Self {
            mandates,
            core,
            agents,
            passports,
            tenant: config.tenant_id.clone(),
            sor_limiter: Mutex::new(TokenBucket {
                rate,
                tokens: rate,
                last: Instant::now(),
            }),
            broker,
        })
    }

    /// The credential broker (the gateway's only source of credentials).
    pub fn broker(&self) -> &Broker {
        &self.broker
    }

    pub fn core(&self) -> &AuthorizeCore<Arc<Mandates>, EvidenceBackend> {
        &self.core
    }

    pub fn mandates(&self) -> &Arc<Mandates> {
        &self.mandates
    }
}

/// The tool registry, vouched for: signed by a `tool` signer (required
/// unless `--insecure-dev`) and matching the pin, if one is set.
fn load_tools(
    config: &DataplaneConfig,
    pack_signers: Option<&Path>,
    insecure_dev: bool,
) -> Result<ToolRegistry, String> {
    let signers = config
        .tool_signers
        .as_deref()
        .or(pack_signers)
        .map(TrustedSigners::from_file)
        .transpose()
        .map_err(|e| format!("tool signers: {e}"))?;
    if signers.is_none() && insecure_dev {
        eprintln!(
            "WARNING: kavach-api: the agent tool registry is not signature-checked \
             (--insecure-dev). Development only."
        );
    }
    ToolRegistry::load(
        &config.tool_registry,
        RegistryTrust {
            signers: signers.as_ref(),
            pin: config.tool_registry_sha256.as_deref(),
            require_signature: !insecure_dev,
        },
    )
    .map_err(|e| format!("tool registry: {}", e.message))
}

/// The credential broker, with key separation (NIST SP 800-57 key usage):
/// its signing key is neither the mandate nor the evidence key, by id or by
/// key material; every provider the tool registry forwards to has a usable
/// encryption key; and it is not a test double outside `--insecure-dev`.
async fn build_broker(
    config: &DataplaneConfig,
    tools: &ToolRegistry,
    mandate_kid: &str,
    insecure_dev: bool,
) -> Result<Broker, String> {
    let kid = &config.credential_key_id;
    if kid == mandate_kid || kid == &config.evidence_key_id {
        return Err(format!(
            "the credential key {kid} must be a separate key from the mandate and evidence keys"
        ));
    }
    let keys = LocalFileKeyProvider::new(&config.credential_keys_dir);
    let credential = keys
        .public_key(kid)
        .await
        .map_err(|e| format!("credential signing key: {e}"))?;
    let others = [
        LocalFileKeyProvider::new(&config.mandate_keys_dir)
            .public_key(mandate_kid)
            .await,
        LocalFileKeyProvider::new(&config.evidence_keys_dir)
            .public_key(&config.evidence_key_id)
            .await,
    ];
    if others
        .iter()
        .flatten()
        .any(|other| other.bytes == credential.bytes)
    {
        return Err(format!(
            "the credential key {kid} reuses the mandate or evidence key material"
        ));
    }

    let file: ProvidersFile = read_json(&config.providers, "providers")?;
    let mut recipients = std::collections::BTreeMap::new();
    for entry in file.providers {
        let public: [u8; 32] = hex::decode(entry.x25519_public_key.trim())
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| {
                format!(
                    "provider {}: x25519_public_key must be 32 bytes hex",
                    entry.audience
                )
            })?;
        let recipient = RecipientKey {
            kid: entry.kid,
            public,
        };
        // A probe encryption refuses low-order (non-contributory) keys now.
        kavach_credential::jwe::encrypt(b"probe", &recipient, "probe", "probe")
            .map_err(|e| format!("provider {}: {}", entry.audience, e.message))?;
        if recipients
            .insert(entry.audience.clone(), recipient)
            .is_some()
        {
            return Err(format!("provider {} is listed twice", entry.audience));
        }
    }
    if let Some(missing) = tools
        .providers()
        .into_iter()
        .find(|p| !recipients.contains_key(*p))
    {
        return Err(format!(
            "the tool registry forwards to {missing}, which has no encryption key in --providers"
        ));
    }

    let broker = JoseCredentialBroker::new(keys, kid.clone(), "kavach", recipients);
    if broker.is_test_double() && !insecure_dev {
        return Err(
            "the credential broker is a test double; refused outside --insecure-dev".into(),
        );
    }
    Ok(broker)
}

fn select_clock(insecure_dev: bool) -> Result<ClockBackend, String> {
    if insecure_dev {
        eprintln!(
            "WARNING: kavach-api: --insecure-dev declares the system clock synced for agent \
             decisions. Development only."
        );
        Ok(ClockBackend::InsecureDev)
    } else {
        let reading = kavach_clocksync::read();
        if reading.status == SyncStatus::Unknown {
            return Err(format!(
                "agent surfaces need trusted time, and the kernel clock status is unreadable: {}",
                reading.detail
            ));
        }
        Ok(ClockBackend::Kernel(kavach_clocksync::KernelClock))
    }
}

fn select_stores(
    pool: Option<&StoragePool>,
    insecure_dev: bool,
) -> Result<(MandateStoreBackend, ReplayBackend, EvidenceBackend), String> {
    Ok(match pool {
        Some(pool) => (
            MandateStoreBackend::Postgres(pool.mandate_store()),
            ReplayBackend::Postgres(pool.replay_guard()),
            EvidenceBackend::Postgres(pool.agent_evidence_store()),
        ),
        None if insecure_dev => (
            MandateStoreBackend::Memory(InMemoryMandateStore::new()),
            ReplayBackend::Dev(DevReplayGuard::default()),
            EvidenceBackend::Memory(Box::default()),
        ),
        None => {
            return Err(
                "agent surfaces need the Postgres evidence store (memory stores are for \
                 --insecure-dev only)"
                    .into(),
            )
        }
    })
}

async fn load_mandate_config(
    path: &Path,
    keys: &LocalFileKeyProvider,
) -> Result<(MandateConfig, BTreeSet<(String, String)>), String> {
    let file: MandateConfigFile = read_json(path, "mandate config")?;
    let mandate_public = keys
        .public_key(&file.signing_kid)
        .await
        .map_err(|e| format!("mandate signing key: {e}"))?;
    let sor_issuers = file
        .sor_issuers
        .into_iter()
        .map(|i| {
            let bytes: [u8; 32] = hex::decode(i.public_key.trim())
                .ok()
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| format!("sor issuer {}: public_key must be 32 bytes hex", i.kid))?;
            Ok(SorIssuer {
                system: i.system,
                key: PublicKey {
                    kid: i.kid,
                    algorithm: KeyAlgorithm::Ed25519,
                    bytes,
                },
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let passports = file
        .passports
        .iter()
        .map(|p| (p.tenant_id.clone(), p.agent_id.clone()))
        .collect();
    let mandate_config = MandateConfig {
        issuer_id: file.issuer_id,
        signing_kid: file.signing_kid,
        mandate_keys: KeySet::new([mandate_public]),
        sor_issuers,
        templates: file.templates,
        passports: file.passports,
        event_freshness_seconds: file.event_freshness_seconds,
        replay_window_seconds: file.replay_window_seconds,
    };
    Ok((mandate_config, passports))
}

// ---- HTTP ----

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub error: String,
}

type Refusal = (StatusCode, Json<ErrorBody>);

fn refuse(status: StatusCode, error: impl Into<String>) -> Refusal {
    (
        status,
        Json(ErrorBody {
            error: error.into(),
        }),
    )
}

fn dataplane(state: &AppState) -> Result<&Dataplane, Refusal> {
    state
        .dataplane()
        .ok_or_else(|| refuse(StatusCode::NOT_FOUND, "agent surfaces are not configured"))
}

/// The authenticated agent: a bearer token for the agent audience, from an
/// agent with a passport. The operator header is never accepted.
fn authenticate_agent(dp: &Dataplane, headers: &HeaderMap) -> Result<AgentIdentity, Refusal> {
    if headers.contains_key("x-kavach-principal") {
        return Err(refuse(
            StatusCode::UNAUTHORIZED,
            "X-Kavach-Principal is not accepted on agent surfaces",
        ));
    }
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split_once(' '))
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
        .map(|(_, token)| token.trim())
        .ok_or_else(|| refuse(StatusCode::UNAUTHORIZED, "agent access token required"))?;
    let verified = dp.agents.verify(token).map_err(|err| {
        if matches!(err, OidcError::UnknownKid(_)) {
            dp.agents.request_refresh();
        }
        refuse(StatusCode::UNAUTHORIZED, "invalid agent access token")
    })?;
    if !dp
        .passports
        .contains(&(dp.tenant.clone(), verified.principal.clone()))
    {
        return Err(refuse(StatusCode::FORBIDDEN, "agent has no passport"));
    }
    Ok(AgentIdentity {
        identity_key: format!("oidc:{}#{}", dp.agents.issuer(), verified.principal),
        agent_id: verified.principal,
        // Agent risk states (RESTRICTED/QUARANTINED) arrive with the
        // gateway's taint tracking (FR-5).
        state: kavach_authz::AgentState::Active,
    })
}

/// A pre-check: the tool and the request the agent would send to
/// `POST /v1/tools/{tool}`, extracted through the same registry.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizeBody {
    pub tool: String,
    pub mandate_id: String,
    pub request_id: String,
    #[serde(default)]
    pub params: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct AuthorizeResponse {
    pub decision: Decision,
    pub reasons: Vec<String>,
    /// Always true here: a pre-check authorises nothing. Only the gateway
    /// executes and records (ADR-007).
    pub precheck: bool,
}

/// `POST /v1/authorize`: the decision the gateway would make, without
/// reserving a contact or recording anything.
pub async fn authorize(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Result<Json<AuthorizeBody>, JsonRejection>,
) -> Result<Json<AuthorizeResponse>, Refusal> {
    let dp = dataplane(&state)?;
    let agent = authenticate_agent(dp, &headers)?;
    // Malformed or unknown fields: 400, nothing recorded (H5b item 5).
    // The parser's message can quote values, so it is not echoed.
    let Json(body) = body.map_err(|_| {
        refuse(
            StatusCode::BAD_REQUEST,
            "malformed body: expected JSON with exactly tool, mandate_id, request_id, params",
        )
    })?;
    let call = dp
        .core
        .tools()
        .extract(
            &body.tool,
            ToolRequest {
                mandate_id: body.mandate_id,
                request_id: body.request_id,
                params: body.params,
            },
        )
        .map_err(|e| refuse(StatusCode::BAD_REQUEST, e.message))?;
    let decided = dp
        .core
        .authorize(&agent, &call, Mode::Precheck)
        .await
        .map_err(|e| refuse(StatusCode::BAD_REQUEST, e.message))?;
    Ok(Json(AuthorizeResponse {
        decision: decided.decision,
        reasons: decided.reasons,
        precheck: true,
    }))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SorEventBody {
    /// The signed event (JWS, `typ` sor-event).
    pub event: String,
}

#[derive(Debug, Serialize)]
pub struct SorEventResponse {
    pub mandate_id: String,
    pub exp: DateTime<Utc>,
    /// True when this event had already issued the mandate (a retry).
    pub replayed: bool,
}

/// `POST /v1/sor/events` (system-of-record listener, ADR-004 §4): a signed
/// event issues a mandate. A retry with identical content returns the
/// existing mandate; the same event id with other content is a conflict.
pub async fn sor_event(
    State(state): State<Arc<AppState>>,
    Json(body): Json<SorEventBody>,
) -> Result<(StatusCode, Json<SorEventResponse>), Refusal> {
    let dp = dataplane(&state)?;
    let allowed = dp.sor_limiter.lock().is_ok_and(|mut bucket| bucket.take());
    if !allowed {
        return Err(refuse(StatusCode::TOO_MANY_REQUESTS, "event rate limit"));
    }
    match dp.mandates.issue_from_event(&body.event).await {
        Ok(issued) => Ok((
            StatusCode::CREATED,
            Json(SorEventResponse {
                mandate_id: issued.mandate.id,
                exp: issued.mandate.exp,
                replayed: false,
            }),
        )),
        Err(issue_err) => match dp.mandates.existing_for_event(&body.event).await {
            Ok(Some(existing)) => Ok((
                StatusCode::OK,
                Json(SorEventResponse {
                    mandate_id: existing.mandate.id,
                    exp: existing.mandate.exp,
                    replayed: true,
                }),
            )),
            Err(conflict)
                if conflict.class == ErrorClass::Rejected
                    && conflict.message.contains("different content") =>
            {
                Err(refuse(StatusCode::CONFLICT, conflict.message))
            }
            _ => Err(match issue_err.class {
                ErrorClass::Invalid => refuse(StatusCode::BAD_REQUEST, issue_err.message),
                ErrorClass::Rejected => refuse(StatusCode::UNPROCESSABLE_ENTITY, issue_err.message),
                ErrorClass::Unavailable => {
                    refuse(StatusCode::SERVICE_UNAVAILABLE, issue_err.message)
                }
            }),
        },
    }
}

/// Router for the agent listener (`--agent-listen`, the only listener on the
/// agent network): agent routes and liveness — never operator, admin,
/// change-request, metrics or system-of-record routes (ADR-007).
pub fn agent_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/authorize", post(authorize))
        .route(
            "/health",
            axum::routing::get(|| async { Json(serde_json::json!({ "status": "ok" })) }),
        )
        .with_state(state)
}

/// Router for the system-of-record listener (backend network only).
pub fn sor_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/sor/events", post(sor_event))
        .layer(DefaultBodyLimit::max(SOR_BODY_LIMIT))
        .with_state(state)
}

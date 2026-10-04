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

use crate::strict_json::{StrictJson, StrictJsonRejection};
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use chrono::{DateTime, NaiveDate, Utc};
use kavach_credential::{JoseCredentialBroker, RecipientKey};
use kavach_dataplane::{
    execute, AgentIdentity, AuthorizeConfig, AuthorizeCore, CheckpointPolicy, Checkpointer,
    Decided, FixtureResolver, GatewayDeps, GatewayError, GatewayReply, Mode, RegistryTrust,
    ToolRegistry, ToolRequest, WhatIfStore,
};
use kavach_domain::mandate::{AgentPassport, ConsentRecord, MandateTemplate, RevocationReason};
use kavach_domain::Decision;
use kavach_keys::{SubjectKeys, TrustedSigners};

use crate::signing::{HsmConfig, HsmRole, HsmStatus, KeySources, SigningKeys};
use kavach_mandate::jws::KeySet;
use kavach_mandate::memory::{InMemoryConsentSource, InMemoryEventBus, InMemoryMandateStore};
use kavach_mandate::{MandateConfig, MandateDeps, MandateService, SorIssuer};
use kavach_ports::agent_evidence::{
    AgentDecisionRecord, AgentEvidenceStore, CommitRequest, CommitResult, EvidenceSigner,
    OutcomeRecord,
};
use kavach_ports::checkpoint::{Appended, Checkpoint, CheckpointStore, Scope};
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
    /// Directory and id of the checkpoint signing key (signs evidence
    /// checkpoints only; must differ from every other key). Mandatory:
    /// there is no mode without checkpoints (ADR-005 §13).
    pub checkpoint_keys_dir: PathBuf,
    pub checkpoint_key_id: String,
    /// Uncovered records get a checkpoint at least this often (1–3600).
    pub checkpoint_interval_seconds: u64,
    /// Records uncovered by a checkpoint for this long raise an alert.
    pub checkpoint_stall_seconds: u64,
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
    /// Reference fixture (JSON): capability references to destinations,
    /// synthetic numbers only (a reference vault replaces it in M2).
    pub references: PathBuf,
    /// Gateway → provider timeouts (no retries). Both stay below the
    /// credential lifetime.
    pub provider_connect_timeout_ms: u64,
    pub provider_timeout_ms: u64,
    /// CA certificates (PEM) trusted for provider TLS, besides the system
    /// roots (e.g. a private CA for internal providers).
    pub provider_ca: Option<PathBuf>,
    /// Signing keys held in an HSM, per role (`--hsm-*`); the other roles
    /// use their key directories.
    pub hsm: Option<HsmConfig>,
    /// Tests only (no CLI flag): a controllable trusted clock. Refused
    /// outside `--insecure-dev`.
    pub test_clock: Option<TestClock>,
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
    /// Base URL the gateway forwards to (`<endpoint>/v1/messages`). HTTPS
    /// preferred; plain HTTP only on an isolated backend network.
    endpoint: String,
}

pub type Broker = JoseCredentialBroker<SigningKeys>;

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
    /// Earlier mandate signing keys, after a rotation: trusted to verify the
    /// mandates they signed until those expire, never used to sign.
    #[serde(default)]
    previous_mandate_keys: Vec<VerificationKeyFile>,
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
    async fn record(
        &self,
        tenant_id: &str,
        record_id: &str,
    ) -> Result<Option<AgentDecisionRecord>, PortError> {
        match self {
            Self::Memory(s) => s.record(tenant_id, record_id).await,
            Self::Postgres(s) => s.record(tenant_id, record_id).await,
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

impl CheckpointStore for EvidenceBackend {
    async fn head(&self, scope: Scope<'_>) -> Result<Option<(i64, String)>, PortError> {
        match self {
            Self::Memory(s) => s.head(scope).await,
            Self::Postgres(s) => s.head(scope).await,
        }
    }
    async fn latest(&self, scope: Scope<'_>) -> Result<Option<Checkpoint>, PortError> {
        match self {
            Self::Memory(s) => s.latest(scope).await,
            Self::Postgres(s) => s.latest(scope).await,
        }
    }
    async fn append(&self, checkpoint: &Checkpoint) -> Result<Appended, PortError> {
        match self {
            Self::Memory(s) => s.append(checkpoint).await,
            Self::Postgres(s) => s.append(checkpoint).await,
        }
    }
    async fn list(
        &self,
        scope: Scope<'_>,
        after_seq: i64,
        limit: u32,
    ) -> Result<Vec<Checkpoint>, PortError> {
        match self {
            Self::Memory(s) => s.list(scope, after_seq, limit).await,
            Self::Postgres(s) => s.list(scope, after_seq, limit).await,
        }
    }
}

/// Trusted time: the kernel clock, or — only with `--insecure-dev` — the
/// system clock declared synced (development machines without NTP status).
#[derive(Clone)]
pub enum ClockBackend {
    Kernel(kavach_clocksync::KernelClock),
    InsecureDev,
    /// A clock a test controls (only with `--insecure-dev`; no CLI flag).
    Test(TestClock),
}

/// A clock injected by an embedding test (`DataplaneConfig::test_clock`).
/// Startup refuses it outside `--insecure-dev`.
#[derive(Clone)]
pub struct TestClock(pub Arc<dyn TimeSource + Send + Sync>);

impl std::fmt::Debug for TestClock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TestClock")
    }
}

impl TimeSource for ClockBackend {
    fn now(&self) -> TrustedNow {
        match self {
            Self::Kernel(clock) => clock.now(),
            Self::Test(clock) => clock.0.now(),
            Self::InsecureDev => TrustedNow {
                utc: Utc::now(),
                sync: SyncStatus::Synced { max_error_ms: 0 },
            },
        }
    }
}

pub type Mandates = MandateService<
    SigningKeys,
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
    checkpointer: Arc<Checkpointer<EvidenceBackend>>,
    agents: Arc<OidcVerifier>,
    passports: BTreeSet<(String, String)>,
    tenant: String,
    sor_limiter: Mutex<TokenBucket>,
    broker: Broker,
    resolver: FixtureResolver,
    forwarder: crate::forward::HttpForwarder,
    keys: KeySources,
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
        // Before anything else: a dev bundle must never run as production.
        refuse_dev_key("evidence", &config.evidence_key_id, insecure_dev)?;
        refuse_dev_key("checkpoint", &config.checkpoint_key_id, insecure_dev)?;
        refuse_dev_key("credential", &config.credential_key_id, insecure_dev)?;
        let tools = Arc::new(load_tools(config, pack_signers, insecure_dev)?);
        let clock = match &config.test_clock {
            Some(_) if !insecure_dev => {
                return Err("a test clock is refused outside --insecure-dev".into())
            }
            Some(test) => ClockBackend::Test(test.clone()),
            None => select_clock(insecure_dev)?,
        };
        let (store, replay, evidence) = select_stores(pool, insecure_dev)?;

        let sources = open_key_sources(config, insecure_dev)?;
        let keys = sources.keys(HsmRole::Mandate, &config.mandate_keys_dir);
        let (mandate_config, passports) =
            load_mandate_config(&config.mandate_config, &keys, insecure_dev).await?;
        let mandate_kid = mandate_config.signing_kid.clone();
        refuse_dev_key("mandate signing", &mandate_kid, insecure_dev)?;
        for issuer in &mandate_config.sor_issuers {
            refuse_dev_key("system-of-record issuer", &issuer.key.kid, insecure_dev)?;
        }
        let consents: Vec<ConsentRecord> = read_json(&config.consents, "consents")?;
        let mandates = Arc::new(
            MandateService::new(
                MandateDeps {
                    keys,
                    replay,
                    consents: InMemoryConsentSource::new(consents),
                    store,
                    events: InMemoryEventBus::new(),
                    clock: clock.clone(),
                },
                mandate_config,
            )
            .map_err(|e| format!("mandate config: {e}"))?,
        );
        let signer = sources.evidence_signer(
            HsmRole::Evidence,
            &config.evidence_keys_dir,
            &config.evidence_key_id,
        )?;
        let resolver = FixtureResolver::from_file(&config.references)
            .map_err(|e| format!("references: {}", e.message))?;
        let forwarder = build_forwarder(config, &tools)?;
        let broker = build_broker(config, &tools, &mandate_kid, insecure_dev, &sources).await?;
        let subject_keys = SubjectKeys::from_file(&config.subject_pseudonym_key)
            .map_err(|e| format!("subject pseudonym key: {e}"))?;
        let evidence = Arc::new(evidence);
        let authorize = AuthorizeConfig {
            tenant_id: config.tenant_id.clone(),
            ..AuthorizeConfig::default()
        };
        let checkpointer = Arc::new(build_checkpointer(
            config,
            &evidence,
            checkpoint_signer(config, &mandate_kid, &sources).await?,
            &clock,
            &authorize,
        ));
        let core = AuthorizeCore::new(
            Arc::clone(&mandates),
            evidence,
            tools,
            subject_keys,
            signer,
            Box::new(clock),
            authorize,
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
            checkpointer,
            agents,
            passports,
            tenant: config.tenant_id.clone(),
            sor_limiter: Mutex::new(TokenBucket {
                rate,
                tokens: rate,
                last: Instant::now(),
            }),
            broker,
            resolver,
            forwarder,
            keys: sources,
        })
    }

    /// Which signing roles use the HSM and whether it answers now; `None`
    /// when every key is a key file.
    pub async fn hsm_status(&self) -> Option<HsmStatus> {
        self.keys.status().await
    }

    pub fn forwarder(&self) -> &crate::forward::HttpForwarder {
        &self.forwarder
    }

    /// Resolves capability references, after an allow, inside the gateway.
    pub fn resolver(&self) -> &FixtureResolver {
        &self.resolver
    }

    /// The credential broker (the gateway's only source of credentials).
    pub fn broker(&self) -> &Broker {
        &self.broker
    }

    pub fn core(&self) -> &AuthorizeCore<Arc<Mandates>, EvidenceBackend> {
        &self.core
    }

    /// The checkpoint writer's state (the background task ticks it).
    pub fn checkpointer(&self) -> &Arc<Checkpointer<EvidenceBackend>> {
        &self.checkpointer
    }

    pub fn mandates(&self) -> &Arc<Mandates> {
        &self.mandates
    }
}

/// A what-if authorizer (`kavach authorize`): the same mandate checks,
/// agent policies and tool registry as [`Dataplane`], in pre-check mode,
/// over in-memory mandates and a [`WhatIfStore`]. Nothing is recorded, no
/// contact is reserved and nothing listens. Development bundles only: it
/// runs as `--insecure-dev` does.
pub struct WhatIf {
    mandates: Arc<Mandates>,
    core: AuthorizeCore<Arc<Mandates>, WhatIfStore>,
    passports: BTreeSet<(String, String)>,
    tenant: String,
}

impl WhatIf {
    /// Decisions are made at `clock`'s time, with `contacts_today` contacts
    /// already made with the subject today.
    pub async fn build(
        config: &DataplaneConfig,
        clock: TestClock,
        contacts_today: u32,
    ) -> Result<Self, String> {
        let insecure_dev = true;
        let tools = Arc::new(load_tools(config, None, insecure_dev)?);
        let clock = ClockBackend::Test(clock);
        let sources = open_key_sources(config, insecure_dev)?;
        let keys = sources.keys(HsmRole::Mandate, &config.mandate_keys_dir);
        let (mandate_config, passports) =
            load_mandate_config(&config.mandate_config, &keys, insecure_dev).await?;
        let consents: Vec<ConsentRecord> = read_json(&config.consents, "consents")?;
        let mandates = Arc::new(
            MandateService::new(
                MandateDeps {
                    keys,
                    replay: ReplayBackend::Dev(DevReplayGuard::default()),
                    consents: InMemoryConsentSource::new(consents),
                    store: MandateStoreBackend::Memory(InMemoryMandateStore::new()),
                    events: InMemoryEventBus::new(),
                    clock: clock.clone(),
                },
                mandate_config,
            )
            .map_err(|e| format!("mandate config: {e}"))?,
        );
        // Never used: a pre-check signs nothing. The core needs one.
        let signer = sources.evidence_signer(
            HsmRole::Evidence,
            &config.evidence_keys_dir,
            &config.evidence_key_id,
        )?;
        let subject_keys = SubjectKeys::from_file(&config.subject_pseudonym_key)
            .map_err(|e| format!("subject pseudonym key: {e}"))?;
        let core = AuthorizeCore::new(
            Arc::clone(&mandates),
            Arc::new(WhatIfStore { contacts_today }),
            tools,
            subject_keys,
            signer,
            Box::new(clock),
            AuthorizeConfig {
                tenant_id: config.tenant_id.clone(),
                ..AuthorizeConfig::default()
            },
        )
        .map_err(|e| format!("authorization core: {e}"))?;
        Ok(Self {
            mandates,
            core,
            passports,
            tenant: config.tenant_id.clone(),
        })
    }

    /// Issues a mandate from a signed system-of-record event, in memory:
    /// it lives only as long as this value.
    pub async fn issue(&self, event: &str) -> Result<String, String> {
        self.mandates
            .issue_from_event(event)
            .await
            .map(|issued| issued.mandate.id)
            .map_err(|e| e.message)
    }

    pub fn tools(&self) -> &ToolRegistry {
        self.core.tools()
    }

    /// The in-memory mandate service (as [`Dataplane::mandates`]), e.g. to
    /// delegate a what-if mandate through the real delegation rules.
    pub fn mandates(&self) -> &Arc<Mandates> {
        &self.mandates
    }

    /// The decision the gateway would make for `agent_id` calling `tool`
    /// now. `Err` for a request the gateway would refuse with 400 or 403.
    pub async fn precheck(
        &self,
        agent_id: &str,
        tool: &str,
        request: ToolRequest,
    ) -> Result<Decided, String> {
        if !self
            .passports
            .contains(&(self.tenant.clone(), agent_id.to_string()))
        {
            return Err(format!("agent {agent_id} has no passport"));
        }
        let call = self
            .core
            .tools()
            .extract(tool, request)
            .map_err(|e| e.message)?;
        let agent = AgentIdentity {
            agent_id: agent_id.into(),
            identity_key: format!("what-if#{agent_id}"),
            state: kavach_authz::AgentState::Active,
        };
        self.core
            .authorize(&agent, &call, Mode::Precheck)
            .await
            .map_err(|e| e.message)
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
        tracing::warn!(
            "the agent tool registry is not signature-checked \
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

/// Development keys (`dev-…`, from `kavach-devkit`) are refused outside
/// `--insecure-dev`, so a dev bundle can never sign production evidence,
/// mandates or credentials.
/// Export keys (`export-…`) are refused always.
fn refuse_dev_key(what: &str, kid: &str, insecure_dev: bool) -> Result<(), String> {
    // Export keys sign bundles and live with the auditor (ADR-005 §13):
    // never a key of this process, in any profile.
    if kavach_ports::bundle::is_export_key(kid) {
        return Err(format!(
            "the {what} key {kid} is named as an export key (export-…); export keys sign \
             evidence bundles and are never used by the API"
        ));
    }
    if !insecure_dev && kavach_ports::agent_evidence::is_dev_key(kid) {
        return Err(format!(
            "the {what} key {kid} is a development key (dev-…); development keys are refused \
             outside --insecure-dev"
        ));
    }
    Ok(())
}

/// The checkpoint signer: a key of its own. The same id or the same key
/// material as the mandate, evidence or credential key is refused, so a
/// checkpoint signature can never be produced by a key with another job.
async fn checkpoint_signer(
    config: &DataplaneConfig,
    mandate_kid: &str,
    sources: &KeySources,
) -> Result<Box<dyn EvidenceSigner>, String> {
    if !(1..=3600).contains(&config.checkpoint_interval_seconds)
        || config.checkpoint_stall_seconds <= config.checkpoint_interval_seconds
    {
        return Err(
            "the checkpoint interval must be 1 to 3600 seconds, and the stall threshold longer \
             than the interval"
                .into(),
        );
    }
    let kid = &config.checkpoint_key_id;
    if kid == mandate_kid || kid == &config.evidence_key_id || kid == &config.credential_key_id {
        return Err(format!(
            "the checkpoint key {kid} must be a separate key from the mandate, evidence and \
             credential keys"
        ));
    }
    let signer = sources.evidence_signer(HsmRole::Checkpoint, &config.checkpoint_keys_dir, kid)?;
    let checkpoint = sources
        .public_key(HsmRole::Checkpoint, &config.checkpoint_keys_dir, kid)
        .await?;
    let evidence = sources
        .public_key(
            HsmRole::Evidence,
            &config.evidence_keys_dir,
            &config.evidence_key_id,
        )
        .await?;
    if checkpoint.bytes == evidence.bytes {
        return Err(format!(
            "the checkpoint key {kid} has the same key material as the evidence key"
        ));
    }
    Ok(signer)
}

/// The checkpoint writer over the evidence store, signing with its own key.
fn build_checkpointer(
    config: &DataplaneConfig,
    evidence: &Arc<EvidenceBackend>,
    signer: Box<dyn EvidenceSigner>,
    clock: &ClockBackend,
    authorize: &AuthorizeConfig,
) -> Checkpointer<EvidenceBackend> {
    Checkpointer::new(
        Arc::clone(evidence),
        signer,
        Box::new(clock.clone()),
        &authorize.tenant_id,
        authorize.partition_id,
        CheckpointPolicy {
            every: std::time::Duration::from_secs(config.checkpoint_interval_seconds),
            stall_after: std::time::Duration::from_secs(config.checkpoint_stall_seconds),
            max_clock_error_ms: authorize.max_clock_error_ms,
            ..CheckpointPolicy::default()
        },
        Instant::now(),
    )
}

/// The mandate configuration's signing key id, read before the rest.
#[derive(Deserialize)]
struct SigningKid {
    signing_kid: String,
}

/// The HSM for the roles `config.hsm` lists, or key files only. The
/// mandate key id comes from the mandate configuration.
fn open_key_sources(config: &DataplaneConfig, insecure_dev: bool) -> Result<KeySources, String> {
    let Some(hsm) = &config.hsm else {
        return Ok(KeySources::files());
    };
    let mandate: SigningKid = {
        let text = std::fs::read_to_string(&config.mandate_config)
            .map_err(|e| format!("mandate config {}: {e}", config.mandate_config.display()))?;
        serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .and_then(|v| serde_json::from_value(v).ok())
            .ok_or("mandate config: no signing_kid")?
    };
    let kid_of = |role| match role {
        HsmRole::Mandate => mandate.signing_kid.clone(),
        HsmRole::Evidence => config.evidence_key_id.clone(),
        HsmRole::Checkpoint => config.checkpoint_key_id.clone(),
        HsmRole::Credential => config.credential_key_id.clone(),
    };
    let sources = KeySources::open(hsm, kid_of, insecure_dev)?;
    let roles: Vec<_> = hsm.roles.iter().map(|r| r.as_str()).collect();
    tracing::info!(roles = ?roles, "signing keys in the HSM");
    Ok(sources)
}

/// The gateway's forwarder: every provider the registry forwards to needs
/// an endpoint; timeouts stay below the credential lifetime.
fn build_forwarder(
    config: &DataplaneConfig,
    tools: &ToolRegistry,
) -> Result<crate::forward::HttpForwarder, String> {
    let ttl_ms = u64::try_from(kavach_ports::MAX_CREDENTIAL_TTL_SECONDS).unwrap_or(15) * 1000;
    let (connect, total) = (
        config.provider_connect_timeout_ms,
        config.provider_timeout_ms,
    );
    if connect == 0 || total == 0 || connect > total || total >= ttl_ms {
        return Err(format!(
            "provider timeouts must satisfy 0 < connect <= total < {ttl_ms} ms (the credential \
             lifetime); got connect {connect} ms, total {total} ms"
        ));
    }
    let file: ProvidersFile = read_json(&config.providers, "providers")?;
    let mut endpoints = std::collections::BTreeMap::new();
    for entry in &file.providers {
        let (url, plain) = crate::forward::messages_url(&entry.endpoint)
            .map_err(|e| format!("provider {}: {e}", entry.audience))?;
        if plain {
            tracing::warn!(
                "provider {} uses plain HTTP; credentials travel unencrypted \
                 at the transport layer. Use HTTPS (or mTLS) outside an isolated backend network.",
                entry.audience
            );
        }
        endpoints.insert(entry.audience.clone(), url);
    }
    if let Some(missing) = tools
        .providers()
        .into_iter()
        .find(|p| !endpoints.contains_key(*p))
    {
        return Err(format!(
            "the tool registry forwards to {missing}, which has no endpoint in --providers"
        ));
    }
    let extra_roots = match &config.provider_ca {
        Some(path) => {
            std::fs::read(path).map_err(|e| format!("provider CA {}: {e}", path.display()))?
        }
        None => Vec::new(),
    };
    crate::forward::HttpForwarder::new(
        endpoints,
        std::time::Duration::from_millis(connect),
        std::time::Duration::from_millis(total),
        &extra_roots,
    )
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
    sources: &KeySources,
) -> Result<Broker, String> {
    let kid = &config.credential_key_id;
    if kid == mandate_kid || kid == &config.evidence_key_id {
        return Err(format!(
            "the credential key {kid} must be a separate key from the mandate and evidence keys"
        ));
    }
    let keys = sources.keys(HsmRole::Credential, &config.credential_keys_dir);
    let credential = keys
        .public_key(kid)
        .await
        .map_err(|e| format!("credential signing key: {e}"))?;
    let others = [
        sources
            .public_key(HsmRole::Mandate, &config.mandate_keys_dir, mandate_kid)
            .await,
        sources
            .public_key(
                HsmRole::Evidence,
                &config.evidence_keys_dir,
                &config.evidence_key_id,
            )
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
        tracing::warn!(
            "--insecure-dev declares the system clock synced for agent \
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

/// One verify-only public key (hex).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerificationKeyFile {
    kid: String,
    /// Hex Ed25519 public key.
    public_key: String,
}

/// The previous mandate keys of a rotation: verify-only, each distinct from
/// the signing key (by id and by key material) and from each other.
fn previous_mandate_keys(
    file: &MandateConfigFile,
    current: &PublicKey,
    insecure_dev: bool,
) -> Result<Vec<PublicKey>, String> {
    let mut seen = BTreeSet::new();
    file.previous_mandate_keys
        .iter()
        .map(|k| {
            refuse_dev_key("previous mandate", &k.kid, insecure_dev)?;
            let bytes: [u8; 32] = hex::decode(k.public_key.trim())
                .ok()
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| {
                    format!(
                        "previous mandate key {}: public_key must be 32 bytes hex",
                        k.kid
                    )
                })?;
            if k.kid == file.signing_kid || bytes == current.bytes {
                return Err(format!(
                    "previous mandate key {} is the current signing key; list only earlier keys",
                    k.kid
                ));
            }
            if !seen.insert(k.kid.clone()) {
                return Err(format!("previous mandate key {} is listed twice", k.kid));
            }
            Ok(PublicKey {
                kid: k.kid.clone(),
                algorithm: KeyAlgorithm::Ed25519,
                bytes,
            })
        })
        .collect()
}

async fn load_mandate_config(
    path: &Path,
    keys: &SigningKeys,
    insecure_dev: bool,
) -> Result<(MandateConfig, BTreeSet<(String, String)>), String> {
    let file: MandateConfigFile = read_json(path, "mandate config")?;
    let mandate_public = keys
        .public_key(&file.signing_kid)
        .await
        .map_err(|e| format!("mandate signing key: {e}"))?;
    let previous = previous_mandate_keys(&file, &mandate_public, insecure_dev)?;
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
        mandate_keys: KeySet::new(std::iter::once(mandate_public).chain(previous)),
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
    body: Result<StrictJson<AuthorizeBody>, StrictJsonRejection>,
) -> Result<Json<AuthorizeResponse>, Refusal> {
    let dp = dataplane(&state)?;
    let agent = authenticate_agent(dp, &headers)?;
    // Malformed or unknown fields: 400, nothing recorded (H5b item 5).
    // The parser's message can quote values, so it is not echoed.
    let StrictJson(body) = body.map_err(|_| {
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
/// `POST /v1/tools/{tool}`: the gateway (H5b step 8). Decides and records,
/// then (allow, first call only) resolves, obtains a credential, forwards
/// once and records the outcome. The reply is an allowlist of fields.
pub async fn tool_call(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(tool): axum::extract::Path<String>,
    headers: HeaderMap,
    body: Result<StrictJson<ToolRequest>, StrictJsonRejection>,
) -> Result<Json<GatewayReply>, Refusal> {
    let dp = dataplane(&state)?;
    let agent = authenticate_agent(dp, &headers)?;
    let metrics = state.metrics();
    let malformed = |message: String| {
        metrics.observe_gateway_malformed();
        refuse(StatusCode::BAD_REQUEST, message)
    };
    // The parser's message can quote values, so it is not echoed.
    let StrictJson(request) = body.map_err(|_| {
        malformed(
            "malformed body: expected JSON with exactly mandate_id, request_id, params".into(),
        )
    })?;
    let deps = GatewayDeps {
        core: &dp.core,
        resolver: &dp.resolver,
        broker: &dp.broker,
        forwarder: &dp.forwarder,
        observer: metrics,
    };
    // Log the registry's tool name, never the caller's path text.
    let tool_label = dp
        .core
        .tools()
        .tool(&tool)
        .map_or("unknown", |t| t.name.as_str())
        .to_string();
    let result = execute(&deps, &agent, &tool, request).await;
    match &result {
        Ok(reply) => {
            tracing::info!(
            tool = %tool_label,
            agent = %agent.agent_id,
            request_id = %reply.request_id,
            record_id = reply.record_id.as_deref().unwrap_or("-"),
            decision = ?reply.decision,
            outcome = reply.outcome.map_or("none", kavach_ports::agent_evidence::Outcome::as_str),
            outcome_reason = reply.outcome_reason.as_deref().unwrap_or("-"),
            replayed = reply.replayed,
            outcome_recorded = reply.outcome_recorded,
            "gateway call"
            );
        }
        Err(error) => {
            tracing::info!(
                tool = %tool_label,
                agent = %agent.agent_id,
                refused = error_kind(error),
                "gateway call refused"
            );
        }
    }
    match result {
        Ok(reply) => Ok(Json(reply)),
        Err(GatewayError::Invalid(message)) => Err(malformed(message)),
        Err(GatewayError::NotForwardable(message)) => {
            Err(refuse(StatusCode::NOT_IMPLEMENTED, message))
        }
        Err(GatewayError::Conflict) => Err(refuse(
            StatusCode::CONFLICT,
            "request_id was already used for different content",
        )),
        Err(GatewayError::InFlight) => Err(refuse(
            StatusCode::CONFLICT,
            "in_flight_or_unknown: an earlier identical call has no final outcome; it is never \
             run again",
        )),
    }
}

/// A fixed label for a refusal (never its message, which may quote input).
fn error_kind(error: &GatewayError) -> &'static str {
    match error {
        GatewayError::Invalid(_) => "malformed",
        GatewayError::NotForwardable(_) => "not_forwardable",
        GatewayError::Conflict => "conflict",
        GatewayError::InFlight => "in_flight",
    }
}

/// Agent request bodies are small: the envelope plus a few parameters.
pub const AGENT_BODY_LIMIT: usize = 16 * 1024;

pub fn agent_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/authorize", post(authorize))
        .route("/v1/tools/{tool}", post(tool_call))
        .layer(DefaultBodyLimit::max(AGENT_BODY_LIMIT))
        .route(
            "/health",
            axum::routing::get(|| async { Json(serde_json::json!({ "status": "ok" })) }),
        )
        .route_layer(axum::middleware::from_fn(crate::correlation::correlate))
        .with_state(state)
}

/// Router for the system-of-record listener (backend network only).
pub fn sor_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/sor/events", post(sor_event))
        .route_layer(axum::middleware::from_fn(crate::correlation::correlate))
        .layer(DefaultBodyLimit::max(SOR_BODY_LIMIT))
        .with_state(state)
}

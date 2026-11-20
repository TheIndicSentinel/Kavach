use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Mutex;

use chrono::{Duration, Utc};
use kavach_auth::KavachAuthorizer;
use kavach_domain::{EvaluateRequest, EvaluateResponse, ModelRecord};
use kavach_evaluate::{EvaluateConfig, EvaluatePath, EvaluateService};
use kavach_evidence::MemoryChain;
use kavach_keys::{verify_pack_file, TrustedSigners};
use kavach_policy::{LoadedPolicyPack, PackLoader};
use kavach_storage::{
    check_startup_pack, AdminBackend, AuditInsert, BatchJobBackend, BootstrapOutcome,
    ChangeRequestBackend, EvidenceBackend, IncidentBackend, MemoryAdminStore, MemoryChangeStore,
    MemoryRetentionStore, RetentionBackend, RetentionStoreError, RoleBackend, RuntimePointers,
    StartupPackCheck, StoragePool,
};

use crate::config::{AccessControlKind, ApiConfig, EvidenceStoreKind};
use crate::error::ApiError;
use crate::governance::RuntimeResponse;
use crate::metrics::Metrics;
use crate::registry::registry_roots;

/// Runtime-selected storage for D17 challenge state. The challenge itself
/// retains only state/nonce digests and is one-use; production deployments
/// use PostgreSQL while development memory stores remain process-local.
#[derive(Clone)]
pub enum StepUpChallengeBackend {
    Memory(kavach_storage::MemoryStepUpChallengeStore),
    Postgres(kavach_storage::PostgresStepUpChallengeStore),
}

/// Runtime-selected D17 encrypted review-snapshot store.
#[derive(Clone)]
pub enum ReviewSnapshotBackend {
    Memory(std::sync::Arc<kavach_storage::MemoryReviewSnapshotStore>),
    Postgres(kavach_storage::PostgresReviewSnapshotStore),
}

/// Runtime-selected store for completed D17 human-review decisions.
#[derive(Clone)]
pub enum ReviewApprovalBackend {
    Memory(std::sync::Arc<kavach_storage::MemoryReviewApprovalStore>),
    Postgres(kavach_storage::PostgresReviewApprovalStore),
}

impl kavach_ports::ReviewApprovalStore for ReviewApprovalBackend {
    async fn insert(
        &self,
        record: kavach_ports::ReviewApprovalRecord,
    ) -> Result<(), kavach_ports::PortError> {
        match self {
            Self::Memory(store) => store.insert(record).await,
            Self::Postgres(store) => store.insert(record).await,
        }
    }

    async fn release(
        &self,
        tenant_id: &str,
        approval_id: &str,
        execution_id: &str,
        action_hash: &str,
        now: chrono::DateTime<Utc>,
    ) -> Result<Option<kavach_ports::ReviewReleaseRecord>, kavach_ports::PortError> {
        match self {
            Self::Memory(store) => {
                store
                    .release(tenant_id, approval_id, execution_id, action_hash, now)
                    .await
            }
            Self::Postgres(store) => {
                store
                    .release(tenant_id, approval_id, execution_id, action_hash, now)
                    .await
            }
        }
    }
}

impl kavach_ports::ReviewSnapshotStore for ReviewSnapshotBackend {
    async fn insert(
        &self,
        snapshot: kavach_ports::EncryptedReviewSnapshot,
        now: chrono::DateTime<Utc>,
    ) -> Result<(), kavach_ports::PortError> {
        match self {
            Self::Memory(store) => store.insert(snapshot, now).await,
            Self::Postgres(store) => store.insert(snapshot, now).await,
        }
    }

    async fn get_live(
        &self,
        tenant_id: &str,
        record_id: &str,
        now: chrono::DateTime<Utc>,
    ) -> Result<Option<kavach_ports::EncryptedReviewSnapshot>, kavach_ports::PortError> {
        match self {
            Self::Memory(store) => store.get_live(tenant_id, record_id, now).await,
            Self::Postgres(store) => store.get_live(tenant_id, record_id, now).await,
        }
    }

    async fn purge_expired(
        &self,
        now: chrono::DateTime<Utc>,
    ) -> Result<u64, kavach_ports::PortError> {
        match self {
            Self::Memory(store) => store.purge_expired(now).await,
            Self::Postgres(store) => store.purge_expired(now).await,
        }
    }
}

impl kavach_ports::StepUpChallengeStore for StepUpChallengeBackend {
    async fn insert(
        &self,
        state: kavach_ports::StepUpChallengeState,
    ) -> Result<(), kavach_ports::PortError> {
        match self {
            Self::Memory(store) => store.insert(state).await,
            Self::Postgres(store) => store.insert(state).await,
        }
    }

    async fn get_live(
        &self,
        tenant_id: &str,
        state_hash: &str,
        now: chrono::DateTime<Utc>,
    ) -> Result<Option<kavach_ports::StepUpChallengeState>, kavach_ports::PortError> {
        match self {
            Self::Memory(store) => store.get_live(tenant_id, state_hash, now).await,
            Self::Postgres(store) => store.get_live(tenant_id, state_hash, now).await,
        }
    }

    async fn consume(
        &self,
        tenant_id: &str,
        state_hash: &str,
        now: chrono::DateTime<Utc>,
    ) -> Result<Option<kavach_ports::StepUpChallengeState>, kavach_ports::PortError> {
        match self {
            Self::Memory(store) => store.consume(tenant_id, state_hash, now).await,
            Self::Postgres(store) => store.consume(tenant_id, state_hash, now).await,
        }
    }

    async fn purge_expired(
        &self,
        now: chrono::DateTime<Utc>,
    ) -> Result<u64, kavach_ports::PortError> {
        match self {
            Self::Memory(store) => store.purge_expired(now).await,
            Self::Postgres(store) => store.purge_expired(now).await,
        }
    }
}

pub struct AppState {
    service: Mutex<EvaluateService<EvidenceBackend, IncidentBackend>>,
    hmac_secret: Option<String>,
    access_control: Option<KavachAuthorizer>,
    metrics: Metrics,
    runtime: Mutex<RuntimeResponse>,
    runtime_pointer_version: AtomicI64,
    runtime_reload_lock: tokio::sync::Mutex<()>,
    packs_dir: PathBuf,
    models_dir: PathBuf,
    admin: AdminBackend,
    retention: RetentionBackend,
    incidents: IncidentBackend,
    batch_jobs: BatchJobBackend,
    /// When set, every pack load requires a valid signature from these keys.
    pack_signers: Option<TrustedSigners>,
    oidc: Option<std::sync::Arc<crate::oidc::OidcVerifier>>,
    insecure_dev: bool,
    require_hardening: bool,
    relaxations: std::collections::BTreeSet<crate::relaxations::Relaxation>,
    mtls_principal_san: Option<crate::mtls::MtlsSanKind>,
    hmac_nonces: crate::hmac_auth::HmacNonceBackend,
    changes: ChangeRequestBackend,
    change_ttl: Duration,
    /// Operator role bindings and the principals directory (ADR-019).
    roles: RoleBackend,
    /// When each person's directory row was last written by this process.
    seen: crate::auth::SeenThrottle,
    /// The tenant this process serves (ADR-014 Tier 1).
    tenant_id: String,
    /// `--access-review-stale-days` (ADR-019 §9).
    access_review_stale_days: u32,
    /// Serializes change decisions in this process, so commit order and
    /// live-swap order agree.
    governance_lock: tokio::sync::Mutex<()>,
    dataplane: Option<crate::dataplane::Dataplane>,
    /// One-use D17 step-up challenge state (PRD D17).
    step_up_challenges: StepUpChallengeBackend,
    /// Active and decrypt-only previous keys for encrypted D17 review projections.
    review_snapshot_key: Option<crate::review_snapshot_key::ReviewSnapshotKey>,
    /// Runtime-selected persistence for encrypted D17 review projections.
    review_snapshot_store: ReviewSnapshotBackend,
    /// Runtime-selected persistence for exact-action D17 approvals.
    review_approval_store: ReviewApprovalBackend,
    /// Postgres lease ownership; disabled for existing single-instance mode.
    ha_fence: crate::ha_lease::HaFence,
    lease_store: Option<kavach_storage::PostgresActiveLeaseStore>,
    /// Console sign-in (ADR-018); `None` unless configured.
    console_login: Option<std::sync::Arc<crate::console_login::ConsoleLogin>>,
}

/// One of the process-wide locks of [`AppState`], for refusing requests once
/// it is poisoned. A poisoned lock means a thread panicked while holding it,
/// so what it guards may be half-updated (an evaluate can stop midway through
/// its idempotency cache and evidence chain): it is never used again, and
/// every request that needs it is refused with a 500 until the process is
/// restarted. Not a 503: retrying cannot succeed, and an `Unavailable` from
/// a change's preparation would close the change request as failed.
struct GuardedLock {
    name: &'static str,
    alerted: AtomicBool,
}

impl GuardedLock {
    const fn new(name: &'static str) -> Self {
        Self {
            name,
            alerted: AtomicBool::new(false),
        }
    }

    /// The refusal for a request that found this lock poisoned. The alert is
    /// logged once per process and names only the lock, never the request.
    fn poisoned(&self) -> ApiError {
        if !self.alerted.swap(true, Ordering::Relaxed) {
            tracing::error!(
                lock = self.name,
                "ALERT kavach-api: the {} lock is poisoned (a thread panicked while holding it); \
                 requests that need it are refused until the process is restarted",
                self.name
            );
        }
        ApiError::Internal(format!("{} lock poisoned", self.name))
    }
}

static EVALUATE_LOCK: GuardedLock = GuardedLock::new("evaluate");
static RUNTIME_LOCK: GuardedLock = GuardedLock::new("runtime");

#[path = "state_changes.rs"]
mod changes;
pub use changes::{ChangeProposal, DEFAULT_CHANGE_TTL_HOURS};

impl AppState {
    pub async fn from_config(config: &ApiConfig) -> Result<Self, ApiError> {
        let pack = PackLoader::load_from_path(config.pack_path())
            .map_err(|e| ApiError::Internal(format!("load pack: {e}")))?;
        pack.verify_pin(config.pack_sha256.as_deref())
            .map_err(|e| ApiError::Internal(format!("pack pin: {e}")))?;
        let pack_signers = match &config.pack_signers {
            Some(path) => Some(
                TrustedSigners::from_file(path)
                    .map_err(|e| ApiError::Internal(format!("pack signers: {e}")))?,
            ),
            None => None,
        };
        if let Some(signers) = &pack_signers {
            verify_signed(&pack, config.pack_path(), signers)
                .map_err(|e| ApiError::Internal(format!("startup pack signature: {e}")))?;
        }
        let (yaml_model, model_sha256) =
            read_model_file(config.model_path(), pack_signers.as_ref())?;

        let (evidence, incidents, batch_jobs, admin, retention, changes, roles, pool) =
            storage_backends(config).await?;
        let (step_up_challenges, review_snapshot_store, review_approval_store) =
            select_review_stores(pool.as_ref());
        let review_snapshot_key = load_review_snapshot_key(config)?;
        bootstrap_superadmins(&roles, &config.roles).await?;
        let dataplane = build_dataplane(config, pool.as_ref()).await?;

        if matches!(config.evidence_store, EvidenceStoreKind::Postgres { .. }) {
            enforce_startup_pointer(&admin, config, pack.digest.as_deref(), &model_sha256).await?;
        }
        let model = startup_model(&admin, config, yaml_model, &model_sha256).await?;
        let pointer_version = admin
            .get_runtime_pointers()
            .await
            .map_err(|e| ApiError::Internal(format!("load runtime pointers: {e}")))?
            .map_or(0, |p| p.version);

        let (packs_dir, models_dir) = registry_roots(config.pack_path(), config.model_path());
        let runtime = RuntimeResponse {
            pack_id: pack.pack.id.clone(),
            pack_version: pack.pack.version.clone(),
            model_id: model.model_id.clone(),
            model_version: model.version.clone(),
            sector: model.sector.clone(),
            governance_mode: model.governance_mode,
            pack_path: config.pack_path().display().to_string(),
            model_path: config.model_path().display().to_string(),
            pack_sha256: pack.digest.clone(),
            pointer_version,
            model_sha256: Some(model_sha256),
            model_pack_mismatch: model.pack_id != pack.pack.id,
        };

        let metrics = start_metrics(
            runtime.model_pack_mismatch,
            dataplane.as_ref(),
            &config.roles.tenant_id,
        )?;
        let service = EvaluateService::new(
            pack,
            model,
            evidence,
            incidents.clone(),
            EvaluateConfig::default(),
        )
        .map_err(|e| ApiError::Internal(format!("evaluate service: {e}")))?;

        let oidc = load_oidc(config).await?;

        let access_control = match &config.access_control {
            AccessControlKind::None => None,
            AccessControlKind::Cedar {
                policy_path,
                entities_path,
            } => Some(
                KavachAuthorizer::from_files(policy_path, entities_path)
                    .map_err(|e| ApiError::Internal(format!("cedar access control: {e}")))?,
            ),
        };

        let relaxations = report_relaxations(config, dataplane.as_ref(), &metrics);
        let lease_store = pool.as_ref().map(StoragePool::active_lease_store);
        Ok(Self {
            relaxations,
            service: Mutex::new(service),
            hmac_secret: config.hmac_secret.clone(),
            access_control,
            metrics,
            runtime: Mutex::new(runtime),
            runtime_pointer_version: AtomicI64::new(pointer_version),
            runtime_reload_lock: tokio::sync::Mutex::new(()),
            packs_dir,
            models_dir,
            admin,
            retention,
            incidents,
            batch_jobs,
            pack_signers,
            oidc,
            insecure_dev: config.insecure_dev,
            require_hardening: config.require_hardening,
            mtls_principal_san: config.mtls_principal_san,
            hmac_nonces: crate::hmac_auth::HmacNonceBackend::from_pool(pool.as_ref()),
            roles,
            seen: crate::auth::SeenThrottle::default(),
            tenant_id: config.roles.tenant_id.clone(),
            access_review_stale_days: config.roles.access_review_stale_days,
            changes,
            change_ttl: Duration::seconds(
                i64::try_from(config.change_ttl_seconds).unwrap_or(i64::MAX),
            ),
            governance_lock: tokio::sync::Mutex::new(()),
            dataplane,
            step_up_challenges,
            review_snapshot_key,
            review_snapshot_store,
            review_approval_store,
            ha_fence: crate::ha_lease::HaFence::default(),
            lease_store,
            console_login: None,
        })
    }

    pub async fn from_paths_for_tests(
        pack_path: &std::path::Path,
        model_path: &std::path::Path,
        hmac_secret: Option<String>,
    ) -> Result<Self, ApiError> {
        let config = ApiConfig {
            pack_path: pack_path.to_path_buf(),
            model_path: model_path.to_path_buf(),
            hmac_secret,
            evidence_store: EvidenceStoreKind::Memory,
            access_control: AccessControlKind::None,
            tls: None,
            pack_sha256: None,
            bootstrap_pack: false,
            bootstrap_model: false,
            pack_signers: None,
            oidc: None,
            insecure_dev: true,
            mtls_principal_san: None,
            change_ttl_seconds: DEFAULT_CHANGE_TTL_HOURS * 3600,
            roles: crate::config::RolesConfig::default(),
            migration_database_url: None,
            database_tls: kavach_storage::DatabaseTls::default(),
            database_pool_size: kavach_storage::DEFAULT_POOL_SIZE,
            dataplane: None,
            require_hardening: false,
            review_snapshot_key_file: None,
            review_snapshot_key_id: crate::config::DEFAULT_REVIEW_SNAPSHOT_KEY_ID.into(),
            review_snapshot_previous_keys: Vec::new(),
        };
        Self::from_config(&config).await
    }

    /// Turns console sign-in on (ADR-018). Off unless this is called.
    #[must_use]
    pub fn with_console_login(
        mut self,
        login: std::sync::Arc<crate::console_login::ConsoleLogin>,
    ) -> Self {
        self.console_login = Some(login);
        self
    }

    #[must_use]
    pub fn with_ha_fence(mut self, fence: crate::ha_lease::HaFence) -> Self {
        self.ha_fence = fence;
        self
    }

    #[must_use]
    pub fn ha_fence(&self) -> &crate::ha_lease::HaFence {
        &self.ha_fence
    }

    #[must_use]
    pub fn active_lease_store(&self) -> Option<kavach_storage::PostgresActiveLeaseStore> {
        // The configured persistence adapters share the same database pool;
        // retain only the narrow lease API for HA lifecycle work.
        self.lease_store.clone()
    }

    pub fn console_login(&self) -> Option<&std::sync::Arc<crate::console_login::ConsoleLogin>> {
        self.console_login.as_ref()
    }

    /// The runtime challenge store used by the D17 Keycloak adapter.
    pub fn step_up_challenges(&self) -> &StepUpChallengeBackend {
        &self.step_up_challenges
    }

    /// Active D17 encryption key with configured decrypt-only previous keys, if configured.
    pub fn review_snapshot_key(&self) -> Option<&crate::review_snapshot_key::ReviewSnapshotKey> {
        self.review_snapshot_key.as_ref()
    }

    /// Runtime snapshot store: memory for development, Postgres when configured.
    pub fn review_snapshot_store(&self) -> &ReviewSnapshotBackend {
        &self.review_snapshot_store
    }

    /// The configured one-use D17 approval persistence adapter.
    pub fn review_approval_store(&self) -> &ReviewApprovalBackend {
        &self.review_approval_store
    }

    pub fn hmac_secret(&self) -> Option<&str> {
        self.hmac_secret.as_deref()
    }

    pub fn access_control(&self) -> Option<&KavachAuthorizer> {
        self.access_control.as_ref()
    }

    pub fn oidc(&self) -> Option<&std::sync::Arc<crate::oidc::OidcVerifier>> {
        self.oidc.as_ref()
    }

    pub fn insecure_dev(&self) -> bool {
        self.insecure_dev
    }

    /// The process was started with `--require-hardening`.
    pub fn require_hardening(&self) -> bool {
        self.require_hardening
    }

    /// The relaxations this process runs with (empty in production).
    pub fn relaxations(&self) -> &std::collections::BTreeSet<crate::relaxations::Relaxation> {
        &self.relaxations
    }

    pub fn mtls_principal_san(&self) -> Option<crate::mtls::MtlsSanKind> {
        self.mtls_principal_san
    }

    pub fn hmac_nonces(&self) -> &crate::hmac_auth::HmacNonceBackend {
        &self.hmac_nonces
    }

    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    /// The live runtime view. Fails (500) once the runtime lock is poisoned,
    /// rather than panicking every request that reads it.
    pub fn runtime(&self) -> Result<RuntimeResponse, ApiError> {
        self.runtime
            .lock()
            .map(|runtime| runtime.clone())
            .map_err(|_| RUNTIME_LOCK.poisoned())
    }

    /// Converge to another process's committed runtime pointer before an
    /// evaluation. The assets are validated before the live evaluator swaps;
    /// failed or backward convergence refuses the request.
    pub async fn ensure_runtime_pointer_current(&self) -> Result<(), ApiError> {
        let _reload = self.runtime_reload_lock.lock().await;
        let pointers = self
            .admin
            .get_runtime_pointers()
            .await
            .map_err(|_| ApiError::Unavailable("runtime pointer is unavailable".into()))?;
        let local_version = self.runtime_pointer_version.load(Ordering::Acquire);
        let stored_version = pointers.as_ref().map_or(0, |p| p.version);
        if stored_version == local_version {
            return Ok(());
        }
        if stored_version < local_version {
            return Err(ApiError::Unavailable(
                "stored runtime pointer moved backwards; operator recovery is required".into(),
            ));
        }
        let pointers = pointers.ok_or_else(|| {
            ApiError::Unavailable(
                "runtime pointer disappeared; operator recovery is required".into(),
            )
        })?;
        self.reload_runtime_pointer(pointers).await
    }

    async fn reload_runtime_pointer(&self, pointers: RuntimePointers) -> Result<(), ApiError> {
        let pack_path = std::path::Path::new(&pointers.pack_path);
        let pack = PackLoader::load_from_path(pack_path).map_err(|_| {
            ApiError::Unavailable("committed runtime pack could not be loaded".into())
        })?;
        pack.verify_pin(pointers.pack_sha256.as_deref())
            .map_err(|_| ApiError::Unavailable("committed runtime pack digest mismatch".into()))?;
        if let Some(signers) = &self.pack_signers {
            verify_signed(&pack, pack_path, signers).map_err(|_| {
                ApiError::Unavailable("committed runtime pack signature is invalid".into())
            })?;
        }

        let model_path = std::path::Path::new(&pointers.model_path);
        let (mut model, model_digest) = read_model_file(model_path, self.pack_signers.as_ref())
            .map_err(|_| {
                ApiError::Unavailable("committed runtime model could not be loaded".into())
            })?;
        if pointers.model_sha256.as_deref() != Some(model_digest.as_str()) {
            return Err(ApiError::Unavailable(
                "committed runtime model digest mismatch".into(),
            ));
        }
        let governed = self
            .admin
            .get_model_state(self.tenant_id(), &model.model_id)
            .await
            .map_err(|_| ApiError::Unavailable("governed model state is unavailable".into()))?
            .ok_or_else(|| {
                ApiError::Unavailable("committed runtime model has no governed state".into())
            })?;
        model.status = governed.status;
        model.governance_mode = governed.governance_mode;
        precheck_model(&model).map_err(|_| {
            ApiError::Unavailable("committed runtime model failed validation".into())
        })?;

        let latest_version = self
            .admin
            .get_runtime_pointers()
            .await
            .map_err(|_| ApiError::Unavailable("runtime pointer is unavailable".into()))?
            .map_or(0, |latest| latest.version);
        if latest_version != pointers.version {
            return Err(ApiError::Unavailable(
                "runtime pointer changed during reload; retry after convergence".into(),
            ));
        }

        let runtime = RuntimeResponse {
            pack_id: pack.pack.id.clone(),
            pack_version: pack.pack.version.clone(),
            model_id: model.model_id.clone(),
            model_version: model.version.clone(),
            sector: model.sector.clone(),
            governance_mode: model.governance_mode,
            pack_path: pointers.pack_path,
            model_path: pointers.model_path,
            pack_sha256: pack.digest.clone(),
            pointer_version: pointers.version,
            model_sha256: Some(model_digest),
            model_pack_mismatch: model.pack_id != pack.pack.id,
        };
        self.swap_live(pack, model, &runtime)
    }

    pub fn packs_dir(&self) -> &std::path::Path {
        &self.packs_dir
    }

    pub fn models_dir(&self) -> &std::path::Path {
        &self.models_dir
    }

    pub fn admin(&self) -> &AdminBackend {
        &self.admin
    }

    pub fn retention(&self) -> &RetentionBackend {
        &self.retention
    }

    pub fn incidents(&self) -> &IncidentBackend {
        &self.incidents
    }

    pub fn batch_jobs(&self) -> &BatchJobBackend {
        &self.batch_jobs
    }

    pub fn dataplane(&self) -> Option<&crate::dataplane::Dataplane> {
        self.dataplane.as_ref()
    }

    pub fn changes(&self) -> &ChangeRequestBackend {
        &self.changes
    }

    pub fn roles(&self) -> &RoleBackend {
        &self.roles
    }

    pub(crate) fn seen(&self) -> &crate::auth::SeenThrottle {
        &self.seen
    }

    /// The tenant this process serves (ADR-014 Tier 1).
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    /// Days after which the access review marks a person stale.
    pub fn access_review_stale_days(&self) -> u32 {
        self.access_review_stale_days
    }

    pub async fn model_states(&self) -> Result<Vec<kavach_storage::ModelState>, ApiError> {
        self.admin
            .list_model_states(self.tenant_id())
            .await
            .map_err(|e| ApiError::Internal(format!("model states: {e}")))
    }

    /// One decision event by evidence id, as export views show it: a
    /// tombstoned event comes back redacted (and says so).
    pub async fn decision_event(
        &self,
        evidence_id: &str,
    ) -> Result<Option<(kavach_domain::DecisionEvent, bool)>, ApiError> {
        // Never hold the evaluate lock across an await.
        let source = {
            let service = self.service.lock().map_err(|_| EVALUATE_LOCK.poisoned())?;
            match service.evidence_store() {
                EvidenceBackend::Memory(chain) => Err(chain
                    .events()
                    .iter()
                    .find(|e| e.evidence_id == evidence_id)
                    .cloned()),
                EvidenceBackend::Postgres(store) => Ok(store.clone()),
            }
        };
        let found = match source {
            Err(in_memory) => in_memory,
            Ok(postgres) => postgres
                .event(evidence_id)
                .await
                .map_err(|e| ApiError::Internal(format!("evidence read: {e}")))?,
        };
        self.tombstone_view(found).await
    }

    async fn tombstone_view(
        &self,
        event: Option<kavach_domain::DecisionEvent>,
    ) -> Result<Option<(kavach_domain::DecisionEvent, bool)>, ApiError> {
        let Some(event) = event else { return Ok(None) };
        let tombstoned = self
            .retention
            .is_tombstoned(&event.evidence_id)
            .await
            .map_err(|e| ApiError::Internal(format!("tombstone check: {e}")))?;
        Ok(Some(if tombstoned {
            (kavach_evidence::redact_tombstoned_event(&event), true)
        } else {
            (event, false)
        }))
    }

    fn memory_events_snapshot(
        &self,
    ) -> Result<Option<Vec<kavach_domain::DecisionEvent>>, ApiError> {
        let service = self.service.lock().map_err(|_| EVALUATE_LOCK.poisoned())?;
        Ok(service.evidence_store().memory_events())
    }

    pub fn evaluate(
        &self,
        transport: &str,
        request: &EvaluateRequest,
    ) -> Result<EvaluateResponse, ApiError> {
        let started = std::time::Instant::now();
        let result = self.evaluate_inner(request);
        let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);

        match &result {
            Ok(response) => {
                self.metrics
                    .observe_success(transport, response.returned_decision, latency_ms);
            }
            Err(err) if err.is_client_error() => {
                self.metrics.observe_client_error(transport);
            }
            Err(_) => self.metrics.observe_server_error(transport),
        }

        result
    }

    /// Swaps the live evaluator and runtime view. Called only after the change
    /// has been persisted and audited; `precheck_model` has already validated
    /// the only fallible step of the reload.
    fn swap_live(
        &self,
        loaded_pack: LoadedPolicyPack,
        model: ModelRecord,
        runtime: &RuntimeResponse,
    ) -> Result<(), ApiError> {
        let runtime = &RuntimeResponse {
            model_pack_mismatch: model.pack_id != loaded_pack.pack.id,
            ..runtime.clone()
        };
        self.metrics
            .set_model_pack_mismatch(runtime.model_pack_mismatch);
        self.service
            .lock()
            .map_err(|_| EVALUATE_LOCK.poisoned())?
            .reload_pack_and_model(loaded_pack, model)
            .map_err(|e| ApiError::Internal(format!("reload evaluate service: {e}")))?;
        *self.runtime.lock().map_err(|_| RUNTIME_LOCK.poisoned())? = runtime.clone();
        self.runtime_pointer_version
            .store(runtime.pointer_version, Ordering::Release);
        Ok(())
    }

    /// When trusted pack signers are configured, refuses a pack without a valid
    /// signature; the refusal is written to the admin audit log.
    async fn check_pack_signature(
        &self,
        loaded: &LoadedPolicyPack,
        path: &std::path::Path,
        operation: &str,
        principals: (&str, &str),
    ) -> Result<(), ApiError> {
        let Some(signers) = &self.pack_signers else {
            return Ok(());
        };
        let Err(err) = verify_signed(loaded, path, signers) else {
            return Ok(());
        };
        self.admin
            .append_audit(AuditInsert {
                tenant_id: self.tenant_id.clone(),
                acting_as_superadmin: false,
                action: format!("{operation}_refused"),
                resource_type: "policy_pack".into(),
                resource_id: loaded.pack.id.clone(),
                actor_principal: principals.0.into(),
                approver_principal: principals.1.into(),
                payload: serde_json::json!({
                    "reason": "pack_signature_invalid",
                    "detail": err.to_string(),
                    "pack_sha256": loaded.digest,
                }),
            })
            .await
            .map_err(|e| ApiError::Internal(format!("audit append: {e}")))?;
        Err(ApiError::Conflict(format!("pack_signature_invalid: {err}")))
    }

    /// Refuses to reload a pack whose file changed since it was pinned; the
    /// refusal is written to the admin audit log. A missing pin (pointers
    /// recorded before digests existed) is accepted and audited.
    async fn check_pack_pin(
        &self,
        loaded: &LoadedPolicyPack,
        expected: Option<&str>,
        operation: &str,
        principals: (&str, &str),
    ) -> Result<(), ApiError> {
        let Some(expected) = expected else {
            // Pointers recorded before digests existed: allowed, but audited
            // so the fail-open reload is visible to governance reviewers.
            self.admin
                .append_audit(AuditInsert {
                    tenant_id: self.tenant_id.clone(),
                    acting_as_superadmin: false,
                    action: format!("{operation}_unpinned"),
                    resource_type: "policy_pack".into(),
                    resource_id: loaded.pack.id.clone(),
                    actor_principal: principals.0.into(),
                    approver_principal: principals.1.into(),
                    payload: serde_json::json!({
                        "reason": "digest_unpinned",
                        "actual_sha256": loaded.digest,
                    }),
                })
                .await
                .map_err(|e| ApiError::Internal(format!("audit append: {e}")))?;
            return Ok(());
        };
        let Err(err) = loaded.verify_pin(Some(expected)) else {
            return Ok(());
        };
        self.admin
            .append_audit(AuditInsert {
                tenant_id: self.tenant_id.clone(),
                acting_as_superadmin: false,
                action: format!("{operation}_refused"),
                resource_type: "policy_pack".into(),
                resource_id: loaded.pack.id.clone(),
                actor_principal: principals.0.into(),
                approver_principal: principals.1.into(),
                payload: serde_json::json!({
                    "reason": "pack_digest_mismatch",
                    "expected_sha256": expected,
                    "actual_sha256": loaded.digest,
                }),
            })
            .await
            .map_err(|e| ApiError::Internal(format!("audit append: {e}")))?;
        Err(ApiError::Conflict(format!("pack_digest_mismatch: {err}")))
    }

    fn evaluate_inner(&self, request: &EvaluateRequest) -> Result<EvaluateResponse, ApiError> {
        let mut service = self.service.lock().map_err(|_| EVALUATE_LOCK.poisoned())?;
        let result = service
            .evaluate(EvaluatePath::Sync, request, Utc::now())
            .map_err(ApiError::Evaluate)?;
        if let Some(err) = &result.incident_write_error {
            // Never let an infra failure become invisible (ADR-001 §5).
            self.metrics.observe_incident_write_failure();
            tracing::warn!(
                "ALERT kavach-api: incident not persisted (correlation_id={}, model_id={}): {err}",
                request.correlation_id,
                request.model_id
            );
        }
        Ok(result.response)
    }
}

fn load_review_snapshot_key(
    config: &ApiConfig,
) -> Result<Option<crate::review_snapshot_key::ReviewSnapshotKey>, ApiError> {
    let Some(path) = config.review_snapshot_key_file.as_deref() else {
        if config.review_snapshot_previous_keys.is_empty() {
            return Ok(None);
        }
        return Err(ApiError::Internal(
            "previous review snapshot keys require an active key file".into(),
        ));
    };
    let mut active = crate::review_snapshot_key::ReviewSnapshotKey::from_file(
        path,
        &config.review_snapshot_key_id,
    )
    .map_err(ApiError::Internal)?;
    for (key_id, path) in &config.review_snapshot_previous_keys {
        let previous = crate::review_snapshot_key::ReviewSnapshotKey::from_file(path, key_id)
            .map_err(ApiError::Internal)?;
        active.add_previous(previous).map_err(ApiError::Internal)?;
    }
    Ok(Some(active))
}

fn select_review_stores(
    pool: Option<&StoragePool>,
) -> (
    StepUpChallengeBackend,
    ReviewSnapshotBackend,
    ReviewApprovalBackend,
) {
    let challenges = pool.map_or_else(
        || StepUpChallengeBackend::Memory(kavach_storage::MemoryStepUpChallengeStore::default()),
        |pool| StepUpChallengeBackend::Postgres(pool.step_up_challenge_store()),
    );
    let snapshots = pool.map_or_else(
        || {
            ReviewSnapshotBackend::Memory(std::sync::Arc::new(
                kavach_storage::MemoryReviewSnapshotStore::default(),
            ))
        },
        |pool| ReviewSnapshotBackend::Postgres(pool.review_snapshot_store()),
    );
    let approvals = pool.map_or_else(
        || {
            ReviewApprovalBackend::Memory(std::sync::Arc::new(
                kavach_storage::MemoryReviewApprovalStore::default(),
            ))
        },
        |pool| ReviewApprovalBackend::Postgres(pool.review_approval_store()),
    );
    (challenges, snapshots, approvals)
}

/// The metrics registry, with the evidence checkpoint writer reporting into
/// it when the agent surfaces are on.
fn start_metrics(
    model_pack_mismatch: bool,
    dataplane: Option<&crate::dataplane::Dataplane>,
    tenant_id: &str,
) -> Result<Metrics, ApiError> {
    let metrics =
        Metrics::new(tenant_id).map_err(|e| ApiError::Internal(format!("metrics: {e}")))?;
    metrics.set_model_pack_mismatch(model_pack_mismatch);
    crate::checkpoints::start(dataplane, &metrics);
    crate::revocation_evidence::start(dataplane, &metrics);
    crate::outcome_reconciler::start(dataplane, &metrics);
    crate::agent_state_evidence::start(dataplane, &metrics);
    Ok(metrics)
}

/// The OIDC verifier of the operator API, with its key refresher running.
async fn load_oidc(
    config: &ApiConfig,
) -> Result<Option<std::sync::Arc<crate::oidc::OidcVerifier>>, ApiError> {
    let Some(oidc) = &config.oidc else {
        return Ok(None);
    };
    let verifier = crate::oidc::OidcVerifier::load(oidc.clone())
        .await
        .map_err(|e| ApiError::Internal(format!("oidc: {e}")))?;
    verifier.spawn_refresher();
    Ok(Some(verifier))
}

/// What this process runs relaxed (the configuration's, and the agent
/// surfaces' own), published as metrics.
fn report_relaxations(
    config: &ApiConfig,
    dataplane: Option<&crate::dataplane::Dataplane>,
    metrics: &Metrics,
) -> std::collections::BTreeSet<crate::relaxations::Relaxation> {
    let mut relaxations = crate::relaxations::of_config(config);
    if let Some(dp) = dataplane {
        relaxations.extend(dp.relaxations().iter().copied());
    }
    metrics.set_relaxations(&relaxations);
    relaxations
}

/// The agent surfaces, when configured (ADR-007).
async fn build_dataplane(
    config: &ApiConfig,
    pool: Option<&StoragePool>,
) -> Result<Option<crate::dataplane::Dataplane>, ApiError> {
    let Some(dp) = &config.dataplane else {
        return Ok(None);
    };
    crate::dataplane::Dataplane::build(
        dp,
        pool,
        config.insecure_dev,
        config.oidc.as_ref().map(|o| o.audience.as_str()),
        config.pack_signers.as_deref(),
    )
    .await
    .map(Some)
    .map_err(|e| ApiError::Internal(format!("agent surfaces: {e}")))
}

type Backends = (
    EvidenceBackend,
    IncidentBackend,
    BatchJobBackend,
    AdminBackend,
    RetentionBackend,
    ChangeRequestBackend,
    RoleBackend,
    Option<StoragePool>,
);

async fn storage_backends(config: &ApiConfig) -> Result<Backends, ApiError> {
    Ok(match &config.evidence_store {
        EvidenceStoreKind::Memory => {
            let admin = std::sync::Arc::new(MemoryAdminStore::default());
            let retention = std::sync::Arc::new(MemoryRetentionStore::default());
            // One role store: approved grants and revokes write where the
            // per-request lookups read.
            let roles = std::sync::Arc::new(kavach_storage::MemoryRoleStore::default());
            (
                EvidenceBackend::Memory(MemoryChain::new()),
                IncidentBackend::memory_for_tenant(&config.roles.tenant_id),
                BatchJobBackend::memory_for_tenant(&config.roles.tenant_id),
                AdminBackend::Memory(admin.clone(), config.roles.tenant_id.clone()),
                RetentionBackend::Memory(retention.clone(), config.roles.tenant_id.clone()),
                ChangeRequestBackend::Memory(std::sync::Arc::new(MemoryChangeStore::new(
                    admin.clone(),
                    retention,
                    roles.clone(),
                ))),
                RoleBackend::memory_with(roles, admin),
                None,
            )
        }
        EvidenceStoreKind::Postgres { database_url } => {
            let pool = StoragePool::connect_with_roles_sized(
                database_url,
                config.migration_database_url.as_deref(),
                &config.database_tls,
                config.database_pool_size,
            )
            .await
            .map_err(|e| ApiError::Internal(format!("postgres storage: {e}")))?;
            (
                EvidenceBackend::Postgres(pool.evidence_store_for_tenant(&config.roles.tenant_id)),
                IncidentBackend::Postgres(pool.incident_store_for_tenant(&config.roles.tenant_id)),
                BatchJobBackend::Postgres(pool.batch_job_store_for_tenant(&config.roles.tenant_id)),
                AdminBackend::Postgres(pool.admin_store_for_tenant(&config.roles.tenant_id)),
                RetentionBackend::Postgres(
                    pool.retention_store_for_tenant(&config.roles.tenant_id),
                ),
                ChangeRequestBackend::Postgres(pool.change_request_store()),
                RoleBackend::Postgres(pool.role_store()),
                Some(pool),
            )
        }
    })
}

/// ADR-019 §5: writes the first two superadmins, before anything is served,
/// unless the tenant already has one. The log names no person; the audit
/// rows do.
async fn bootstrap_superadmins(
    roles: &RoleBackend,
    config: &crate::config::RolesConfig,
) -> Result<(), ApiError> {
    if config.bootstrap_superadmins.is_empty() {
        return Ok(());
    }
    let outcome = roles
        .bootstrap_superadmins(&config.tenant_id, &config.bootstrap_superadmins, Utc::now())
        .await
        .map_err(|e| ApiError::Internal(format!("bootstrap superadmins: {e}")))?;
    match outcome {
        BootstrapOutcome::Written(bindings) => tracing::warn!(
            bindings = bindings.len(),
            "superadmin bootstrap applied (ADR-019 §5): two superadmin bindings written and \
             audited as bootstrap_superadmin; remove --bootstrap-superadmins"
        ),
        BootstrapOutcome::AlreadyPresent => tracing::warn!(
            "--bootstrap-superadmins ignored: the tenant already has an active superadmin; \
             remove the setting"
        ),
    }
    Ok(())
}

/// Reads a model file: the record and the SHA-256 of its bytes. With trusted
/// signers, the file must carry a model signature from a `model` signer.
fn read_model_file(
    path: &std::path::Path,
    signers: Option<&TrustedSigners>,
) -> Result<(ModelRecord, String), ApiError> {
    let bytes = std::fs::read(path)
        .map_err(|e| ApiError::Internal(format!("read model {}: {e}", path.display())))?;
    let model: ModelRecord = serde_yaml::from_slice(&bytes)
        .map_err(|e| ApiError::Internal(format!("parse model {}: {e}", path.display())))?;
    let digest = kavach_policy::pack_digest(&bytes);
    if let Some(signers) = signers {
        kavach_keys::verify_model_file(
            path,
            kavach_keys::ModelIdentity {
                model_id: &model.model_id,
                model_version: &model.version,
                model_sha256: &digest,
            },
            signers,
        )
        .map_err(|e| ApiError::Conflict(format!("model_signature_invalid: {e}")))?;
    }
    Ok((model, digest))
}

/// The effective model at startup: governed state in Postgres (ADR-010);
/// in memory mode the YAML, registered as the governed state.
async fn startup_model(
    admin: &AdminBackend,
    config: &ApiConfig,
    yaml: ModelRecord,
    digest: &str,
) -> Result<ModelRecord, ApiError> {
    if !matches!(config.evidence_store, EvidenceStoreKind::Postgres { .. }) {
        if config.bootstrap_model {
            return Err(ApiError::Internal(
                "--bootstrap-model applies to the Postgres evidence store only".into(),
            ));
        }
        admin
            .insert_model_state_if_absent(
                &config.roles.tenant_id,
                kavach_storage::ModelState {
                    model_id: yaml.model_id.clone(),
                    status: yaml.status,
                    governance_mode: yaml.governance_mode,
                    updated_at: Utc::now(),
                    updated_by: STARTUP_PRINCIPAL.into(),
                    approved_by: STARTUP_PRINCIPAL.into(),
                },
            )
            .await
            .map_err(|e| ApiError::Internal(format!("model state: {e}")))?;
        return Ok(yaml);
    }
    let governed = kavach_storage::govern_model(
        admin,
        &config.roles.tenant_id,
        config.model_path(),
        yaml,
        digest,
        kavach_storage::ModelStartupRole::Api {
            bootstrap_model: config.bootstrap_model,
        },
    )
    .await
    .map_err(|e| ApiError::Internal(format!("startup model refused: {e}")))?;
    if let Some(note) = &governed.yaml_divergence {
        tracing::warn!("{note}");
    }
    Ok(governed.model)
}

fn map_retention_error(error: RetentionStoreError) -> ApiError {
    match error {
        RetentionStoreError::NotFound(id) => ApiError::NotFound(id),
        RetentionStoreError::AlreadyTombstoned(id) => {
            ApiError::BadRequest(format!("evidence already tombstoned: {id}"))
        }
        RetentionStoreError::Io(message) => ApiError::Internal(message),
    }
}

/// Validates the parts of a pack/model reload that can fail, so the live swap
/// after persistence cannot fail on them.
fn precheck_model(model: &ModelRecord) -> Result<(), ApiError> {
    kavach_evaluate::compile_input_validator(&model.input_schema)
        .map_err(|e| ApiError::BadRequest(format!("model input schema: {e}")))?;
    // Supplier controls run at proposal and approval, not first at evaluate
    // time (where a vendor draft in enforce mode would fail every request).
    kavach_evaluate::validate_supplier_controls(model)
        .map_err(|e| ApiError::BadRequest(format!("supplier controls: {e}")))
}

const STARTUP_PRINCIPAL: &str = "system:startup";

fn startup_audit(
    tenant_id: &str,
    action: &str,
    resource_id: &str,
    payload: serde_json::Value,
) -> AuditInsert {
    AuditInsert {
        tenant_id: tenant_id.into(),
        acting_as_superadmin: false,
        action: action.into(),
        resource_type: "policy_pack".into(),
        resource_id: resource_id.into(),
        actor_principal: STARTUP_PRINCIPAL.into(),
        approver_principal: STARTUP_PRINCIPAL.into(),
        payload,
    }
}

/// Postgres mode: the governed runtime pointer is the startup source of truth.
/// First start records the startup pack as the baseline; later starts refuse a
/// different path or different bytes unless `--bootstrap-pack` is set, which is
/// audited.
async fn enforce_startup_pointer(
    admin: &AdminBackend,
    config: &ApiConfig,
    digest: Option<&str>,
    model_sha256: &str,
) -> Result<(), ApiError> {
    let path = config.pack_path();
    let path_str = path.display().to_string();
    let pointers = admin
        .get_runtime_pointers()
        .await
        .map_err(|e| ApiError::Internal(format!("load runtime pointers: {e}")))?;
    let audit = |insert: AuditInsert| async move {
        admin
            .append_audit(insert)
            .await
            .map(|_| ())
            .map_err(|e| ApiError::Internal(format!("audit append: {e}")))
    };

    match check_startup_pack(pointers.as_ref(), path, digest) {
        Ok(StartupPackCheck::Matches { pinned: true }) => Ok(()),
        Ok(StartupPackCheck::Matches { pinned: false }) => {
            audit(startup_audit(
                &config.roles.tenant_id,
                "startup_unpinned",
                &path_str,
                serde_json::json!({ "pack_path": path_str, "actual_sha256": digest }),
            ))
            .await
        }
        Ok(StartupPackCheck::NoPointer) => {
            let inserted = admin
                .insert_pointers_if_absent(RuntimePointers {
                    pack_path: path_str.clone(),
                    model_path: config.model_path().display().to_string(),
                    previous_pack_path: None,
                    pack_sha256: digest.map(ToString::to_string),
                    previous_pack_sha256: None,
                    model_sha256: Some(model_sha256.to_string()),
                    updated_at: Utc::now(),
                    updated_by: STARTUP_PRINCIPAL.into(),
                    approved_by: STARTUP_PRINCIPAL.into(),
                    version: 0,
                })
                .await
                .map_err(|e| ApiError::Internal(format!("persist runtime pointers: {e}")))?;
            if !inserted {
                // Another process recorded the baseline first; check against it.
                let pointers = admin
                    .get_runtime_pointers()
                    .await
                    .map_err(|e| ApiError::Internal(format!("load runtime pointers: {e}")))?;
                check_startup_pack(pointers.as_ref(), path, digest)
                    .map_err(|e| ApiError::Internal(format!("startup pack refused: {e}")))?;
                return Ok(());
            }
            audit(startup_audit(
                &config.roles.tenant_id,
                "startup_baseline_recorded",
                &path_str,
                serde_json::json!({ "pack_path": path_str, "pack_sha256": digest }),
            ))
            .await
        }
        Err(err) if config.bootstrap_pack => {
            tracing::warn!("--bootstrap-pack override: {err}");
            audit(startup_audit(
                &config.roles.tenant_id,
                "startup_bootstrap_override",
                &path_str,
                serde_json::json!({
                    "reason": err.to_string(),
                    "pack_path": path_str,
                    "pack_sha256": digest,
                    "active_pack_path": pointers.as_ref().map(|p| p.pack_path.clone()),
                    "active_pack_sha256": pointers.as_ref().and_then(|p| p.pack_sha256.clone()),
                }),
            ))
            .await
        }
        Err(err) => Err(ApiError::Internal(format!("startup pack refused: {err}"))),
    }
}

/// Verifies `<path>.sig` for a loaded pack against the trusted signers.
fn verify_signed(
    loaded: &LoadedPolicyPack,
    path: &std::path::Path,
    signers: &TrustedSigners,
) -> Result<(), kavach_ports::PortError> {
    let digest = loaded
        .digest
        .as_deref()
        .ok_or_else(|| kavach_ports::PortError::invalid("pack has no file digest"))?;
    verify_pack_file(path, digest, signers)
}

/// Roadmap 1.5: a panic while one of the [`AppState`] locks is held poisons
/// it. Every request that needs that lock is then refused (never decided,
/// never panicking), and requests that don't need it are still served.
#[cfg(test)]
mod poisoned_lock_tests {
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use chrono::Utc;
    use http_body_util::BodyExt;
    use kavach_storage::RuntimePointers;
    use serde_json::{json, Value};
    use tower::ServiceExt;

    use super::AppState;
    use crate::error::ApiError;

    async fn state() -> Arc<AppState> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        Arc::new(
            AppState::from_paths_for_tests(
                &root.join("packs/finance/v0.yaml"),
                &root.join("models/finance/credit-underwriting-v1.yaml"),
                None,
            )
            .await
            .expect("state"),
        )
    }

    #[tokio::test]
    async fn evaluate_refuses_when_stored_runtime_pointer_is_newer() {
        let state = state().await;
        state
            .admin()
            .set_runtime_pointers(RuntimePointers {
                pack_path: "packs/finance/v1.yaml".into(),
                model_path: "models/finance/model.yaml".into(),
                previous_pack_path: None,
                pack_sha256: Some("sha256:new".into()),
                previous_pack_sha256: None,
                model_sha256: Some("sha256:model".into()),
                updated_at: Utc::now(),
                updated_by: "test-proposer".into(),
                approved_by: "test-approver".into(),
                version: 0,
            })
            .await
            .unwrap();

        let (status, body) = send(
            &state,
            "POST",
            "/v1/evaluate",
            None,
            Some(json!({"correlation_id":"drift-test"})),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        assert_eq!(body["code"], "unavailable", "{body}");
        let (ready_status, ready_body) = send(&state, "GET", "/ready", None, None).await;
        assert_eq!(
            ready_status,
            StatusCode::SERVICE_UNAVAILABLE,
            "{ready_body}"
        );
        let (health_status, _) = send(&state, "GET", "/health", None, None).await;
        assert_eq!(health_status, StatusCode::OK);
        assert!(matches!(
            state.ensure_runtime_pointer_current().await,
            Err(ApiError::Unavailable(_))
        ));
    }

    /// Panics in another thread while holding `lock`, which poisons it.
    fn poison<T: Send>(lock: &Mutex<T>) {
        std::thread::scope(|scope| {
            let holder = scope.spawn(|| {
                let _held = lock.lock().unwrap();
                panic!("test: panicking while holding the lock");
            });
            assert!(holder.join().is_err());
        });
        assert!(lock.is_poisoned());
    }

    async fn send(
        state: &Arc<AppState>,
        method: &str,
        uri: &str,
        principal: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut request = Request::builder().method(method).uri(uri);
        if let Some(principal) = principal {
            request = request.header("x-kavach-principal", principal);
        }
        let body = match body {
            Some(value) => {
                request = request.header("content-type", "application/json");
                Body::from(value.to_string())
            }
            None => Body::empty(),
        };
        let response = crate::http::router(Arc::clone(state))
            .oneshot(request.body(body).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    fn clean_request() -> kavach_domain::EvaluateRequest {
        let golden: Value =
            serde_json::from_str(include_str!("../../../golden/finance/v0/credit_clean.json"))
                .unwrap();
        let mut request: kavach_domain::EvaluateRequest =
            serde_json::from_value(golden["request"].clone()).unwrap();
        let now = chrono::Utc::now();
        request.decision_time = now;
        request.consent.as_mut().expect("consent").timestamp = now;
        request
    }

    fn evaluate_body() -> Value {
        serde_json::to_value(clean_request()).unwrap()
    }

    #[tokio::test]
    async fn a_poisoned_evaluate_lock_refuses_every_decision_and_the_rest_is_served() {
        let state = state().await;
        poison(&state.service);

        for _ in 0..2 {
            let (status, body) =
                send(&state, "POST", "/v1/evaluate", None, Some(evaluate_body())).await;
            assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
            assert_eq!(body["code"], "internal", "{body}");
            assert!(body.get("returned_decision").is_none(), "{body}");
            assert!(!body.to_string().contains("poison"), "{body}");
        }
        // gRPC evaluates through the same call.
        assert!(matches!(
            state.evaluate("grpc", &clean_request()),
            Err(ApiError::Internal(_))
        ));
        // A change that reads the live model is refused too.
        let (status, body) = send(
            &state,
            "POST",
            "/v1/change-requests",
            Some("admin-1"),
            Some(json!({
                "kind": "update_model",
                "params": { "model_id": "credit-underwriting-v1", "governance_mode": "enforce" },
            })),
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");

        // Nothing was decided: no decision event was recorded.
        let recorded = state
            .service
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .evidence_store()
            .memory_events()
            .map(|events| events.len());
        assert_eq!(recorded, Some(0));
        // The server is still up for what does not need the lock.
        assert_eq!(
            send(&state, "GET", "/health", None, None).await.0,
            StatusCode::OK
        );
        assert_eq!(
            send(&state, "GET", "/v1/runtime", None, None).await.0,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn a_poisoned_runtime_lock_refuses_its_readers_and_leaves_changes_pending() {
        let state = state().await;
        let (status, proposed) = send(
            &state,
            "POST",
            "/v1/change-requests",
            Some("admin-1"),
            Some(json!({
                "kind": "update_model",
                "params": { "model_id": "credit-underwriting-v1", "governance_mode": "enforce" },
            })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{proposed}");
        poison(&state.runtime);

        assert!(matches!(state.runtime(), Err(ApiError::Internal(_))));
        for uri in ["/v1/runtime", "/v1/runtime", "/v1/packs", "/v1/models"] {
            let (status, body) = send(&state, "GET", uri, None, None).await;
            assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{uri}: {body}");
            assert_eq!(body["code"], "internal", "{uri}: {body}");
        }
        // The approval is refused and the request is not closed as failed:
        // it can be approved once the process is restarted.
        let id = proposed["id"].as_str().expect("id");
        let (status, body) = send(
            &state,
            "POST",
            &format!("/v1/change-requests/{id}/approve"),
            Some("admin-2"),
            Some(json!({ "change_digest": proposed["change_digest"] })),
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
        let (_, stored) = send(
            &state,
            "GET",
            &format!("/v1/change-requests/{id}"),
            Some("admin-1"),
            None,
        )
        .await;
        assert_eq!(stored["status"], "pending", "{stored}");

        // Decisions do not need the runtime lock and are still made.
        let (status, body) =
            send(&state, "POST", "/v1/evaluate", None, Some(evaluate_body())).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["returned_decision"], "PASS");
    }
}

#[cfg(test)]
mod step_up_backend_tests {
    use chrono::{Duration, Utc};
    use kavach_ports::{
        ReviewApprovalRecord, ReviewApprovalStore, ReviewDecision, StepUpChallengeState,
        StepUpChallengeStore,
    };

    use super::*;

    #[tokio::test]
    async fn app_state_exposes_one_use_memory_challenge_storage() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let app = AppState::from_paths_for_tests(
            &root.join("packs/finance/v0.yaml"),
            &root.join("models/finance/credit-underwriting-v1.yaml"),
            None,
        )
        .await
        .expect("state");
        let now = Utc::now();
        let challenge = StepUpChallengeState {
            challenge_id: "state-value".into(),
            state_hash: format!("sha256:{}", "a".repeat(64)),
            nonce_hash: format!("sha256:{}", "b".repeat(64)),
            tenant_id: "tenant-a".into(),
            principal_key: "oidc:https://idp.example#reviewer".into(),
            action_hash: format!("sha256-action-v1:{}", "c".repeat(64)),
            issued_at: now - Duration::seconds(1),
            expires_at: now + Duration::minutes(5),
        };

        let store = app.step_up_challenges();
        store.insert(challenge.clone()).await.unwrap();
        assert_eq!(
            store
                .get_live(&challenge.tenant_id, &challenge.state_hash, now)
                .await
                .unwrap(),
            Some(challenge.clone())
        );
        assert_eq!(
            store
                .consume(&challenge.tenant_id, &challenge.state_hash, now)
                .await
                .unwrap(),
            Some(challenge.clone())
        );
        assert!(store
            .consume(&challenge.tenant_id, &challenge.state_hash, now)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn app_state_exposes_exact_action_memory_approval_storage() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let app = AppState::from_paths_for_tests(
            &root.join("packs/finance/v0.yaml"),
            &root.join("models/finance/credit-underwriting-v1.yaml"),
            None,
        )
        .await
        .expect("state");
        let now = Utc::now();
        let action_hash = format!("sha256-action-v1:{}", "a".repeat(64));
        let record = ReviewApprovalRecord {
            tenant_id: "tenant-a".into(),
            approval_id: "approval-a".into(),
            review_record_id: "adr:tenant-a:0:1".into(),
            execution_id: Some("execution-a".into()),
            action_hash: action_hash.clone(),
            rendered_action: "Approve proposal".into(),
            approver: "oidc:https://idp.example#reviewer".into(),
            step_up_ref: "webauthn:opaque-proof".into(),
            decision: ReviewDecision::Approve,
            single_use_credential_id: Some("credential-a".into()),
            expires: now + Duration::minutes(5),
        };

        let store = app.review_approval_store();
        store.insert(record.clone()).await.expect("insert");
        let release = store
            .release("tenant-a", "approval-a", "execution-a", &action_hash, now)
            .await
            .expect("release")
            .expect("matching approval");
        assert_eq!(release.review_record_id, record.review_record_id);
        assert_eq!(release.execution_id, "execution-a");
        assert_eq!(
            release.single_use_credential_id,
            record.single_use_credential_id.clone().unwrap()
        );
        assert!(store
            .release(
                "tenant-a",
                "approval-a",
                "execution-other",
                &action_hash,
                now
            )
            .await
            .expect("different execution")
            .is_none());
        assert!(store
            .release(
                "tenant-a",
                "approval-a",
                "execution-other",
                &format!("sha256-action-v1:{}", "b".repeat(64)),
                now
            )
            .await
            .expect("mismatched release")
            .is_none());
        assert_eq!(
            store
                .release("tenant-a", "approval-a", "execution-a", &action_hash, now)
                .await
                .expect("idempotent release retry"),
            Some(release)
        );
    }
}

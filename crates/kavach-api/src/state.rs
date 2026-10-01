use std::path::PathBuf;
use std::sync::Mutex;

use chrono::{Duration, Utc};
use kavach_auth::KavachAuthorizer;
use kavach_domain::{EvaluateRequest, EvaluateResponse, ModelRecord};
use kavach_evaluate::{EvaluateConfig, EvaluatePath, EvaluateService};
use kavach_evidence::MemoryChain;
use kavach_keys::{verify_pack_file, TrustedSigners};
use kavach_policy::{LoadedPolicyPack, PackLoader};
use kavach_storage::{
    check_startup_pack, AdminBackend, AuditInsert, BatchJobBackend, ChangeRequestBackend,
    EvidenceBackend, IncidentBackend, MemoryAdminStore, MemoryChangeStore, MemoryRetentionStore,
    RetentionBackend, RetentionStoreError, RuntimePointers, StartupPackCheck, StoragePool,
};

use crate::config::{AccessControlKind, ApiConfig, EvidenceStoreKind};
use crate::error::ApiError;
use crate::governance::RuntimeResponse;
use crate::metrics::Metrics;
use crate::registry::registry_roots;

pub struct AppState {
    service: Mutex<EvaluateService<EvidenceBackend, IncidentBackend>>,
    hmac_secret: Option<String>,
    access_control: Option<KavachAuthorizer>,
    metrics: Metrics,
    runtime: Mutex<RuntimeResponse>,
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
    mtls_principal_san: Option<crate::mtls::MtlsSanKind>,
    nonces: crate::hmac_auth::NonceCache,
    changes: ChangeRequestBackend,
    change_ttl: Duration,
    /// Serializes change decisions in this process, so commit order and
    /// live-swap order agree.
    governance_lock: tokio::sync::Mutex<()>,
    dataplane: Option<crate::dataplane::Dataplane>,
}

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

        let (evidence, incidents, batch_jobs, admin, retention, changes, pool) =
            storage_backends(config).await?;
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

        let metrics = Metrics::new().map_err(|e| ApiError::Internal(format!("metrics: {e}")))?;
        metrics.set_model_pack_mismatch(runtime.model_pack_mismatch);
        let service = EvaluateService::new(
            pack,
            model,
            evidence,
            incidents.clone(),
            EvaluateConfig::default(),
        )
        .map_err(|e| ApiError::Internal(format!("evaluate service: {e}")))?;

        let oidc = match &config.oidc {
            Some(oidc) => {
                let verifier = crate::oidc::OidcVerifier::load(oidc.clone())
                    .await
                    .map_err(|e| ApiError::Internal(format!("oidc: {e}")))?;
                verifier.spawn_refresher();
                Some(verifier)
            }
            None => None,
        };

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

        Ok(Self {
            service: Mutex::new(service),
            hmac_secret: config.hmac_secret.clone(),
            access_control,
            metrics,
            runtime: Mutex::new(runtime),
            packs_dir,
            models_dir,
            admin,
            retention,
            incidents,
            batch_jobs,
            pack_signers,
            oidc,
            insecure_dev: config.insecure_dev,
            mtls_principal_san: config.mtls_principal_san,
            nonces: crate::hmac_auth::NonceCache::default(),
            changes,
            change_ttl: Duration::seconds(
                i64::try_from(config.change_ttl_seconds).unwrap_or(i64::MAX),
            ),
            governance_lock: tokio::sync::Mutex::new(()),
            dataplane,
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
            migration_database_url: None,
            dataplane: None,
        };
        Self::from_config(&config).await
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

    pub fn mtls_principal_san(&self) -> Option<crate::mtls::MtlsSanKind> {
        self.mtls_principal_san
    }

    pub fn nonces(&self) -> &crate::hmac_auth::NonceCache {
        &self.nonces
    }

    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    pub fn runtime(&self) -> RuntimeResponse {
        self.runtime.lock().expect("runtime lock poisoned").clone()
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

    pub async fn model_states(&self) -> Result<Vec<kavach_storage::ModelState>, ApiError> {
        self.admin
            .list_model_states()
            .await
            .map_err(|e| ApiError::Internal(format!("model states: {e}")))
    }

    fn memory_events_snapshot(
        &self,
    ) -> Result<Option<Vec<kavach_domain::DecisionEvent>>, ApiError> {
        let service = self
            .service
            .lock()
            .map_err(|_| ApiError::Internal("evaluate lock poisoned".into()))?;
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
            .map_err(|_| ApiError::Internal("evaluate lock poisoned".into()))?
            .reload_pack_and_model(loaded_pack, model)
            .map_err(|e| ApiError::Internal(format!("reload evaluate service: {e}")))?;
        *self
            .runtime
            .lock()
            .map_err(|_| ApiError::Internal("runtime lock poisoned".into()))? = runtime.clone();
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
        let mut service = self
            .service
            .lock()
            .map_err(|_| ApiError::Internal("evaluate lock poisoned".into()))?;
        let result = service
            .evaluate(EvaluatePath::Sync, request, Utc::now())
            .map_err(ApiError::Evaluate)?;
        if let Some(err) = &result.incident_write_error {
            // Never let an infra failure become invisible (ADR-001 §5).
            self.metrics.observe_incident_write_failure();
            eprintln!(
                "ALERT kavach-api: incident not persisted (correlation_id={}, model_id={}): {err}",
                request.correlation_id, request.model_id
            );
        }
        Ok(result.response)
    }
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
    Option<StoragePool>,
);

async fn storage_backends(config: &ApiConfig) -> Result<Backends, ApiError> {
    Ok(match &config.evidence_store {
        EvidenceStoreKind::Memory => {
            let admin = std::sync::Arc::new(MemoryAdminStore::default());
            let retention = std::sync::Arc::new(MemoryRetentionStore::default());
            (
                EvidenceBackend::Memory(MemoryChain::new()),
                IncidentBackend::memory(),
                BatchJobBackend::memory(),
                AdminBackend::Memory(admin.clone()),
                RetentionBackend::Memory(retention.clone()),
                ChangeRequestBackend::Memory(std::sync::Arc::new(MemoryChangeStore::new(
                    admin, retention,
                ))),
                None,
            )
        }
        EvidenceStoreKind::Postgres { database_url } => {
            let pool = StoragePool::connect_with_roles(
                database_url,
                config.migration_database_url.as_deref(),
            )
            .await
            .map_err(|e| ApiError::Internal(format!("postgres storage: {e}")))?;
            (
                EvidenceBackend::Postgres(pool.evidence_store()),
                IncidentBackend::Postgres(pool.incident_store()),
                BatchJobBackend::Postgres(pool.batch_job_store()),
                AdminBackend::Postgres(pool.admin_store()),
                RetentionBackend::Postgres(pool.retention_store()),
                ChangeRequestBackend::Postgres(pool.change_request_store()),
                Some(pool),
            )
        }
    })
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
            .insert_model_state_if_absent(kavach_storage::ModelState {
                model_id: yaml.model_id.clone(),
                status: yaml.status,
                governance_mode: yaml.governance_mode,
                updated_at: Utc::now(),
                updated_by: STARTUP_PRINCIPAL.into(),
                approved_by: STARTUP_PRINCIPAL.into(),
            })
            .await
            .map_err(|e| ApiError::Internal(format!("model state: {e}")))?;
        return Ok(yaml);
    }
    let governed = kavach_storage::govern_model(
        admin,
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
        eprintln!("WARNING: kavach-api: {note}");
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

fn startup_audit(action: &str, resource_id: &str, payload: serde_json::Value) -> AuditInsert {
    AuditInsert {
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
                "startup_baseline_recorded",
                &path_str,
                serde_json::json!({ "pack_path": path_str, "pack_sha256": digest }),
            ))
            .await
        }
        Err(err) if config.bootstrap_pack => {
            eprintln!("WARNING: kavach-api: --bootstrap-pack override: {err}");
            audit(startup_audit(
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

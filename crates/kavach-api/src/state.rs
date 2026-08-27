use std::path::PathBuf;
use std::sync::Mutex;

use chrono::Utc;
use kavach_auth::KavachAuthorizer;
use kavach_domain::{EvaluateRequest, EvaluateResponse, GovernanceMode, ModelRecord, ModelStatus};
use kavach_evaluate::{EvaluateConfig, EvaluatePath, EvaluateService};
use kavach_evidence::MemoryChain;
use kavach_policy::PackLoader;
use kavach_storage::{
    AdminBackend, AuditInsert, EvidenceBackend, IncidentBackend, RuntimePointers, StoragePool,
};

use crate::auth::DualControlPrincipals;
use crate::config::{AccessControlKind, ApiConfig, EvidenceStoreKind};
use crate::error::ApiError;
use crate::governance::RuntimeResponse;
use crate::metrics::Metrics;
use crate::registry::{model_source_path, pack_source_path, registry_roots};

pub struct AppState {
    service: Mutex<EvaluateService<EvidenceBackend, IncidentBackend>>,
    hmac_secret: Option<String>,
    access_control: Option<KavachAuthorizer>,
    metrics: Metrics,
    runtime: Mutex<RuntimeResponse>,
    packs_dir: PathBuf,
    models_dir: PathBuf,
    admin: AdminBackend,
}

impl AppState {
    pub async fn from_config(config: &ApiConfig) -> Result<Self, ApiError> {
        let pack = PackLoader::load_from_path(config.pack_path())
            .map_err(|e| ApiError::Internal(format!("load pack: {e}")))?;
        let model = load_model_record(config.model_path())?;

        let (evidence, incidents, admin) = match &config.evidence_store {
            EvidenceStoreKind::Memory => (
                EvidenceBackend::Memory(MemoryChain::new()),
                IncidentBackend::Memory(kavach_evaluate::VecIncidentRecorder::default()),
                AdminBackend::memory(),
            ),
            EvidenceStoreKind::Postgres { database_url } => {
                let pool = StoragePool::connect(database_url)
                    .await
                    .map_err(|e| ApiError::Internal(format!("postgres storage: {e}")))?;
                (
                    EvidenceBackend::Postgres(pool.evidence_store()),
                    IncidentBackend::Postgres(pool.incident_recorder()),
                    AdminBackend::Postgres(pool.admin_store()),
                )
            }
        };

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
        };

        let service =
            EvaluateService::new(pack, model, evidence, incidents, EvaluateConfig::default())
                .map_err(|e| ApiError::Internal(format!("evaluate service: {e}")))?;

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
            metrics: Metrics::new().map_err(|e| ApiError::Internal(format!("metrics: {e}")))?,
            runtime: Mutex::new(runtime),
            packs_dir,
            models_dir,
            admin,
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
        };
        Self::from_config(&config).await
    }

    pub fn hmac_secret(&self) -> Option<&str> {
        self.hmac_secret.as_deref()
    }

    pub fn access_control(&self) -> Option<&KavachAuthorizer> {
        self.access_control.as_ref()
    }

    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    pub fn runtime(&self) -> RuntimeResponse {
        self.runtime
            .lock()
            .expect("runtime lock poisoned")
            .clone()
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

    pub async fn activate_pack(
        &self,
        pack_id: &str,
        principals: &DualControlPrincipals,
    ) -> Result<RuntimeResponse, ApiError> {
        let new_pack_path = pack_source_path(&self.packs_dir, pack_id)?;
        let current = self.runtime();
        if current.pack_path == new_pack_path.display().to_string() {
            return Err(ApiError::BadRequest(format!(
                "pack already active: {pack_id}"
            )));
        }

        let loaded_pack = PackLoader::load_from_path(&new_pack_path)
            .map_err(|e| ApiError::Internal(format!("load pack: {e}")))?;
        let model = load_model_record(std::path::Path::new(&current.model_path))?;

        let previous_pack_path = Some(current.pack_path.clone());
        let runtime = RuntimeResponse {
            pack_id: loaded_pack.pack.id.clone(),
            pack_version: loaded_pack.pack.version.clone(),
            model_id: current.model_id,
            model_version: current.model_version,
            sector: current.sector,
            governance_mode: current.governance_mode,
            pack_path: new_pack_path.display().to_string(),
            model_path: current.model_path,
        };

        {
            let mut service = self
                .service
                .lock()
                .map_err(|_| ApiError::Internal("evaluate lock poisoned".into()))?;
            service
                .reload_pack_and_model(loaded_pack, model)
                .map_err(|e| ApiError::Internal(format!("reload evaluate service: {e}")))?;
        }

        *self
            .runtime
            .lock()
            .map_err(|_| ApiError::Internal("runtime lock poisoned".into()))? = runtime.clone();

        self.admin
            .set_runtime_pointers(RuntimePointers {
                pack_path: runtime.pack_path.clone(),
                model_path: runtime.model_path.clone(),
                previous_pack_path: previous_pack_path.clone(),
                updated_at: Utc::now(),
                updated_by: principals.actor.clone(),
                approved_by: principals.approver.clone(),
            })
            .await
            .map_err(|e| ApiError::Internal(format!("persist runtime pointers: {e}")))?;

        self.admin
            .append_audit(AuditInsert {
                action: "activate_pack".into(),
                resource_type: "policy_pack".into(),
                resource_id: pack_id.to_string(),
                actor_principal: principals.actor.clone(),
                approver_principal: principals.approver.clone(),
                payload: serde_json::json!({
                    "pack_path": runtime.pack_path,
                    "previous_pack_path": previous_pack_path,
                }),
            })
            .await
            .map_err(|e| ApiError::Internal(format!("audit append: {e}")))?;

        Ok(runtime)
    }

    pub async fn rollback_pack(
        &self,
        principals: &DualControlPrincipals,
    ) -> Result<RuntimeResponse, ApiError> {
        let pointers = self
            .admin
            .get_runtime_pointers()
            .await
            .map_err(|e| ApiError::Internal(format!("load runtime pointers: {e}")))?;
        let Some(pointers) = pointers else {
            return Err(ApiError::BadRequest(
                "no runtime pointer history to rollback".into(),
            ));
        };
        let Some(previous_pack_path) = pointers.previous_pack_path.clone() else {
            return Err(ApiError::BadRequest(
                "no previous pack path recorded".into(),
            ));
        };

        let loaded_pack = PackLoader::load_from_path(std::path::Path::new(&previous_pack_path))
            .map_err(|e| ApiError::Internal(format!("load pack: {e}")))?;
        let current = self.runtime();
        let model = load_model_record(std::path::Path::new(&current.model_path))?;

        let runtime = RuntimeResponse {
            pack_id: loaded_pack.pack.id.clone(),
            pack_version: loaded_pack.pack.version.clone(),
            model_id: current.model_id,
            model_version: current.model_version,
            sector: current.sector,
            governance_mode: current.governance_mode,
            pack_path: previous_pack_path.clone(),
            model_path: current.model_path,
        };

        {
            let mut service = self
                .service
                .lock()
                .map_err(|_| ApiError::Internal("evaluate lock poisoned".into()))?;
            service
                .reload_pack_and_model(loaded_pack, model)
                .map_err(|e| ApiError::Internal(format!("reload evaluate service: {e}")))?;
        }

        *self
            .runtime
            .lock()
            .map_err(|_| ApiError::Internal("runtime lock poisoned".into()))? = runtime.clone();

        self.admin
            .set_runtime_pointers(RuntimePointers {
                pack_path: runtime.pack_path.clone(),
                model_path: runtime.model_path.clone(),
                previous_pack_path: None,
                updated_at: Utc::now(),
                updated_by: principals.actor.clone(),
                approved_by: principals.approver.clone(),
            })
            .await
            .map_err(|e| ApiError::Internal(format!("persist runtime pointers: {e}")))?;

        self.admin
            .append_audit(AuditInsert {
                action: "rollback_pack".into(),
                resource_type: "policy_pack".into(),
                resource_id: runtime.pack_id.clone(),
                actor_principal: principals.actor.clone(),
                approver_principal: principals.approver.clone(),
                payload: serde_json::json!({
                    "pack_path": runtime.pack_path,
                }),
            })
            .await
            .map_err(|e| ApiError::Internal(format!("audit append: {e}")))?;

        Ok(runtime)
    }

    pub async fn update_model(
        &self,
        model_id: &str,
        status: Option<ModelStatus>,
        governance_mode: Option<GovernanceMode>,
        principals: &DualControlPrincipals,
    ) -> Result<RuntimeResponse, ApiError> {
        let model_path = model_source_path(&self.models_dir, model_id)?;
        let mut model = load_model_record(&model_path)?;
        if let Some(next_status) = status {
            model.status = next_status;
        }
        if let Some(next_mode) = governance_mode {
            model.governance_mode = next_mode;
        }

        let audit_status = format!("{:?}", model.status).to_lowercase();
        let audit_mode = format!("{:?}", model.governance_mode).to_lowercase();

        let current = self.runtime();
        if current.model_id != model_id {
            return Err(ApiError::BadRequest(
                "runtime model differs from requested model_id".into(),
            ));
        }

        let loaded_pack = PackLoader::load_from_path(std::path::Path::new(&current.pack_path))
            .map_err(|e| ApiError::Internal(format!("load pack: {e}")))?;

        let runtime = RuntimeResponse {
            pack_id: current.pack_id,
            pack_version: current.pack_version,
            model_id: model.model_id.clone(),
            model_version: model.version.clone(),
            sector: model.sector.clone(),
            governance_mode: model.governance_mode,
            pack_path: current.pack_path,
            model_path: model_path.display().to_string(),
        };

        {
            let mut service = self
                .service
                .lock()
                .map_err(|_| ApiError::Internal("evaluate lock poisoned".into()))?;
            service
                .reload_pack_and_model(loaded_pack, model)
                .map_err(|e| ApiError::Internal(format!("reload evaluate service: {e}")))?;
        }

        *self
            .runtime
            .lock()
            .map_err(|_| ApiError::Internal("runtime lock poisoned".into()))? = runtime.clone();

        self.admin
            .append_audit(AuditInsert {
                action: "update_model".into(),
                resource_type: "model_record".into(),
                resource_id: model_id.to_string(),
                actor_principal: principals.actor.clone(),
                approver_principal: principals.approver.clone(),
                payload: serde_json::json!({
                    "status": audit_status,
                    "governance_mode": audit_mode,
                    "model_path": runtime.model_path,
                }),
            })
            .await
            .map_err(|e| ApiError::Internal(format!("audit append: {e}")))?;

        Ok(runtime)
    }

    fn evaluate_inner(&self, request: &EvaluateRequest) -> Result<EvaluateResponse, ApiError> {
        let mut service = self
            .service
            .lock()
            .map_err(|_| ApiError::Internal("evaluate lock poisoned".into()))?;
        let result = service
            .evaluate(EvaluatePath::Sync, request, Utc::now())
            .map_err(ApiError::Evaluate)?;
        Ok(result.response)
    }
}

fn load_model_record(path: &std::path::Path) -> Result<ModelRecord, ApiError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| ApiError::Internal(format!("read model {}: {e}", path.display())))?;
    serde_yaml::from_str(&content)
        .map_err(|e| ApiError::Internal(format!("parse model {}: {e}", path.display())))
}

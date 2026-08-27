use std::sync::Mutex;

use chrono::Utc;
use kavach_auth::KavachAuthorizer;
use kavach_domain::{EvaluateRequest, EvaluateResponse, ModelRecord};
use kavach_evaluate::{EvaluateConfig, EvaluatePath, EvaluateService};
use kavach_evidence::MemoryChain;
use kavach_policy::PackLoader;
use kavach_storage::{EvidenceBackend, IncidentBackend, StoragePool};

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
    runtime: RuntimeResponse,
    packs_dir: std::path::PathBuf,
    models_dir: std::path::PathBuf,
}

impl AppState {
    pub async fn from_config(config: &ApiConfig) -> Result<Self, ApiError> {
        let pack = PackLoader::load_from_path(config.pack_path())
            .map_err(|e| ApiError::Internal(format!("load pack: {e}")))?;
        let model = load_model_record(config.model_path())?;

        let (evidence, incidents) = match &config.evidence_store {
            EvidenceStoreKind::Memory => (
                EvidenceBackend::Memory(MemoryChain::new()),
                IncidentBackend::Memory(kavach_evaluate::VecIncidentRecorder::default()),
            ),
            EvidenceStoreKind::Postgres { database_url } => {
                let pool = StoragePool::connect(database_url)
                    .await
                    .map_err(|e| ApiError::Internal(format!("postgres storage: {e}")))?;
                (
                    EvidenceBackend::Postgres(pool.evidence_store()),
                    IncidentBackend::Postgres(pool.incident_recorder()),
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
            runtime,
            packs_dir,
            models_dir,
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

    pub fn runtime(&self) -> &RuntimeResponse {
        &self.runtime
    }

    pub fn packs_dir(&self) -> &std::path::Path {
        &self.packs_dir
    }

    pub fn models_dir(&self) -> &std::path::Path {
        &self.models_dir
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

use std::sync::Mutex;

use chrono::Utc;
use kavach_domain::{EvaluateRequest, EvaluateResponse, ModelRecord};
use kavach_evaluate::{EvaluateConfig, EvaluateService};
use kavach_evidence::MemoryChain;
use kavach_policy::PackLoader;

use crate::config::{ApiConfig, EvidenceStoreKind};
use crate::error::ApiError;
use crate::evidence::{
    EvidenceBackend, IncidentBackend, PostgresEvidenceStore, PostgresIncidentRecorder,
};
use crate::metrics::Metrics;

pub struct AppState {
    service: Mutex<EvaluateService<EvidenceBackend, IncidentBackend>>,
    hmac_secret: Option<String>,
    metrics: Metrics,
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
                let store = PostgresEvidenceStore::connect(database_url)
                    .await
                    .map_err(|e| ApiError::Internal(format!("postgres evidence: {e}")))?;
                let pool = store.pool.clone();
                (
                    EvidenceBackend::Postgres(store),
                    IncidentBackend::Postgres(PostgresIncidentRecorder::new(pool)),
                )
            }
        };

        let service =
            EvaluateService::new(pack, model, evidence, incidents, EvaluateConfig::default())
                .map_err(|e| ApiError::Internal(format!("evaluate service: {e}")))?;

        Ok(Self {
            service: Mutex::new(service),
            hmac_secret: config.hmac_secret.clone(),
            metrics: Metrics::new().map_err(|e| ApiError::Internal(format!("metrics: {e}")))?,
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
            tls: None,
        };
        Self::from_config(&config).await
    }

    pub fn hmac_secret(&self) -> Option<&str> {
        self.hmac_secret.as_deref()
    }

    pub fn metrics(&self) -> &Metrics {
        &self.metrics
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
                    .observe_success(transport, response.returned_decision, latency_ms)
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
            .evaluate(request, Utc::now())
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

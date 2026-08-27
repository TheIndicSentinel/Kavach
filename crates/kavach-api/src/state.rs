use std::sync::Mutex;

use chrono::Utc;
use kavach_domain::{EvaluateRequest, EvaluateResponse, ModelRecord};
use kavach_evaluate::{EvaluateConfig, EvaluateService, VecIncidentRecorder};
use kavach_evidence::MemoryChain;
use kavach_policy::PackLoader;
use std::path::Path;

use crate::error::ApiError;

pub struct AppState {
    service: Mutex<EvaluateService<MemoryChain, VecIncidentRecorder>>,
    hmac_secret: Option<String>,
}

impl AppState {
    pub fn from_paths(
        pack_path: &Path,
        model_path: &Path,
        hmac_secret: Option<String>,
    ) -> Result<Self, ApiError> {
        let pack = PackLoader::load_from_path(pack_path)
            .map_err(|e| ApiError::Internal(format!("load pack: {e}")))?;
        let model = load_model_record(model_path)?;
        let service = EvaluateService::new(
            pack,
            model,
            MemoryChain::new(),
            VecIncidentRecorder::default(),
            EvaluateConfig::default(),
        )
        .map_err(|e| ApiError::Internal(format!("evaluate service: {e}")))?;

        Ok(Self {
            service: Mutex::new(service),
            hmac_secret,
        })
    }

    pub fn hmac_secret(&self) -> Option<&str> {
        self.hmac_secret.as_deref()
    }

    pub fn evaluate(&self, request: &EvaluateRequest) -> Result<EvaluateResponse, ApiError> {
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

fn load_model_record(path: &Path) -> Result<ModelRecord, ApiError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| ApiError::Internal(format!("read model {}: {e}", path.display())))?;
    serde_yaml::from_str(&content)
        .map_err(|e| ApiError::Internal(format!("parse model {}: {e}", path.display())))
}

use std::path::{Path, PathBuf};

use kavach_domain::{ModelRecord, PolicyPack};
use serde::Serialize;

use crate::error::ApiError;

#[derive(Debug, Clone, Serialize)]
pub struct PackSummary {
    pub id: String,
    pub version: String,
    pub sector: String,
    pub jurisdiction: String,
    pub effective_from: chrono::DateTime<chrono::Utc>,
    pub rule_count: usize,
    pub source_path: String,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModelSummary {
    pub model_id: String,
    pub version: String,
    pub sector: String,
    pub status: String,
    pub risk_tier: String,
    pub governance_mode: String,
    pub pack_id: String,
    pub owner: String,
    pub source_path: String,
    pub active: bool,
}

pub fn registry_roots(pack_path: &Path, model_path: &Path) -> (PathBuf, PathBuf) {
    let packs_dir = pack_path
        .parent()
        .and_then(|sector| sector.parent())
        .unwrap_or_else(|| pack_path.parent().unwrap_or(pack_path))
        .to_path_buf();
    let models_dir = model_path
        .parent()
        .and_then(|sector| sector.parent())
        .unwrap_or_else(|| model_path.parent().unwrap_or(model_path))
        .to_path_buf();
    (packs_dir, models_dir)
}

pub fn list_packs(
    packs_dir: &Path,
    active_id: &str,
    active_version: &str,
) -> Result<Vec<PackSummary>, ApiError> {
    let mut packs = Vec::new();
    for entry in walkdir::WalkDir::new(packs_dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "yaml"))
    {
        let path = entry.path();
        let pack = load_policy_pack(path)?;
        packs.push(PackSummary {
            id: pack.id.clone(),
            version: pack.version.clone(),
            sector: pack.sector.clone(),
            jurisdiction: pack.jurisdiction.clone(),
            effective_from: pack.effective_from,
            rule_count: pack.rules.len(),
            source_path: path.display().to_string(),
            active: pack.id == active_id && pack.version == active_version,
        });
    }
    packs.sort_by(|a, b| a.id.cmp(&b.id).then_with(|| a.version.cmp(&b.version)));
    Ok(packs)
}

pub fn pack_source_path(packs_dir: &Path, pack_id: &str) -> Result<PathBuf, ApiError> {
    for entry in walkdir::WalkDir::new(packs_dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "yaml"))
    {
        let pack = load_policy_pack(entry.path())?;
        if pack.id == pack_id {
            return Ok(entry.path().to_path_buf());
        }
    }
    Err(ApiError::NotFound(format!(
        "policy pack not found: {pack_id}"
    )))
}

pub fn model_source_path(models_dir: &Path, model_id: &str) -> Result<PathBuf, ApiError> {
    for entry in walkdir::WalkDir::new(models_dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "yaml"))
    {
        let model = load_model_record(entry.path())?;
        if model.model_id == model_id {
            return Ok(entry.path().to_path_buf());
        }
    }
    Err(ApiError::NotFound(format!(
        "model record not found: {model_id}"
    )))
}

pub fn get_pack_by_id(packs_dir: &Path, pack_id: &str) -> Result<PolicyPack, ApiError> {
    for entry in walkdir::WalkDir::new(packs_dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "yaml"))
    {
        let pack = load_policy_pack(entry.path())?;
        if pack.id == pack_id {
            return Ok(pack);
        }
    }
    Err(ApiError::NotFound(format!(
        "policy pack not found: {pack_id}"
    )))
}

pub fn list_models(
    models_dir: &Path,
    active_model_id: &str,
    active_version: &str,
) -> Result<Vec<ModelSummary>, ApiError> {
    let mut models = Vec::new();
    for entry in walkdir::WalkDir::new(models_dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "yaml"))
    {
        let path = entry.path();
        let model = load_model_record(path)?;
        models.push(ModelSummary {
            model_id: model.model_id.clone(),
            version: model.version.clone(),
            sector: model.sector.clone(),
            status: format!("{:?}", model.status).to_lowercase(),
            risk_tier: format!("{:?}", model.risk_tier).to_lowercase(),
            governance_mode: format!("{:?}", model.governance_mode).to_lowercase(),
            pack_id: model.pack_id.clone(),
            owner: model.owner.clone(),
            source_path: path.display().to_string(),
            active: model.model_id == active_model_id && model.version == active_version,
        });
    }
    models.sort_by(|a, b| a.model_id.cmp(&b.model_id));
    Ok(models)
}

pub fn get_model_by_id(models_dir: &Path, model_id: &str) -> Result<ModelRecord, ApiError> {
    for entry in walkdir::WalkDir::new(models_dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "yaml"))
    {
        let model = load_model_record(entry.path())?;
        if model.model_id == model_id {
            return Ok(model);
        }
    }
    Err(ApiError::NotFound(format!(
        "model record not found: {model_id}"
    )))
}

fn load_policy_pack(path: &Path) -> Result<PolicyPack, ApiError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| ApiError::Internal(format!("read pack {}: {e}", path.display())))?;
    serde_yaml::from_str(&content)
        .map_err(|e| ApiError::Internal(format!("parse pack {}: {e}", path.display())))
}

fn load_model_record(path: &Path) -> Result<ModelRecord, ApiError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| ApiError::Internal(format!("read model {}: {e}", path.display())))?;
    serde_yaml::from_str(&content)
        .map_err(|e| ApiError::Internal(format!("parse model {}: {e}", path.display())))
}

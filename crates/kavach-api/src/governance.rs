use std::sync::Arc;

use axum::{
    extract::{Path, State},
    Json,
};
use serde::Serialize;

use kavach_auth::KavachAction;
use kavach_domain::{GovernanceMode, ModelRecord, PolicyPack};

use crate::auth::{authorize_credentials, Credentials};
use crate::error::ApiError;
use crate::registry::{get_model_by_id, get_pack_by_id, list_models, list_packs};
use crate::state::AppState;

#[derive(Debug, Serialize, Clone)]
pub struct RuntimeResponse {
    pub pack_id: String,
    pub pack_version: String,
    pub model_id: String,
    pub model_version: String,
    pub sector: String,
    pub governance_mode: GovernanceMode,
    pub pack_path: String,
    pub model_path: String,
    /// `sha256:<hex>` of the active pack file (additive field).
    pub pack_sha256: Option<String>,
}

pub async fn runtime(
    State(state): State<Arc<AppState>>,
    credentials: Credentials,
) -> Result<Json<RuntimeResponse>, ApiError> {
    authorize_credentials(&state, &credentials, KavachAction::ReadGovernance)?;
    Ok(Json(state.runtime()))
}

pub async fn list_policy_packs(
    State(state): State<Arc<AppState>>,
    credentials: Credentials,
) -> Result<Json<Vec<crate::registry::PackSummary>>, ApiError> {
    authorize_credentials(&state, &credentials, KavachAction::ReadGovernance)?;
    let runtime = state.runtime();
    let packs = list_packs(state.packs_dir(), &runtime.pack_id, &runtime.pack_version)?;
    Ok(Json(packs))
}

pub async fn get_policy_pack(
    State(state): State<Arc<AppState>>,
    credentials: Credentials,
    Path(pack_id): Path<String>,
) -> Result<Json<PolicyPack>, ApiError> {
    authorize_credentials(&state, &credentials, KavachAction::ReadGovernance)?;
    let pack = get_pack_by_id(state.packs_dir(), &pack_id)?;
    Ok(Json(pack))
}

pub async fn list_model_records(
    State(state): State<Arc<AppState>>,
    credentials: Credentials,
) -> Result<Json<Vec<crate::registry::ModelSummary>>, ApiError> {
    authorize_credentials(&state, &credentials, KavachAction::ReadGovernance)?;
    let runtime = state.runtime();
    let models = list_models(
        state.models_dir(),
        &runtime.model_id,
        &runtime.model_version,
    )?;
    Ok(Json(models))
}

pub async fn get_model_record(
    State(state): State<Arc<AppState>>,
    credentials: Credentials,
    Path(model_id): Path<String>,
) -> Result<Json<ModelRecord>, ApiError> {
    authorize_credentials(&state, &credentials, KavachAction::ReadGovernance)?;
    let model = get_model_by_id(state.models_dir(), &model_id)?;
    Ok(Json(model))
}

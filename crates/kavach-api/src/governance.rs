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
    /// Runtime pointer version this process is serving (0: none recorded).
    pub pointer_version: i64,
    /// `sha256:<hex>` of the active model file.
    pub model_sha256: Option<String>,
    /// The active model was written for a different pack than the one
    /// running (ADR-010 §4); evidence records the pack actually used.
    pub model_pack_mismatch: bool,
}

#[derive(Debug, Serialize)]
pub struct RuntimeView {
    #[serde(flatten)]
    pub runtime: RuntimeResponse,
    /// Version of the stored runtime pointer.
    pub stored_pointer_version: i64,
    /// True when another replica applied a change this process has not
    /// loaded; restart it to converge.
    pub pointer_drift: bool,
}

pub async fn runtime(
    State(state): State<Arc<AppState>>,
    credentials: Credentials,
) -> Result<Json<RuntimeView>, ApiError> {
    authorize_credentials(&state, &credentials, KavachAction::ReadGovernance)?;
    let runtime = state.runtime();
    let stored_pointer_version = state
        .admin()
        .get_runtime_pointers()
        .await
        .map_err(|e| ApiError::Internal(format!("load runtime pointers: {e}")))?
        .map_or(0, |p| p.version);
    Ok(Json(RuntimeView {
        pointer_drift: stored_pointer_version != runtime.pointer_version,
        stored_pointer_version,
        runtime,
    }))
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
        &runtime.model_path,
        &state.model_states().await?,
    )?;
    Ok(Json(models))
}

#[derive(Debug, Serialize)]
pub struct ModelDetail {
    #[serde(flatten)]
    pub model: ModelRecord,
    /// Status and mode shown are governed values when this is true.
    pub governed: bool,
}

pub async fn get_model_record(
    State(state): State<Arc<AppState>>,
    credentials: Credentials,
    Path(model_id): Path<String>,
) -> Result<Json<ModelDetail>, ApiError> {
    authorize_credentials(&state, &credentials, KavachAction::ReadGovernance)?;
    let states = state.model_states().await?;
    let model = get_model_by_id(state.models_dir(), &model_id)?;
    Ok(Json(ModelDetail {
        governed: states.iter().any(|s| s.model_id == model.model_id),
        model: crate::registry::apply_state(model, &states),
    }))
}

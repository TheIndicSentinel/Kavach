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

#[allow(clippy::struct_excessive_bools)] // independent facts in a JSON response, not a state
#[derive(Debug, Serialize)]
pub struct RuntimeView {
    #[serde(flatten)]
    pub runtime: RuntimeResponse,
    /// Version of the stored runtime pointer.
    pub stored_pointer_version: i64,
    /// True when another replica applied a change this process has not
    /// loaded; restart it to converge.
    pub pointer_drift: bool,
    /// Evidence checkpoint health; present when the agent surfaces are on.
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub checkpoints: Option<crate::checkpoints::CheckpointView>,
    /// The development clock (`kavach dev up --at` / `--clock`), when the
    /// stack runs with one: its kind and time. Never present in production.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dev_clock: Option<serde_json::Value>,
    /// Signing roles held in an HSM and whether it answers now; present
    /// when an HSM is configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hsm: Option<crate::signing::HsmStatus>,
    /// True when the process runs with `--insecure-dev`.
    pub insecure_dev: bool,
    /// True when the process was started with `--require-hardening`, which
    /// refused to start unless every guarantee was on.
    pub require_hardening: bool,
    /// Every way this process runs with a guarantee relaxed, by name (a
    /// fixed set, see BYPASS_INVENTORY.md section 1). Empty in production.
    pub relaxations: Vec<&'static str>,
    /// True when the data plane runs agent-only (`--agent-only`): the
    /// operator listener does not serve the credit track (evaluate, packs,
    /// models, decision events, retention, tombstones, incidents, batch
    /// jobs). The console uses it to leave those pages out.
    pub agent_only: bool,
}

pub async fn runtime(
    State(state): State<Arc<AppState>>,
    credentials: Credentials,
) -> Result<Json<RuntimeView>, ApiError> {
    authorize_credentials(&state, &credentials, KavachAction::ReadGovernance)?;
    let runtime = state.runtime()?;
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
        checkpoints: state
            .dataplane()
            .map(|dp| crate::checkpoints::CheckpointView::of(dp.checkpointer())),
        dev_clock: state
            .dataplane()
            .and_then(|dp| dp.dev_clock())
            .map(|c| c.view()),
        hsm: match state.dataplane() {
            Some(dp) => dp.hsm_status().await,
            None => None,
        },
        insecure_dev: state.insecure_dev(),
        require_hardening: state.require_hardening(),
        relaxations: state.relaxations().iter().map(|r| r.as_str()).collect(),
        agent_only: state
            .dataplane()
            .is_some_and(crate::dataplane::Dataplane::agent_only),
    }))
}

pub async fn list_policy_packs(
    State(state): State<Arc<AppState>>,
    credentials: Credentials,
) -> Result<Json<Vec<crate::registry::PackSummary>>, ApiError> {
    authorize_credentials(&state, &credentials, KavachAction::ReadGovernance)?;
    let runtime = state.runtime()?;
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
    let runtime = state.runtime()?;
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

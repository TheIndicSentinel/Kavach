use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    Json,
};
use kavach_auth::KavachAction;
use kavach_domain::{GovernanceMode, ModelStatus};
use kavach_storage::AuditEntry;
use serde::Deserialize;

use crate::auth::{authorize_dual_control, authorize_headers};
use crate::error::ApiError;
use crate::governance::RuntimeResponse;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    #[serde(default = "default_audit_limit")]
    limit: u32,
}

fn default_audit_limit() -> u32 {
    50
}

#[derive(Debug, Deserialize)]
pub struct UpdateModelRequest {
    pub status: Option<ModelStatus>,
    pub governance_mode: Option<GovernanceMode>,
}

pub async fn list_audit_log(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
) -> Result<Json<Vec<AuditEntry>>, ApiError> {
    authorize_headers(&state, &headers, KavachAction::ReadAudit)?;
    let limit = query.limit.clamp(1, 200);
    let entries = state
        .admin()
        .list_audit(limit)
        .await
        .map_err(|e| ApiError::Internal(format!("audit list: {e}")))?;
    Ok(Json(entries))
}

pub async fn activate_pack(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(pack_id): Path<String>,
) -> Result<Json<RuntimeResponse>, ApiError> {
    let principals = authorize_dual_control(&state, &headers, KavachAction::ActivatePack)?;
    let runtime = state.activate_pack(&pack_id, &principals).await?;
    Ok(Json(runtime))
}

pub async fn rollback_pack(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<RuntimeResponse>, ApiError> {
    let principals = authorize_dual_control(&state, &headers, KavachAction::RollbackPack)?;
    let runtime = state.rollback_pack(&principals).await?;
    Ok(Json(runtime))
}

pub async fn update_model_record(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(model_id): Path<String>,
    Json(body): Json<UpdateModelRequest>,
) -> Result<Json<RuntimeResponse>, ApiError> {
    if body.status.is_none() && body.governance_mode.is_none() {
        return Err(ApiError::BadRequest(
            "provide status and/or governance_mode".into(),
        ));
    }
    let principals = authorize_dual_control(&state, &headers, KavachAction::UpdateModel)?;
    let runtime = state
        .update_model(&model_id, body.status, body.governance_mode, &principals)
        .await?;
    Ok(Json(runtime))
}

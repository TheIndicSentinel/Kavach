use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    Json,
};
use kavach_auth::KavachAction;
use kavach_storage::{RetentionApplyReport, RetentionSettings, TombstoneReason, TombstoneRecord};
use serde::Deserialize;

use crate::auth::{authorize_dual_control, authorize_headers};
use crate::error::ApiError;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct TombstoneQuery {
    #[serde(default = "default_tombstone_limit")]
    limit: u32,
}

fn default_tombstone_limit() -> u32 {
    50
}

#[derive(Debug, Deserialize)]
pub struct UpdateRetentionRequest {
    pub evidence_retention_days: u32,
}

pub async fn get_retention_settings(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<RetentionSettings>, ApiError> {
    authorize_headers(&state, &headers, KavachAction::ReadRetention)?;
    let settings = state
        .retention()
        .get_settings()
        .await
        .map_err(|e| ApiError::Internal(format!("retention settings: {e}")))?;
    Ok(Json(settings))
}

pub async fn update_retention_settings(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<UpdateRetentionRequest>,
) -> Result<Json<RetentionSettings>, ApiError> {
    if body.evidence_retention_days == 0 {
        return Err(ApiError::BadRequest(
            "evidence_retention_days must be at least 1".into(),
        ));
    }
    let principals = authorize_dual_control(&state, &headers, KavachAction::UpdateRetention)?;
    let settings = state
        .update_retention_settings(body.evidence_retention_days, &principals)
        .await?;
    Ok(Json(settings))
}

pub async fn list_tombstones(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<TombstoneQuery>,
) -> Result<Json<Vec<TombstoneRecord>>, ApiError> {
    authorize_headers(&state, &headers, KavachAction::ReadTombstones)?;
    let limit = query.limit.clamp(1, 200);
    let records = state
        .retention()
        .list_tombstones(limit)
        .await
        .map_err(|e| ApiError::Internal(format!("tombstone list: {e}")))?;
    Ok(Json(records))
}

pub async fn erase_evidence(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(evidence_id): Path<String>,
) -> Result<Json<TombstoneRecord>, ApiError> {
    let principals = authorize_dual_control(&state, &headers, KavachAction::EraseEvidence)?;
    let record = state
        .erase_evidence(&evidence_id, TombstoneReason::DpdpErasure, &principals)
        .await?;
    Ok(Json(record))
}

pub async fn apply_retention(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<RetentionApplyReport>, ApiError> {
    let principals = authorize_dual_control(&state, &headers, KavachAction::ApplyRetention)?;
    let report = state.apply_retention(&principals).await?;
    Ok(Json(report))
}

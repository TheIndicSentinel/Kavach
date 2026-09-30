use std::sync::Arc;

use axum::{
    extract::{Query, State},
    Json,
};
use kavach_auth::KavachAction;
use kavach_storage::{RetentionSettings, TombstoneRecord};
use serde::Deserialize;

use crate::auth::{authorize_credentials, Credentials};
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

pub async fn get_retention_settings(
    State(state): State<Arc<AppState>>,
    credentials: Credentials,
) -> Result<Json<RetentionSettings>, ApiError> {
    authorize_credentials(&state, &credentials, KavachAction::ReadRetention)?;
    let settings = state
        .retention()
        .get_settings()
        .await
        .map_err(|e| ApiError::Internal(format!("retention settings: {e}")))?;
    Ok(Json(settings))
}

pub async fn list_tombstones(
    State(state): State<Arc<AppState>>,
    credentials: Credentials,
    Query(query): Query<TombstoneQuery>,
) -> Result<Json<Vec<TombstoneRecord>>, ApiError> {
    authorize_credentials(&state, &credentials, KavachAction::ReadTombstones)?;
    let limit = query.limit.clamp(1, 200);
    let records = state
        .retention()
        .list_tombstones(limit)
        .await
        .map_err(|e| ApiError::Internal(format!("tombstone list: {e}")))?;
    Ok(Json(records))
}

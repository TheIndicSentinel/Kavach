use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    Json,
};
use kavach_auth::KavachAction;
use kavach_storage::{BatchJobRecord, JobQueryError};
use serde::Deserialize;

use crate::auth::authorize_headers;
use crate::error::ApiError;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct BatchJobQuery {
    #[serde(default = "default_batch_job_limit")]
    limit: u32,
}

fn default_batch_job_limit() -> u32 {
    50
}

pub async fn list_batch_jobs(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<BatchJobQuery>,
) -> Result<Json<Vec<BatchJobRecord>>, ApiError> {
    authorize_headers(&state, &headers, KavachAction::ReadBatchJobs)?;
    let limit = query.limit.clamp(1, 200);
    let records = state
        .batch_jobs()
        .list(limit)
        .await
        .map_err(map_job_query_error)?;
    Ok(Json(records))
}

pub async fn get_batch_job(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(job_id): Path<String>,
) -> Result<Json<BatchJobRecord>, ApiError> {
    authorize_headers(&state, &headers, KavachAction::ReadBatchJobs)?;
    let record = state
        .batch_jobs()
        .get(&job_id)
        .await
        .map_err(map_job_query_error)?;
    Ok(Json(record))
}

fn map_job_query_error(error: JobQueryError) -> ApiError {
    match error {
        JobQueryError::NotFound(id) => ApiError::NotFound(id),
        JobQueryError::Io(message) => ApiError::Internal(message),
    }
}

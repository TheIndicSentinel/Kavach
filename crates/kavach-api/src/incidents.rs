use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::HeaderMap,
    Json,
};
use kavach_auth::KavachAction;
use kavach_storage::IncidentRecord;
use serde::Deserialize;

use crate::auth::authorize_headers;
use crate::error::ApiError;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct IncidentQuery {
    #[serde(default = "default_incident_limit")]
    limit: u32,
}

fn default_incident_limit() -> u32 {
    50
}

pub async fn list_incidents(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<IncidentQuery>,
) -> Result<Json<Vec<IncidentRecord>>, ApiError> {
    authorize_headers(&state, &headers, KavachAction::ReadIncidents)?;
    let limit = query.limit.clamp(1, 200);
    let records = state
        .incidents()
        .list(limit)
        .await
        .map_err(|e| ApiError::Internal(format!("incident list: {e}")))?;
    Ok(Json(records))
}

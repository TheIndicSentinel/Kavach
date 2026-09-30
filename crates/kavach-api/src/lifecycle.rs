use std::sync::Arc;

use axum::{
    extract::{Query, State},
    Json,
};
use kavach_auth::KavachAction;
use kavach_storage::AuditEntry;
use serde::Deserialize;

use crate::auth::{authorize_credentials, Credentials};
use crate::error::ApiError;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    #[serde(default = "default_audit_limit")]
    limit: u32,
}

fn default_audit_limit() -> u32 {
    50
}

pub async fn list_audit_log(
    State(state): State<Arc<AppState>>,
    credentials: Credentials,
    Query(query): Query<AuditQuery>,
) -> Result<Json<Vec<AuditEntry>>, ApiError> {
    authorize_credentials(&state, &credentials, KavachAction::ReadAudit)?;
    let limit = query.limit.clamp(1, 200);
    let entries = state
        .admin()
        .list_audit(limit)
        .await
        .map_err(|e| ApiError::Internal(format!("audit list: {e}")))?;
    Ok(Json(entries))
}

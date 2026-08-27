use axum::http::HeaderMap;
use kavach_auth::KavachAction;
use tonic::metadata::MetadataMap;

use crate::error::ApiError;
use crate::state::AppState;

pub fn authorize_headers(
    state: &AppState,
    headers: &HeaderMap,
    action: KavachAction,
) -> Result<(), ApiError> {
    let principal = headers
        .get("x-kavach-principal")
        .and_then(|value| value.to_str().ok());
    authorize_principal(state, principal, action)
}

pub fn authorize_metadata(
    state: &AppState,
    metadata: &MetadataMap,
    action: KavachAction,
) -> Result<(), ApiError> {
    let principal = metadata
        .get("x-kavach-principal")
        .and_then(|value| value.to_str().ok());
    authorize_principal(state, principal, action)
}

fn authorize_principal(
    state: &AppState,
    principal: Option<&str>,
    action: KavachAction,
) -> Result<(), ApiError> {
    let Some(auth) = state.access_control() else {
        return Ok(());
    };

    let principal = principal.ok_or(ApiError::Unauthorized)?;
    let allowed = auth
        .authorize(principal, action)
        .map_err(|e| ApiError::Internal(format!("cedar authorize: {e}")))?;
    if allowed {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}

//! `/v1/change-requests`: maker-checker governance changes (ADR-009).

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use chrono::Utc;
use kavach_auth::KavachAction;
use kavach_storage::{ChangeKind, ChangeRequest, ChangeStatus};
use serde::Deserialize;

use crate::auth::{authorized_principal, Credentials};
use crate::error::ApiError;
use crate::state::{AppState, ChangeProposal};

#[must_use]
pub fn propose_action(kind: ChangeKind) -> KavachAction {
    match kind {
        ChangeKind::ActivatePack => KavachAction::ProposeActivatePack,
        ChangeKind::RollbackPack => KavachAction::ProposeRollbackPack,
        ChangeKind::UpdateModel => KavachAction::ProposeUpdateModel,
        ChangeKind::UpdateRetention => KavachAction::ProposeUpdateRetention,
        ChangeKind::EraseEvidence => KavachAction::ProposeEraseEvidence,
        ChangeKind::ApplyRetention => KavachAction::ProposeApplyRetention,
    }
}

#[must_use]
pub fn approve_action(kind: ChangeKind) -> KavachAction {
    match kind {
        ChangeKind::ActivatePack => KavachAction::ApproveActivatePack,
        ChangeKind::RollbackPack => KavachAction::ApproveRollbackPack,
        ChangeKind::UpdateModel => KavachAction::ApproveUpdateModel,
        ChangeKind::UpdateRetention => KavachAction::ApproveUpdateRetention,
        ChangeKind::EraseEvidence => KavachAction::ApproveEraseEvidence,
        ChangeKind::ApplyRetention => KavachAction::ApproveApplyRetention,
    }
}

/// Pending requests past their expiry are reported as expired; the stored
/// status changes when someone next acts on them.
fn with_display_status(mut request: ChangeRequest) -> ChangeRequest {
    if request.status == ChangeStatus::Pending && request.expires_at <= Utc::now() {
        request.status = ChangeStatus::Expired;
    }
    request
}

pub async fn propose(
    State(state): State<Arc<AppState>>,
    credentials: Credentials,
    Json(proposal): Json<ChangeProposal>,
) -> Result<(StatusCode, Json<ChangeRequest>), ApiError> {
    let proposer = authorized_principal(&state, &credentials, propose_action(proposal.kind))?;
    let request = state.propose_change(&proposer, proposal).await?;
    Ok((StatusCode::CREATED, Json(request)))
}

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    status: Option<String>,
    #[serde(default = "default_limit")]
    limit: u32,
}

fn default_limit() -> u32 {
    50
}

pub async fn list(
    State(state): State<Arc<AppState>>,
    credentials: Credentials,
    Query(query): Query<ListQuery>,
) -> Result<Json<Vec<ChangeRequest>>, ApiError> {
    authorized_principal(&state, &credentials, KavachAction::ReadChangeRequests)?;
    let status = match query.status.as_deref() {
        None => None,
        Some(value) => Some(
            ChangeStatus::parse(value)
                .ok_or_else(|| ApiError::BadRequest(format!("unknown status: {value}")))?,
        ),
    };
    let requests = state
        .changes()
        .list(status, query.limit.clamp(1, 200))
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(Json(
        requests.into_iter().map(with_display_status).collect(),
    ))
}

pub async fn get(
    State(state): State<Arc<AppState>>,
    credentials: Credentials,
    Path(id): Path<String>,
) -> Result<Json<ChangeRequest>, ApiError> {
    authorized_principal(&state, &credentials, KavachAction::ReadChangeRequests)?;
    let request = state
        .changes()
        .get(&id)
        .await
        .map_err(|_| ApiError::NotFound(format!("change request {id}")))?;
    Ok(Json(with_display_status(request)))
}

async fn kind_of(state: &AppState, id: &str) -> Result<ChangeKind, ApiError> {
    state
        .changes()
        .get(id)
        .await
        .map(|request| request.kind)
        .map_err(|_| ApiError::NotFound(format!("change request {id}")))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApproveBody {
    /// The digest shown to the approver; approval fails if it differs.
    change_digest: String,
}

pub async fn approve(
    State(state): State<Arc<AppState>>,
    credentials: Credentials,
    Path(id): Path<String>,
    Json(body): Json<ApproveBody>,
) -> Result<Json<ChangeRequest>, ApiError> {
    let kind = kind_of(&state, &id).await?;
    let approver = authorized_principal(&state, &credentials, approve_action(kind))?;
    Ok(Json(
        state
            .approve_change(&approver, &id, &body.change_digest)
            .await?,
    ))
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RejectBody {
    reason: Option<String>,
}

pub async fn reject(
    State(state): State<Arc<AppState>>,
    credentials: Credentials,
    Path(id): Path<String>,
    body: Option<Json<RejectBody>>,
) -> Result<Json<ChangeRequest>, ApiError> {
    let kind = kind_of(&state, &id).await?;
    let checker = authorized_principal(&state, &credentials, approve_action(kind))?;
    let reason = body.and_then(|Json(body)| body.reason);
    Ok(Json(state.reject_change(&checker, &id, reason).await?))
}

pub async fn cancel(
    State(state): State<Arc<AppState>>,
    credentials: Credentials,
    Path(id): Path<String>,
) -> Result<Json<ChangeRequest>, ApiError> {
    let kind = kind_of(&state, &id).await?;
    let proposer = authorized_principal(&state, &credentials, propose_action(kind))?;
    Ok(Json(state.cancel_change(&proposer, &id).await?))
}

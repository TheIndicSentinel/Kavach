//! `/v1/change-requests`: maker-checker governance changes (ADR-009).

use crate::strict_json::StrictJson;
use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use chrono::Utc;
use kavach_auth::KavachAction;
use kavach_storage::{ChangeKind, ChangeRequest, ChangeStatus, Role};
use serde::Deserialize;
use serde_json::Value;

use crate::auth::{authorized_principal, authorized_role_change, Authorized, Credentials};
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
        ChangeKind::ActivateModel => KavachAction::ProposeActivateModel,
        ChangeKind::ReinstateAgent => KavachAction::ProposeReinstateAgent,
        ChangeKind::GrantRole => KavachAction::ProposeGrantRole,
        ChangeKind::RevokeRole => KavachAction::ProposeRevokeRole,
        ChangeKind::AttestOutcomeDelivered => KavachAction::AttestOutcomeDelivered,
        ChangeKind::AttestOutcomeNotDelivered => KavachAction::AttestOutcomeNotDelivered,
        ChangeKind::ResolveOutcomeConflict => KavachAction::ResolveOutcomeConflict,
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
        ChangeKind::ActivateModel => KavachAction::ApproveActivateModel,
        ChangeKind::ReinstateAgent => KavachAction::ApproveReinstateAgent,
        ChangeKind::GrantRole => KavachAction::ApproveGrantRole,
        ChangeKind::RevokeRole => KavachAction::ApproveRevokeRole,
        ChangeKind::AttestOutcomeDelivered => KavachAction::AttestOutcomeDelivered,
        ChangeKind::AttestOutcomeNotDelivered => KavachAction::AttestOutcomeNotDelivered,
        ChangeKind::ResolveOutcomeConflict => KavachAction::ResolveOutcomeConflict,
    }
}

/// Whether the kind changes operator access, which every deployment has,
/// rather than the credit track (packs, models, retention, erasure).
fn serves_agent_only(kind: ChangeKind) -> bool {
    matches!(
        kind,
        ChangeKind::ReinstateAgent
            | ChangeKind::GrantRole
            | ChangeKind::RevokeRole
            | ChangeKind::AttestOutcomeDelivered
            | ChangeKind::AttestOutcomeNotDelivered
            | ChangeKind::ResolveOutcomeConflict
    )
}

/// The role a pending or decided role-change request changes: a grant's
/// from its parameters, a revoke's from the binding frozen at proposal.
/// `None` for every other kind.
fn role_of_request(request: &ChangeRequest) -> Result<Option<Role>, ApiError> {
    let source = match request.kind {
        ChangeKind::GrantRole => &request.params,
        ChangeKind::RevokeRole => &request.binding,
        _ => return Ok(None),
    };
    source
        .get("role")
        .and_then(Value::as_str)
        .and_then(Role::parse)
        .map(Some)
        .ok_or_else(|| ApiError::Internal(format!("change request {} names no role", request.id)))
}

/// Authorizes `action` for a request of `role` (or of no role).
async fn authorize_for(
    state: &AppState,
    credentials: &Credentials,
    action: KavachAction,
    role: Option<Role>,
) -> Result<Authorized, ApiError> {
    match role {
        Some(role) => authorized_role_change(state, credentials, action, role).await,
        None => authorized_principal(state, credentials, action).await,
    }
}

/// The role a role-change proposal changes. A revoke's comes from the
/// binding it names; the caller must first be allowed to propose a revoke
/// of the least role, so whether a binding id exists is not told to
/// someone who may revoke nothing.
async fn role_of_proposal(
    state: &AppState,
    credentials: &Credentials,
    proposal: &ChangeProposal,
) -> Result<Option<Role>, ApiError> {
    match proposal.kind {
        ChangeKind::GrantRole => proposal
            .params
            .get("role")
            .and_then(Value::as_str)
            .and_then(Role::parse)
            .map(Some)
            .ok_or_else(|| {
                ApiError::BadRequest("invalid params: role must be one of the seven roles".into())
            }),
        ChangeKind::RevokeRole => {
            authorized_role_change(
                state,
                credentials,
                KavachAction::ProposeRevokeRole,
                Role::Viewer,
            )
            .await?;
            let binding_id = proposal
                .params
                .get("binding_id")
                .and_then(Value::as_str)
                .ok_or_else(|| ApiError::BadRequest("invalid params: binding_id".into()))?;
            state
                .active_binding(binding_id)
                .await
                .map(|binding| Some(binding.role))
        }
        _ => Ok(None),
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
    StrictJson(proposal): StrictJson<ChangeProposal>,
) -> Result<(StatusCode, Json<ChangeRequest>), ApiError> {
    // The credit track's kinds (packs, models, retention, erasure) are not
    // served by an agent-only build; agent reinstatement and operator roles
    // are.
    if !serves_agent_only(proposal.kind)
        && state
            .dataplane()
            .is_some_and(crate::dataplane::Dataplane::agent_only)
    {
        return Err(ApiError::NotFound(
            "this kind of change request is not available in agent-only mode".into(),
        ));
    }
    let role = role_of_proposal(&state, &credentials, &proposal).await?;
    let proposer = authorize_for(&state, &credentials, propose_action(proposal.kind), role).await?;
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
    authorized_principal(&state, &credentials, KavachAction::ReadChangeRequests).await?;
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
    authorized_principal(&state, &credentials, KavachAction::ReadChangeRequests).await?;
    let request = state
        .changes()
        .get(&id)
        .await
        .map_err(|_| ApiError::NotFound(format!("change request {id}")))?;
    Ok(Json(with_display_status(request)))
}

/// The kind of the request and, for a role change, the role it changes.
async fn kind_of(state: &AppState, id: &str) -> Result<(ChangeKind, Option<Role>), ApiError> {
    let request = state
        .changes()
        .get(id)
        .await
        .map_err(|_| ApiError::NotFound(format!("change request {id}")))?;
    Ok((request.kind, role_of_request(&request)?))
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
    let (kind, role) = kind_of(&state, &id).await?;
    let approver = authorize_for(&state, &credentials, approve_action(kind), role).await?;
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
    let (kind, role) = kind_of(&state, &id).await?;
    let checker = authorize_for(&state, &credentials, approve_action(kind), role).await?;
    let reason = body.and_then(|Json(body)| body.reason);
    Ok(Json(state.reject_change(&checker, &id, reason).await?))
}

pub async fn cancel(
    State(state): State<Arc<AppState>>,
    credentials: Credentials,
    Path(id): Path<String>,
) -> Result<Json<ChangeRequest>, ApiError> {
    let (kind, role) = kind_of(&state, &id).await?;
    let proposer = authorize_for(&state, &credentials, propose_action(kind), role).await?;
    Ok(Json(state.cancel_change(&proposer, &id).await?))
}

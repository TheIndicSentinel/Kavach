//! Maker-checker change requests (ADR-009): propose, approve (applies),
//! reject, cancel.
//!
//! `prepare` validates a change and computes what it binds to and what it
//! writes, without side effects. It runs at proposal (to freeze the binding)
//! and again at approval; the approval applies only when the fresh binding
//! equals the frozen one and the store confirms, under lock, that the
//! request is still pending and the runtime pointer version unchanged.

use chrono::{DateTime, Utc};
use kavach_domain::{GovernanceMode, ModelRecord, ModelStatus};
use kavach_policy::{LoadedPolicyPack, PackLoader};
use kavach_storage::{
    evidence_set_digest, ApprovalCommit, AuditInsert, ChangeKind, ChangeRequest, ChangeStatus,
    ChangeStoreError, CloseRequest, GovernanceEffect, RuntimePointers, TombstoneReason,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::{precheck_model, AppState};
use crate::auth::{AuthenticatedPrincipal, PrincipalSource};
use crate::error::ApiError;
use crate::governance::RuntimeResponse;
use crate::registry::pack_source_path;

pub const DEFAULT_CHANGE_TTL_HOURS: u64 = 24;
const TENANT: &str = "default";
const NO_APPROVER: &str = "-";
const MAX_REASON_CHARS: usize = 1000;

/// `POST /v1/change-requests` body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeProposal {
    pub kind: ChangeKind,
    #[serde(default = "empty_object")]
    pub params: Value,
    pub reason: Option<String>,
}

fn empty_object() -> Value {
    json!({})
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivatePackParams {
    pack_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NoParams {}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateModelParams {
    model_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<ModelStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    governance_mode: Option<GovernanceMode>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivateModelParams {
    model_id: String,
    /// The exact version to activate (model files are found by id + version).
    version: String,
    /// Required to activate a lower version of the active model; part of
    /// the change digest, so the approver sees it.
    #[serde(default)]
    allow_downgrade: bool,
}

/// True when `to` is lower than `from`, or when the versions differ and are
/// not both dotted numbers (an explicit `allow_downgrade` is then required).
fn is_downgrade(from: &str, to: &str) -> bool {
    let parse = |v: &str| {
        v.split('.')
            .map(|part| part.parse::<u64>().ok())
            .collect::<Option<Vec<_>>>()
    };
    match (parse(from), parse(to)) {
        (Some(a), Some(b)) => b < a,
        _ => from != to,
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateRetentionParams {
    evidence_retention_days: u32,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EraseEvidenceParams {
    evidence_id: String,
}

fn parse<T: DeserializeOwned>(params: &Value) -> Result<T, ApiError> {
    serde_json::from_value(params.clone())
        .map_err(|e| ApiError::BadRequest(format!("invalid params: {e}")))
}

fn to_value<T: Serialize>(value: &T) -> Result<Value, ApiError> {
    serde_json::to_value(value).map_err(|e| ApiError::Internal(format!("serialize: {e}")))
}

struct LiveSwap {
    pack: LoadedPolicyPack,
    model: ModelRecord,
    runtime: RuntimeResponse,
}

/// A validated change: what it binds to, what it writes, what it swaps.
struct Prepared {
    params: Value,
    binding: Value,
    expected_version: Option<i64>,
    /// Written in order inside the approval transaction.
    effects: Vec<GovernanceEffect>,
    live: Option<LiveSwap>,
    resource_type: &'static str,
    resource_id: String,
    audit_payload: Value,
    outcome: Value,
}

/// Principals named in refusal audits while preparing.
#[derive(Clone, Copy)]
struct Actors<'a> {
    proposer: &'a str,
    approver: &'a str,
}

fn change_digest(request: &ChangeRequest) -> Result<String, ApiError> {
    let bytes = serde_json_canonicalizer::to_vec(&json!({
        "id": request.id,
        "tenant_id": request.tenant_id,
        "kind": request.kind.as_str(),
        "params": request.params,
        "binding": request.binding,
        "proposer_key": request.proposer_key,
        "created_at": request.created_at,
        "expires_at": request.expires_at,
    }))
    .map_err(|e| ApiError::Internal(format!("canonical json: {e}")))?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

fn validate_reason(reason: Option<String>) -> Result<Option<String>, ApiError> {
    let Some(reason) = reason
        .map(|r| r.trim().to_string())
        .filter(|r| !r.is_empty())
    else {
        return Ok(None);
    };
    if reason.chars().count() > MAX_REASON_CHARS
        || reason.chars().any(|c| c.is_control() && c != '\n')
    {
        return Err(ApiError::BadRequest(format!(
            "reason must be at most {MAX_REASON_CHARS} characters without control characters"
        )));
    }
    Ok(Some(reason))
}

fn store_error(err: ChangeStoreError) -> ApiError {
    match err {
        ChangeStoreError::NotFound(id) => ApiError::NotFound(format!("change request {id}")),
        ChangeStoreError::NotPending(request) => {
            ApiError::Conflict(format!("change request is {}", request.status.as_str()))
        }
        ChangeStoreError::DigestMismatch => {
            ApiError::Conflict("change_digest does not match the request".into())
        }
        ChangeStoreError::Expired(_) => ApiError::Conflict("change request expired".into()),
        ChangeStoreError::Stale { reason, .. } => {
            ApiError::Conflict(format!("change request failed: {reason}"))
        }
        ChangeStoreError::Io(message) => ApiError::Internal(message),
    }
}

impl AppState {
    pub async fn propose_change(
        &self,
        proposer: &AuthenticatedPrincipal,
        proposal: ChangeProposal,
    ) -> Result<ChangeRequest, ApiError> {
        let reason = validate_reason(proposal.reason)?;
        let _guard = self.governance_lock.lock().await;
        let actors = Actors {
            proposer: &proposer.id,
            approver: NO_APPROVER,
        };
        let prepared = self
            .prepare(proposal.kind, &proposal.params, actors, None)
            .await?;

        let now = Utc::now();
        let mut request = ChangeRequest {
            id: uuid::Uuid::new_v4().to_string(),
            tenant_id: TENANT.into(),
            kind: proposal.kind,
            params: prepared.params,
            binding: prepared.binding,
            change_digest: String::new(),
            reason,
            proposer: proposer.id.clone(),
            proposer_key: proposer.identity_key(),
            status: ChangeStatus::Pending,
            decided_by: None,
            decided_by_key: None,
            outcome: None,
            created_at: now,
            expires_at: now + self.change_ttl,
            decided_at: None,
        };
        request.change_digest = change_digest(&request)?;
        let audit = AuditInsert {
            action: "change_request_proposed".into(),
            resource_type: "change_request".into(),
            resource_id: request.id.clone(),
            actor_principal: request.proposer.clone(),
            approver_principal: NO_APPROVER.into(),
            payload: json!({
                "kind": request.kind.as_str(),
                "change_digest": request.change_digest,
                "params": request.params,
                "binding": request.binding,
            }),
        };
        self.changes
            .create(&request, audit)
            .await
            .map_err(store_error)?;
        Ok(request)
    }

    /// Approves and applies a pending request. A retry by the same approver
    /// after success returns the applied request.
    pub async fn approve_change(
        &self,
        approver: &AuthenticatedPrincipal,
        id: &str,
        echoed_digest: &str,
    ) -> Result<ChangeRequest, ApiError> {
        let human = approver.source == PrincipalSource::Jwt
            || (approver.source == PrincipalSource::InsecureHeader && self.insecure_dev);
        if !human {
            return Err(ApiError::ForbiddenBecause(
                "approvals require an OIDC user token; certificate principals cannot approve"
                    .into(),
            ));
        }
        let approver_key = approver.identity_key();
        let _guard = self.governance_lock.lock().await;
        let request = self.changes.get(id).await.map_err(store_error)?;
        if request.status == ChangeStatus::Applied
            && request.decided_by_key.as_deref() == Some(approver_key.as_str())
            && request.change_digest == echoed_digest
        {
            return Ok(request);
        }
        if request.status != ChangeStatus::Pending {
            return Err(store_error(ChangeStoreError::NotPending(Box::new(request))));
        }
        if approver_key == request.proposer_key || approver.id == request.proposer {
            return Err(ApiError::ForbiddenBecause(
                "the approver must be a different principal than the proposer".into(),
            ));
        }
        if request.change_digest != echoed_digest {
            return Err(store_error(ChangeStoreError::DigestMismatch));
        }
        let now = Utc::now();
        if request.expires_at <= now {
            self.close(&request, ChangeStatus::Expired, approver, "expired")
                .await?;
            return Err(ApiError::Conflict("change request expired".into()));
        }

        let actors = Actors {
            proposer: &request.proposer,
            approver: &approver.id,
        };
        let cutoff = request
            .binding
            .get("cutoff")
            .and_then(|c| serde_json::from_value::<DateTime<Utc>>(c.clone()).ok());
        let prepared = match self
            .prepare(request.kind, &request.params, actors, cutoff)
            .await
        {
            Ok(prepared) if prepared.binding == request.binding => prepared,
            Ok(prepared) => {
                let reason = format!(
                    "stale: state changed since proposal (bound {}, now {})",
                    request.binding, prepared.binding
                );
                self.close(&request, ChangeStatus::Failed, approver, &reason)
                    .await?;
                return Err(ApiError::Conflict(format!(
                    "change request failed: {reason}"
                )));
            }
            Err(ApiError::Internal(message)) => return Err(ApiError::Internal(message)),
            Err(err) => {
                let reason = err.to_string();
                self.close(&request, ChangeStatus::Failed, approver, &reason)
                    .await?;
                return Err(err);
            }
        };

        self.commit(&request, approver, &approver_key, prepared, now)
            .await
    }

    async fn commit(
        &self,
        request: &ChangeRequest,
        approver: &AuthenticatedPrincipal,
        approver_key: &str,
        prepared: Prepared,
        now: DateTime<Utc>,
    ) -> Result<ChangeRequest, ApiError> {
        let version_before = self.runtime().pointer_version;
        let moves_pointer = prepared
            .effects
            .iter()
            .any(|e| matches!(e, GovernanceEffect::SetPointers(_)));
        let version_after = if moves_pointer {
            prepared.expected_version.unwrap_or(0) + 1
        } else {
            version_before
        };
        let mut payload = prepared.audit_payload;
        if let Value::Object(map) = &mut payload {
            map.insert("change_request_id".into(), json!(request.id));
            map.insert("change_digest".into(), json!(request.change_digest));
            map.insert("pointer_version_before".into(), json!(version_before));
            map.insert("pointer_version_after".into(), json!(version_after));
        }
        let commit = ApprovalCommit {
            request_id: request.id.clone(),
            change_digest: request.change_digest.clone(),
            approver: approver.id.clone(),
            approver_key: approver_key.to_string(),
            expected_pointer_version: prepared.expected_version,
            effects: prepared.effects,
            audit: AuditInsert {
                action: request.kind.as_str().into(),
                resource_type: prepared.resource_type.into(),
                resource_id: prepared.resource_id,
                actor_principal: request.proposer.clone(),
                approver_principal: approver.id.clone(),
                payload,
            },
            outcome: prepared.outcome,
            now,
        };
        let applied = self
            .changes
            .commit_approval(commit)
            .await
            .map_err(store_error)?;
        if let Some(mut live) = prepared.live {
            live.runtime.pointer_version = version_after;
            // Prechecked before commit; if it still fails, a restart converges
            // on the committed pointer.
            self.swap_live(live.pack, live.model, &live.runtime)?;
        }
        Ok(applied)
    }

    /// Rejects a pending request (a checker other than the proposer).
    pub async fn reject_change(
        &self,
        checker: &AuthenticatedPrincipal,
        id: &str,
        reason: Option<String>,
    ) -> Result<ChangeRequest, ApiError> {
        let reason = validate_reason(reason)?;
        let _guard = self.governance_lock.lock().await;
        let request = self.changes.get(id).await.map_err(store_error)?;
        if checker.identity_key() == request.proposer_key || checker.id == request.proposer {
            return Err(ApiError::ForbiddenBecause(
                "the proposer cancels a request; rejection is for another principal".into(),
            ));
        }
        self.close(
            &request,
            ChangeStatus::Rejected,
            checker,
            reason.as_deref().unwrap_or("rejected"),
        )
        .await
    }

    /// Cancels a pending request (its proposer only).
    pub async fn cancel_change(
        &self,
        proposer: &AuthenticatedPrincipal,
        id: &str,
    ) -> Result<ChangeRequest, ApiError> {
        let _guard = self.governance_lock.lock().await;
        let request = self.changes.get(id).await.map_err(store_error)?;
        if proposer.identity_key() != request.proposer_key {
            return Err(ApiError::ForbiddenBecause(
                "only the proposer can cancel a change request".into(),
            ));
        }
        self.close(&request, ChangeStatus::Cancelled, proposer, "cancelled")
            .await
    }

    async fn close(
        &self,
        request: &ChangeRequest,
        status: ChangeStatus,
        by: &AuthenticatedPrincipal,
        reason: &str,
    ) -> Result<ChangeRequest, ApiError> {
        let action = format!("change_request_{}", status.as_str());
        self.changes
            .close(CloseRequest {
                request_id: request.id.clone(),
                status,
                by: by.id.clone(),
                by_key: by.identity_key(),
                outcome: json!({ "reason": reason }),
                audit: kavach_storage::decision_audit(request, &action, &by.id, Some(reason)),
                now: Utc::now(),
            })
            .await
            .map_err(store_error)
    }

    async fn pointer_version(&self) -> Result<(Option<RuntimePointers>, i64), ApiError> {
        let pointers = self
            .admin
            .get_runtime_pointers()
            .await
            .map_err(|e| ApiError::Internal(format!("load runtime pointers: {e}")))?;
        let version = pointers.as_ref().map_or(0, |p| p.version);
        Ok((pointers, version))
    }

    fn live_model(&self) -> Result<ModelRecord, ApiError> {
        Ok(self
            .service
            .lock()
            .map_err(|_| ApiError::Internal("evaluate lock poisoned".into()))?
            .model()
            .clone())
    }

    async fn prepare(
        &self,
        kind: ChangeKind,
        params: &Value,
        actors: Actors<'_>,
        retention_cutoff: Option<DateTime<Utc>>,
    ) -> Result<Prepared, ApiError> {
        match kind {
            ChangeKind::ActivatePack => self.prepare_activate(parse(params)?, actors).await,
            ChangeKind::RollbackPack => {
                let _: NoParams = parse(params)?;
                self.prepare_rollback(actors).await
            }
            ChangeKind::UpdateModel => self.prepare_update_model(parse(params)?, actors).await,
            ChangeKind::UpdateRetention => self.prepare_update_retention(parse(params)?).await,
            ChangeKind::EraseEvidence => self.prepare_erase(parse(params)?).await,
            ChangeKind::ApplyRetention => {
                let _: NoParams = parse(params)?;
                self.prepare_apply_retention(retention_cutoff).await
            }
            ChangeKind::ActivateModel => self.prepare_activate_model(parse(params)?, actors).await,
        }
    }

    fn pack_pointers(
        runtime: &RuntimeResponse,
        previous: Option<&RuntimeResponse>,
        actors: Actors<'_>,
    ) -> RuntimePointers {
        RuntimePointers {
            pack_path: runtime.pack_path.clone(),
            model_path: runtime.model_path.clone(),
            previous_pack_path: previous.map(|p| p.pack_path.clone()),
            pack_sha256: runtime.pack_sha256.clone(),
            previous_pack_sha256: previous.and_then(|p| p.pack_sha256.clone()),
            model_sha256: runtime.model_sha256.clone(),
            updated_at: Utc::now(),
            updated_by: actors.proposer.into(),
            approved_by: actors.approver.into(),
            version: 0,
        }
    }

    /// The stored pointer (or one built from the runtime) re-written by this
    /// change, so it advances the shared runtime version.
    fn touch_pointers(
        stored: Option<RuntimePointers>,
        runtime: &RuntimeResponse,
        actors: Actors<'_>,
    ) -> RuntimePointers {
        let base = stored.unwrap_or_else(|| Self::pack_pointers(runtime, None, actors));
        RuntimePointers {
            updated_at: Utc::now(),
            updated_by: actors.proposer.into(),
            approved_by: actors.approver.into(),
            ..base
        }
    }

    async fn prepare_activate(
        &self,
        params: ActivatePackParams,
        actors: Actors<'_>,
    ) -> Result<Prepared, ApiError> {
        let path = pack_source_path(&self.packs_dir, &params.pack_id)?;
        let current = self.runtime();
        if current.pack_path == path.display().to_string() {
            return Err(ApiError::BadRequest(format!(
                "pack already active: {}",
                params.pack_id
            )));
        }
        let pack = PackLoader::load_from_path(&path)
            .map_err(|e| ApiError::Internal(format!("load pack: {e}")))?;
        if pack.pack.id != params.pack_id {
            return Err(ApiError::Conflict(format!(
                "pack_id_mismatch: {} declares id {}",
                path.display(),
                pack.pack.id
            )));
        }
        self.check_pack_signature(
            &pack,
            &path,
            "activate_pack",
            (actors.proposer, actors.approver),
        )
        .await?;
        let model = self.live_model()?;
        precheck_model(&model)?;
        let (_, version) = self.pointer_version().await?;

        let runtime = RuntimeResponse {
            pack_id: pack.pack.id.clone(),
            pack_version: pack.pack.version.clone(),
            pack_path: path.display().to_string(),
            pack_sha256: pack.digest.clone(),
            ..current.clone()
        };
        Ok(Prepared {
            params: to_value(&params)?,
            binding: json!({
                "pointer_version": version,
                "pack_id": runtime.pack_id,
                "pack_path": runtime.pack_path,
                "pack_sha256": runtime.pack_sha256,
            }),
            expected_version: Some(version),
            effects: vec![GovernanceEffect::SetPointers(Self::pack_pointers(
                &runtime,
                Some(&current),
                actors,
            ))],
            resource_type: "policy_pack",
            resource_id: params.pack_id,
            audit_payload: json!({
                "pack_path": runtime.pack_path,
                "pack_sha256": runtime.pack_sha256,
                "previous_pack_path": current.pack_path,
                "previous_pack_sha256": current.pack_sha256,
            }),
            outcome: to_value(&runtime)?,
            live: Some(LiveSwap {
                pack,
                model,
                runtime,
            }),
        })
    }

    async fn prepare_rollback(&self, actors: Actors<'_>) -> Result<Prepared, ApiError> {
        let (pointers, version) = self.pointer_version().await?;
        let pointers = pointers
            .ok_or_else(|| ApiError::BadRequest("no runtime pointer history to rollback".into()))?;
        let previous_path = pointers
            .previous_pack_path
            .clone()
            .ok_or_else(|| ApiError::BadRequest("no previous pack path recorded".into()))?;
        let path = std::path::Path::new(&previous_path);
        let pack = PackLoader::load_from_path(path)
            .map_err(|e| ApiError::Internal(format!("load pack: {e}")))?;
        let principals = (actors.proposer, actors.approver);
        self.check_pack_pin(
            &pack,
            pointers.previous_pack_sha256.as_deref(),
            "rollback_pack",
            principals,
        )
        .await?;
        self.check_pack_signature(&pack, path, "rollback_pack", principals)
            .await?;
        let model = self.live_model()?;
        precheck_model(&model)?;

        let current = self.runtime();
        let runtime = RuntimeResponse {
            pack_id: pack.pack.id.clone(),
            pack_version: pack.pack.version.clone(),
            pack_path: previous_path,
            pack_sha256: pack.digest.clone(),
            ..current
        };
        Ok(Prepared {
            params: json!({}),
            binding: json!({
                "pointer_version": version,
                "pack_id": runtime.pack_id,
                "pack_path": runtime.pack_path,
                "pack_sha256": runtime.pack_sha256,
            }),
            expected_version: Some(version),
            effects: vec![GovernanceEffect::SetPointers(Self::pack_pointers(
                &runtime, None, actors,
            ))],
            resource_type: "policy_pack",
            resource_id: runtime.pack_id.clone(),
            audit_payload: json!({
                "pack_path": runtime.pack_path,
                "pack_sha256": runtime.pack_sha256,
            }),
            outcome: to_value(&runtime)?,
            live: Some(LiveSwap {
                pack,
                model,
                runtime,
            }),
        })
    }

    /// Reloads the active pack for a model change, re-checking its pin and
    /// signature.
    async fn reload_active_pack(
        &self,
        current: &RuntimeResponse,
        operation: &str,
        actors: Actors<'_>,
    ) -> Result<LoadedPolicyPack, ApiError> {
        let pack_path = std::path::Path::new(&current.pack_path);
        let pack = PackLoader::load_from_path(pack_path)
            .map_err(|e| ApiError::Internal(format!("load pack: {e}")))?;
        let principals = (actors.proposer, actors.approver);
        self.check_pack_pin(&pack, current.pack_sha256.as_deref(), operation, principals)
            .await?;
        self.check_pack_signature(&pack, pack_path, operation, principals)
            .await?;
        Ok(pack)
    }

    async fn prepare_update_model(
        &self,
        params: UpdateModelParams,
        actors: Actors<'_>,
    ) -> Result<Prepared, ApiError> {
        if params.status.is_none() && params.governance_mode.is_none() {
            return Err(ApiError::BadRequest(
                "provide status and/or governance_mode".into(),
            ));
        }
        let current = self.runtime();
        if current.model_id != params.model_id {
            return Err(ApiError::BadRequest(
                "runtime model differs from requested model_id".into(),
            ));
        }
        let before = self.live_model()?;
        let mut model = before.clone();
        if let Some(status) = params.status {
            model.status = status;
        }
        if let Some(mode) = params.governance_mode {
            model.governance_mode = mode;
        }
        precheck_model(&model)?;

        let pack = self
            .reload_active_pack(&current, "update_model", actors)
            .await?;
        if self
            .admin
            .get_model_state(&model.model_id)
            .await
            .map_err(|e| ApiError::Internal(format!("model state: {e}")))?
            .is_none()
        {
            return Err(ApiError::Conflict(format!(
                "model {} is not governed; activate it with an activate_model change first",
                model.model_id
            )));
        }
        let (pointers, version) = self.pointer_version().await?;

        let runtime = RuntimeResponse {
            governance_mode: model.governance_mode,
            ..current
        };
        // The pointer write carries the change on the one runtime version
        // counter that every change binds to.
        let touched = Self::touch_pointers(pointers, &runtime, actors);
        let state = kavach_storage::ModelState {
            model_id: model.model_id.clone(),
            status: model.status,
            governance_mode: model.governance_mode,
            updated_at: Utc::now(),
            updated_by: actors.proposer.into(),
            approved_by: actors.approver.into(),
        };
        let status = |s: ModelStatus| format!("{s:?}").to_lowercase();
        let mode = |m: GovernanceMode| format!("{m:?}").to_lowercase();
        Ok(Prepared {
            params: to_value(&params)?,
            binding: json!({
                "pointer_version": version,
                "model_id": model.model_id,
                "status": status(before.status),
                "governance_mode": mode(before.governance_mode),
            }),
            expected_version: Some(version),
            effects: vec![
                GovernanceEffect::SetPointers(touched),
                GovernanceEffect::SetModelState(state),
            ],
            resource_type: "model_record",
            resource_id: params.model_id,
            audit_payload: json!({
                "status": status(model.status),
                "governance_mode": mode(model.governance_mode),
                "model_path": runtime.model_path,
            }),
            outcome: to_value(&runtime)?,
            live: Some(LiveSwap {
                pack,
                model,
                runtime,
            }),
        })
    }

    /// Activates a model file (a new version, or an edited file of the active
    /// one) under the current pack. A model with governed state keeps it;
    /// otherwise its YAML status and mode become the governed state.
    /// The model file an `activate_model` change names, checked for signature,
    /// "already active" and downgrade.
    fn model_file_for_activation(
        &self,
        params: &ActivateModelParams,
        current: &RuntimeResponse,
    ) -> Result<(std::path::PathBuf, ModelRecord, String), ApiError> {
        let path = crate::registry::model_path_by_version(
            &self.models_dir,
            &params.model_id,
            &params.version,
        )?;
        let (yaml, digest) = super::read_model_file(&path, self.pack_signers.as_ref())?;
        let path_str = path.display().to_string();
        if current.model_path == path_str
            && current.model_sha256.as_deref() == Some(digest.as_str())
        {
            return Err(ApiError::BadRequest(format!(
                "model already active: {} {}",
                params.model_id, params.version
            )));
        }
        if yaml.model_id == current.model_id
            && is_downgrade(&current.model_version, &yaml.version)
            && !params.allow_downgrade
        {
            return Err(ApiError::Conflict(format!(
                "model_downgrade: {} {} is lower than the active {}; set allow_downgrade to \
                 activate it",
                yaml.model_id, yaml.version, current.model_version
            )));
        }
        Ok((path, yaml, digest))
    }

    async fn prepare_activate_model(
        &self,
        params: ActivateModelParams,
        actors: Actors<'_>,
    ) -> Result<Prepared, ApiError> {
        let current = self.runtime();
        let (path, yaml, digest) = self.model_file_for_activation(&params, &current)?;
        let path_str = path.display().to_string();

        let governed = self
            .admin
            .get_model_state(&yaml.model_id)
            .await
            .map_err(|e| ApiError::Internal(format!("model state: {e}")))?;
        let model = match &governed {
            Some(state) => ModelRecord {
                status: state.status,
                governance_mode: state.governance_mode,
                ..yaml.clone()
            },
            None => yaml.clone(),
        };
        precheck_model(&model)?;

        let pack = self
            .reload_active_pack(&current, "activate_model", actors)
            .await?;
        let (pointers, version) = self.pointer_version().await?;

        let runtime = RuntimeResponse {
            model_id: model.model_id.clone(),
            model_version: model.version.clone(),
            sector: model.sector.clone(),
            governance_mode: model.governance_mode,
            model_path: path_str.clone(),
            model_sha256: Some(digest.clone()),
            ..current.clone()
        };
        let base = Self::touch_pointers(pointers, &current, actors);
        let mut effects = vec![GovernanceEffect::SetPointers(RuntimePointers {
            model_path: path_str.clone(),
            model_sha256: Some(digest.clone()),
            ..base
        })];
        if governed.is_none() {
            effects.push(GovernanceEffect::SetModelState(
                kavach_storage::ModelState {
                    model_id: model.model_id.clone(),
                    status: model.status,
                    governance_mode: model.governance_mode,
                    updated_at: Utc::now(),
                    updated_by: actors.proposer.into(),
                    approved_by: actors.approver.into(),
                },
            ));
        }
        let pack_mismatch = model.pack_id != current.pack_id;
        let status = kavach_storage::status_str(model.status);
        let mode = kavach_storage::mode_str(model.governance_mode);
        Ok(Prepared {
            params: to_value(&params)?,
            binding: json!({
                "pointer_version": version,
                "model_id": model.model_id,
                "model_version": model.version,
                "model_path": path_str,
                "model_sha256": digest,
                "status": status,
                "governance_mode": mode,
                "state_source": if governed.is_some() { "governed" } else { "model_file" },
                "model_pack_id": model.pack_id,
                "active_pack_id": current.pack_id,
                "warning": pack_mismatch.then(|| format!(
                    "model {} names pack {}, but pack {} is active",
                    model.model_id, model.pack_id, current.pack_id
                )),
            }),
            expected_version: Some(version),
            effects,
            resource_type: "model_record",
            resource_id: model.model_id.clone(),
            audit_payload: json!({
                "model_path": path_str,
                "model_sha256": digest,
                "model_version": model.version,
                "previous_model_path": current.model_path,
                "previous_model_sha256": current.model_sha256,
                "previous_model_version": current.model_version,
                "status": status,
                "governance_mode": mode,
                "model_pack_mismatch": pack_mismatch,
                "allow_downgrade": params.allow_downgrade,
            }),
            outcome: to_value(&runtime)?,
            live: Some(LiveSwap {
                pack,
                model,
                runtime,
            }),
        })
    }

    async fn prepare_update_retention(
        &self,
        params: UpdateRetentionParams,
    ) -> Result<Prepared, ApiError> {
        if !(1..=36_500).contains(&params.evidence_retention_days) {
            return Err(ApiError::BadRequest(
                "evidence_retention_days must be between 1 and 36500".into(),
            ));
        }
        let current = self
            .retention
            .get_settings()
            .await
            .map_err(super::map_retention_error)?
            .evidence_retention_days;
        Ok(Prepared {
            params: to_value(&params)?,
            binding: json!({ "evidence_retention_days": current }),
            expected_version: None,
            effects: vec![GovernanceEffect::SetRetentionDays {
                days: params.evidence_retention_days,
                expected_current: current,
            }],
            resource_type: "tenant_settings",
            resource_id: "retention".into(),
            audit_payload: json!({
                "evidence_retention_days": params.evidence_retention_days,
                "previous_evidence_retention_days": current,
            }),
            outcome: json!({ "evidence_retention_days": params.evidence_retention_days }),
            live: None,
        })
    }

    async fn prepare_erase(&self, params: EraseEvidenceParams) -> Result<Prepared, ApiError> {
        if let Some(events) = self.memory_events_snapshot()? {
            if !events.iter().any(|e| e.evidence_id == params.evidence_id) {
                return Err(ApiError::NotFound(format!(
                    "evidence not found: {}",
                    params.evidence_id
                )));
            }
        }
        if self
            .retention
            .is_tombstoned(&params.evidence_id)
            .await
            .map_err(super::map_retention_error)?
        {
            return Err(ApiError::Conflict(format!(
                "evidence already tombstoned: {}",
                params.evidence_id
            )));
        }
        Ok(Prepared {
            params: to_value(&params)?,
            binding: json!({ "evidence_id": params.evidence_id }),
            expected_version: None,
            effects: vec![GovernanceEffect::Tombstone {
                evidence_id: params.evidence_id.clone(),
                reason: TombstoneReason::DpdpErasure,
            }],
            resource_type: "evidence",
            resource_id: params.evidence_id.clone(),
            audit_payload: json!({ "reason": TombstoneReason::DpdpErasure.as_str() }),
            outcome: json!({ "evidence_id": params.evidence_id, "reason": "dpdp_erasure" }),
            live: None,
        })
    }

    /// The candidate set is frozen at proposal by its cutoff: approval
    /// tombstones exactly the untombstoned evidence older than that cutoff,
    /// and fails if the set differs from the one approved.
    async fn prepare_apply_retention(
        &self,
        cutoff: Option<DateTime<Utc>>,
    ) -> Result<Prepared, ApiError> {
        let days = self
            .retention
            .get_settings()
            .await
            .map_err(super::map_retention_error)?
            .evidence_retention_days;
        let proposing = cutoff.is_none();
        let cutoff = cutoff.unwrap_or_else(|| {
            let cutoff = Utc::now() - chrono::Duration::days(i64::from(days));
            // Whole seconds, so the cutoff round-trips exactly through JSON.
            DateTime::from_timestamp(cutoff.timestamp(), 0).unwrap_or(cutoff)
        });
        let mut ids = match self
            .retention
            .candidates(cutoff)
            .await
            .map_err(super::map_retention_error)?
        {
            Some(ids) => ids,
            None => self.memory_candidates(cutoff).await?,
        };
        ids.sort();
        if proposing && ids.is_empty() {
            return Err(ApiError::BadRequest(
                "no evidence is older than the retention period".into(),
            ));
        }
        Ok(Prepared {
            params: json!({}),
            binding: json!({
                "cutoff": cutoff,
                "candidate_count": ids.len(),
                "candidates_sha256": evidence_set_digest(&ids),
            }),
            expected_version: None,
            effects: vec![GovernanceEffect::TombstoneSet {
                cutoff,
                evidence_ids: ids.clone(),
            }],
            resource_type: "tenant_settings",
            resource_id: "retention".into(),
            audit_payload: json!({
                "cutoff": cutoff,
                "tombstoned_count": ids.len(),
                "candidates_sha256": evidence_set_digest(&ids),
            }),
            outcome: json!({ "tombstoned_count": ids.len(), "evidence_ids": ids }),
            live: None,
        })
    }

    async fn memory_candidates(&self, cutoff: DateTime<Utc>) -> Result<Vec<String>, ApiError> {
        let events = self.memory_events_snapshot()?.unwrap_or_default();
        let mut ids = Vec::new();
        for event in events.into_iter().filter(|e| e.evaluated_at < cutoff) {
            if !self
                .retention
                .is_tombstoned(&event.evidence_id)
                .await
                .map_err(super::map_retention_error)?
            {
                ids.push(event.evidence_id);
            }
        }
        Ok(ids)
    }
}

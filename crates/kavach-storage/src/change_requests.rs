//! Maker-checker change requests (ADR-009).
//!
//! A proposal freezes everything the approver approves: the parameters, the
//! state it was computed against (`binding`) and a `change_digest` over both.
//! Approval applies the change in one step: the request is re-checked under
//! lock (still pending, digest echoed, not expired, runtime pointer version
//! unchanged), the effect is written, the audit row appended and the request
//! marked applied — atomically in Postgres, under one mutex in memory.

use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::admin::{AuditInsert, MemoryAdminStore, ModelState, RuntimePointers};
use crate::retention::{MemoryRetentionStore, TombstoneReason};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    ActivatePack,
    RollbackPack,
    UpdateModel,
    UpdateRetention,
    EraseEvidence,
    ApplyRetention,
    ActivateModel,
}

impl ChangeKind {
    pub const ALL: [Self; 7] = [
        Self::ActivatePack,
        Self::RollbackPack,
        Self::UpdateModel,
        Self::UpdateRetention,
        Self::EraseEvidence,
        Self::ApplyRetention,
        Self::ActivateModel,
    ];

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ActivatePack => "activate_pack",
            Self::RollbackPack => "rollback_pack",
            Self::UpdateModel => "update_model",
            Self::UpdateRetention => "update_retention",
            Self::EraseEvidence => "erase_evidence",
            Self::ApplyRetention => "apply_retention",
            Self::ActivateModel => "activate_model",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeStatus {
    Pending,
    Applied,
    Failed,
    Rejected,
    Cancelled,
    Expired,
}

impl ChangeStatus {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Applied => "applied",
            Self::Failed => "failed",
            Self::Rejected => "rejected",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        [
            Self::Pending,
            Self::Applied,
            Self::Failed,
            Self::Rejected,
            Self::Cancelled,
            Self::Expired,
        ]
        .into_iter()
        .find(|status| status.as_str() == value)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeRequest {
    pub id: String,
    pub tenant_id: String,
    pub kind: ChangeKind,
    pub params: Value,
    pub binding: Value,
    pub change_digest: String,
    pub reason: Option<String>,
    /// Display id of the proposer (the Cedar principal id).
    pub proposer: String,
    /// Source-qualified identity used for the distinct-approver check.
    pub proposer_key: String,
    pub status: ChangeStatus,
    pub decided_by: Option<String>,
    pub decided_by_key: Option<String>,
    pub outcome: Option<Value>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub decided_at: Option<DateTime<Utc>>,
}

/// What an approved change writes, inside the approval transaction.
#[derive(Debug, Clone)]
pub enum GovernanceEffect {
    /// No stored state (the change lives in the runtime only, e.g. model
    /// mode until the governed model record lands); audit and status only.
    None,
    SetPointers(RuntimePointers),
    /// Governed status and mode of a model (ADR-010).
    SetModelState(ModelState),
    /// Refused when the stored value is no longer `expected_current`.
    SetRetentionDays {
        days: u32,
        expected_current: u32,
    },
    Tombstone {
        evidence_id: String,
        reason: TombstoneReason,
    },
    /// Tombstones exactly the set frozen at proposal. Refused when any of
    /// them is already tombstoned or (Postgres) the set of untombstoned
    /// evidence older than `cutoff` differs.
    TombstoneSet {
        cutoff: DateTime<Utc>,
        evidence_ids: Vec<String>,
    },
}

#[derive(Debug, Clone)]
pub struct ApprovalCommit {
    pub request_id: String,
    pub change_digest: String,
    pub approver: String,
    pub approver_key: String,
    /// Runtime pointer version the change was computed against; `None` for
    /// changes that do not depend on the runtime (retention, erasure).
    pub expected_pointer_version: Option<i64>,
    /// Written in order, in one transaction.
    pub effects: Vec<GovernanceEffect>,
    pub audit: AuditInsert,
    pub outcome: Value,
    pub now: DateTime<Utc>,
}

/// A conditional close of a pending request (reject, cancel, expire, fail).
#[derive(Debug, Clone)]
pub struct CloseRequest {
    pub request_id: String,
    pub status: ChangeStatus,
    pub by: String,
    pub by_key: String,
    pub outcome: Value,
    pub audit: AuditInsert,
    pub now: DateTime<Utc>,
}

#[derive(Debug, thiserror::Error)]
pub enum ChangeStoreError {
    #[error("change request not found: {0}")]
    NotFound(String),
    #[error("change request is not pending")]
    NotPending(Box<ChangeRequest>),
    #[error("change_digest does not match the request")]
    DigestMismatch,
    #[error("change request expired")]
    Expired(Box<ChangeRequest>),
    /// The state the request was bound to changed; the request is now failed.
    #[error("change request failed: {reason}")]
    Stale {
        reason: String,
        request: Box<ChangeRequest>,
    },
    #[error("change store io: {0}")]
    Io(String),
}

fn io<E: std::fmt::Display>(err: E) -> ChangeStoreError {
    ChangeStoreError::Io(err.to_string())
}

pub enum ChangeRequestBackend {
    Memory(Arc<MemoryChangeStore>),
    Postgres(crate::postgres::PostgresChangeStore),
}

impl ChangeRequestBackend {
    pub async fn create(
        &self,
        request: &ChangeRequest,
        audit: AuditInsert,
    ) -> Result<(), ChangeStoreError> {
        match self {
            Self::Memory(store) => store.create(request, audit),
            Self::Postgres(store) => store.create(request, &audit).await,
        }
    }

    pub async fn get(&self, id: &str) -> Result<ChangeRequest, ChangeStoreError> {
        match self {
            Self::Memory(store) => store.get(id),
            Self::Postgres(store) => store.get(id).await,
        }
    }

    pub async fn list(
        &self,
        status: Option<ChangeStatus>,
        limit: u32,
    ) -> Result<Vec<ChangeRequest>, ChangeStoreError> {
        match self {
            Self::Memory(store) => store.list(status, limit),
            Self::Postgres(store) => store.list(status, i64::from(limit)).await,
        }
    }

    pub async fn close(&self, close: CloseRequest) -> Result<ChangeRequest, ChangeStoreError> {
        match self {
            Self::Memory(store) => store.close(close),
            Self::Postgres(store) => store.close(&close).await,
        }
    }

    pub async fn commit_approval(
        &self,
        commit: ApprovalCommit,
    ) -> Result<ChangeRequest, ChangeStoreError> {
        match self {
            Self::Memory(store) => store.commit_approval(commit),
            Self::Postgres(store) => store.commit_approval(commit).await,
        }
    }
}

/// Development store; one mutex serializes every decision.
pub struct MemoryChangeStore {
    requests: Mutex<Vec<ChangeRequest>>,
    admin: Arc<MemoryAdminStore>,
    retention: Arc<MemoryRetentionStore>,
}

impl MemoryChangeStore {
    #[must_use]
    pub fn new(admin: Arc<MemoryAdminStore>, retention: Arc<MemoryRetentionStore>) -> Self {
        Self {
            requests: Mutex::new(Vec::new()),
            admin,
            retention,
        }
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Vec<ChangeRequest>>, ChangeStoreError> {
        self.requests
            .lock()
            .map_err(|_| ChangeStoreError::Io("lock poisoned".into()))
    }

    fn create(&self, request: &ChangeRequest, audit: AuditInsert) -> Result<(), ChangeStoreError> {
        let mut requests = self.lock()?;
        self.admin.append_audit(audit).map_err(io)?;
        requests.push(request.clone());
        Ok(())
    }

    fn get(&self, id: &str) -> Result<ChangeRequest, ChangeStoreError> {
        self.lock()?
            .iter()
            .find(|request| request.id == id)
            .cloned()
            .ok_or_else(|| ChangeStoreError::NotFound(id.into()))
    }

    fn list(
        &self,
        status: Option<ChangeStatus>,
        limit: u32,
    ) -> Result<Vec<ChangeRequest>, ChangeStoreError> {
        Ok(self
            .lock()?
            .iter()
            .rev()
            .filter(|request| status.is_none_or(|s| request.status == s))
            .take(limit as usize)
            .cloned()
            .collect())
    }

    fn decide(
        &self,
        request: &mut ChangeRequest,
        close: CloseRequest,
    ) -> Result<(), ChangeStoreError> {
        self.admin.append_audit(close.audit).map_err(io)?;
        request.status = close.status;
        request.decided_by = Some(close.by);
        request.decided_by_key = Some(close.by_key);
        request.outcome = Some(close.outcome);
        request.decided_at = Some(close.now);
        Ok(())
    }

    fn close(&self, close: CloseRequest) -> Result<ChangeRequest, ChangeStoreError> {
        let mut requests = self.lock()?;
        let request = requests
            .iter_mut()
            .find(|request| request.id == close.request_id)
            .ok_or_else(|| ChangeStoreError::NotFound(close.request_id.clone()))?;
        if request.status != ChangeStatus::Pending {
            return Err(ChangeStoreError::NotPending(Box::new(request.clone())));
        }
        self.decide(request, close)?;
        Ok(request.clone())
    }

    fn commit_approval(&self, commit: ApprovalCommit) -> Result<ChangeRequest, ChangeStoreError> {
        let mut requests = self.lock()?;
        let request = requests
            .iter_mut()
            .find(|request| request.id == commit.request_id)
            .ok_or_else(|| ChangeStoreError::NotFound(commit.request_id.clone()))?;
        if request.status != ChangeStatus::Pending {
            return Err(ChangeStoreError::NotPending(Box::new(request.clone())));
        }
        if request.change_digest != commit.change_digest {
            return Err(ChangeStoreError::DigestMismatch);
        }
        let terminal = |request: &ChangeRequest, status: ChangeStatus, reason: &str| CloseRequest {
            request_id: request.id.clone(),
            status,
            by: commit.approver.clone(),
            by_key: commit.approver_key.clone(),
            outcome: serde_json::json!({ "reason": reason }),
            audit: decision_audit(
                request,
                &format!("change_request_{}", status.as_str()),
                &commit.approver,
                Some(reason),
            ),
            now: commit.now,
        };
        if request.expires_at <= commit.now {
            let close = terminal(request, ChangeStatus::Expired, "expired");
            self.decide(request, close)?;
            return Err(ChangeStoreError::Expired(Box::new(request.clone())));
        }

        let version = self
            .admin
            .get_runtime_pointers()
            .map_err(io)?
            .map_or(0, |p| p.version);
        let stale = match commit.expected_pointer_version {
            Some(expected) if expected != version => Some(format!(
                "stale_baseline: runtime pointer version {version}, request bound to {expected}"
            )),
            _ => commit
                .effects
                .iter()
                .map(|effect| self.check_effect(effect))
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .flatten()
                .next(),
        };
        if let Some(reason) = stale {
            let close = terminal(request, ChangeStatus::Failed, &reason);
            self.decide(request, close)?;
            return Err(ChangeStoreError::Stale {
                reason,
                request: Box::new(request.clone()),
            });
        }

        for effect in &commit.effects {
            self.apply_effect(effect, &request.proposer, &commit.approver)?;
        }
        let close = CloseRequest {
            request_id: request.id.clone(),
            status: ChangeStatus::Applied,
            by: commit.approver,
            by_key: commit.approver_key,
            outcome: commit.outcome,
            audit: commit.audit,
            now: commit.now,
        };
        self.decide(request, close)?;
        Ok(request.clone())
    }

    fn apply_effect(
        &self,
        effect: &GovernanceEffect,
        proposer: &str,
        approver: &str,
    ) -> Result<(), ChangeStoreError> {
        match effect {
            GovernanceEffect::None => {}
            GovernanceEffect::SetPointers(pointers) => {
                self.admin
                    .set_runtime_pointers(pointers.clone())
                    .map_err(io)?;
            }
            GovernanceEffect::SetModelState(state) => {
                self.admin.set_model_state(state.clone()).map_err(io)?;
            }
            GovernanceEffect::SetRetentionDays { days, .. } => {
                self.retention
                    .set_settings(*days, proposer, approver)
                    .map_err(io)?;
            }
            GovernanceEffect::Tombstone {
                evidence_id,
                reason,
            } => {
                self.retention
                    .tombstone(evidence_id, *reason, proposer, approver)
                    .map_err(io)?;
            }
            GovernanceEffect::TombstoneSet { evidence_ids, .. } => {
                for evidence_id in evidence_ids {
                    self.retention
                        .tombstone(evidence_id, TombstoneReason::Retention, proposer, approver)
                        .map_err(io)?;
                }
            }
        }
        Ok(())
    }

    /// Memory mode cannot re-derive retention candidates (the API holds the
    /// events); it checks that nothing in the set was tombstoned meanwhile.
    fn check_effect(&self, effect: &GovernanceEffect) -> Result<Option<String>, ChangeStoreError> {
        let ids: Vec<&String> = match effect {
            GovernanceEffect::SetRetentionDays {
                expected_current, ..
            } => {
                let current = self
                    .retention
                    .get_settings()
                    .map_err(io)?
                    .evidence_retention_days;
                return Ok((current != *expected_current).then(|| {
                    format!("retention changed: now {current} days, request bound to {expected_current}")
                }));
            }
            GovernanceEffect::Tombstone { evidence_id, .. } => vec![evidence_id],
            GovernanceEffect::TombstoneSet { evidence_ids, .. } => evidence_ids.iter().collect(),
            _ => return Ok(None),
        };
        for id in ids {
            if self.retention.is_tombstoned(id).map_err(io)? {
                return Ok(Some(format!("evidence already tombstoned: {id}")));
            }
        }
        Ok(None)
    }
}

/// Audit row for a request decision (`change_request_*`).
#[must_use]
pub fn decision_audit(
    request: &ChangeRequest,
    action: &str,
    decided_by: &str,
    reason: Option<&str>,
) -> AuditInsert {
    AuditInsert {
        action: action.into(),
        resource_type: "change_request".into(),
        resource_id: request.id.clone(),
        actor_principal: request.proposer.clone(),
        approver_principal: decided_by.into(),
        payload: serde_json::json!({
            "kind": request.kind.as_str(),
            "change_digest": request.change_digest,
            "reason": reason,
        }),
    }
}

/// SHA-256 over the sorted evidence ids, one per line (retention binding).
#[must_use]
pub fn evidence_set_digest(ids: &[String]) -> String {
    use sha2::{Digest, Sha256};
    let mut sorted: Vec<&String> = ids.iter().collect();
    sorted.sort();
    let mut hasher = Sha256::new();
    for id in sorted {
        hasher.update(id.as_bytes());
        hasher.update(b"\n");
    }
    format!("sha256:{:x}", hasher.finalize())
}

use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{PgPool, Postgres, Transaction};

use super::admin::{insert_audit, upsert_pointers};
use crate::change_requests::{
    decision_audit, ApprovalCommit, ChangeKind, ChangeRequest, ChangeStatus, ChangeStoreError,
    CloseRequest, GovernanceEffect,
};

const COLUMNS: &str = "id, tenant_id, kind, params, binding, change_digest, reason, proposer, \
    proposer_key, status, decided_by, decided_by_key, outcome, created_at, expires_at, decided_at";

#[derive(Clone)]
pub struct PostgresChangeStore {
    pool: PgPool,
}

fn io<E: std::fmt::Display>(err: E) -> ChangeStoreError {
    ChangeStoreError::Io(err.to_string())
}

impl PostgresChangeStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        request: &ChangeRequest,
        audit: &crate::admin::AuditInsert,
    ) -> Result<(), ChangeStoreError> {
        let mut tx = self.pool.begin().await.map_err(io)?;
        sqlx::query(
            "INSERT INTO change_requests (id, tenant_id, kind, params, binding, change_digest, \
                reason, proposer, proposer_key, status, created_at, expires_at) \
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'pending', $10, $11)",
        )
        .bind(&request.id)
        .bind(&request.tenant_id)
        .bind(request.kind.as_str())
        .bind(&request.params)
        .bind(&request.binding)
        .bind(&request.change_digest)
        .bind(&request.reason)
        .bind(&request.proposer)
        .bind(&request.proposer_key)
        .bind(request.created_at)
        .bind(request.expires_at)
        .execute(&mut *tx)
        .await
        .map_err(io)?;
        insert_audit(&mut *tx, audit).await.map_err(io)?;
        tx.commit().await.map_err(io)
    }

    pub async fn get(&self, id: &str) -> Result<ChangeRequest, ChangeStoreError> {
        let row = sqlx::query_as::<_, Row>(&format!(
            "SELECT {COLUMNS} FROM change_requests WHERE id = $1"
        ))
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(io)?;
        row.ok_or_else(|| ChangeStoreError::NotFound(id.into()))?
            .into_request()
    }

    pub async fn list(
        &self,
        status: Option<ChangeStatus>,
        limit: i64,
    ) -> Result<Vec<ChangeRequest>, ChangeStoreError> {
        let rows = sqlx::query_as::<_, Row>(&format!(
            "SELECT {COLUMNS} FROM change_requests \
            WHERE ($1::TEXT IS NULL OR status = $1) ORDER BY created_at DESC LIMIT $2"
        ))
        .bind(status.map(ChangeStatus::as_str))
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(io)?;
        rows.into_iter().map(Row::into_request).collect()
    }

    pub async fn close(&self, close: &CloseRequest) -> Result<ChangeRequest, ChangeStoreError> {
        let mut tx = self.pool.begin().await.map_err(io)?;
        let request = lock_pending(&mut tx, &close.request_id).await?;
        let closed = decide(
            &mut tx,
            &request.id,
            close.status,
            &close.by,
            &close.by_key,
            &close.outcome,
            close.now,
        )
        .await?;
        insert_audit(&mut *tx, &close.audit).await.map_err(io)?;
        tx.commit().await.map_err(io)?;
        Ok(closed)
    }

    pub async fn commit_approval(
        &self,
        commit: ApprovalCommit,
    ) -> Result<ChangeRequest, ChangeStoreError> {
        let mut tx = self.pool.begin().await.map_err(io)?;
        let request = lock_pending(&mut tx, &commit.request_id).await?;
        if request.change_digest != commit.change_digest {
            return Err(ChangeStoreError::DigestMismatch);
        }
        if request.expires_at <= commit.now {
            let expired = self
                .terminate(tx, &request, &commit, ChangeStatus::Expired, "expired")
                .await?;
            return Err(ChangeStoreError::Expired(Box::new(expired)));
        }

        // Lock order: change request row, then the pointer row.
        let version: i64 =
            sqlx::query_scalar("SELECT version FROM runtime_pointers WHERE id = 1 FOR UPDATE")
                .fetch_optional(&mut *tx)
                .await
                .map_err(io)?
                .unwrap_or(0);
        let stale = match commit.expected_pointer_version {
            Some(expected) if expected != version => Some(format!(
                "stale_baseline: runtime pointer version {version}, request bound to {expected}"
            )),
            _ => check_effect(&mut tx, &commit.effect).await?,
        };
        if let Some(reason) = stale {
            let failed = self
                .terminate(tx, &request, &commit, ChangeStatus::Failed, &reason)
                .await?;
            return Err(ChangeStoreError::Stale {
                reason,
                request: Box::new(failed),
            });
        }

        apply_effect(&mut tx, &commit.effect, &request.proposer, &commit.approver).await?;
        insert_audit(&mut *tx, &commit.audit).await.map_err(io)?;
        let applied = decide(
            &mut tx,
            &request.id,
            ChangeStatus::Applied,
            &commit.approver,
            &commit.approver_key,
            &commit.outcome,
            commit.now,
        )
        .await?;
        tx.commit().await.map_err(io)?;
        Ok(applied)
    }

    /// Records a terminal non-applied outcome and commits it.
    async fn terminate(
        &self,
        mut tx: Transaction<'_, Postgres>,
        request: &ChangeRequest,
        commit: &ApprovalCommit,
        status: ChangeStatus,
        reason: &str,
    ) -> Result<ChangeRequest, ChangeStoreError> {
        let closed = decide(
            &mut tx,
            &request.id,
            status,
            &commit.approver,
            &commit.approver_key,
            &serde_json::json!({ "reason": reason }),
            commit.now,
        )
        .await?;
        let action = format!("change_request_{}", status.as_str());
        insert_audit(
            &mut *tx,
            &decision_audit(request, &action, &commit.approver, Some(reason)),
        )
        .await
        .map_err(io)?;
        tx.commit().await.map_err(io)?;
        Ok(closed)
    }
}

async fn lock_pending(
    tx: &mut Transaction<'_, Postgres>,
    id: &str,
) -> Result<ChangeRequest, ChangeStoreError> {
    let request = sqlx::query_as::<_, Row>(&format!(
        "SELECT {COLUMNS} FROM change_requests WHERE id = $1 FOR UPDATE"
    ))
    .bind(id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(io)?
    .ok_or_else(|| ChangeStoreError::NotFound(id.into()))?
    .into_request()?;
    if request.status == ChangeStatus::Pending {
        Ok(request)
    } else {
        Err(ChangeStoreError::NotPending(Box::new(request)))
    }
}

async fn decide(
    tx: &mut Transaction<'_, Postgres>,
    id: &str,
    status: ChangeStatus,
    by: &str,
    by_key: &str,
    outcome: &Value,
    now: DateTime<Utc>,
) -> Result<ChangeRequest, ChangeStoreError> {
    sqlx::query_as::<_, Row>(&format!(
        "UPDATE change_requests SET status = $2, decided_by = $3, decided_by_key = $4, \
            outcome = $5, decided_at = $6 \
        WHERE id = $1 AND status = 'pending' RETURNING {COLUMNS}"
    ))
    .bind(id)
    .bind(status.as_str())
    .bind(by)
    .bind(by_key)
    .bind(outcome)
    .bind(now)
    .fetch_one(&mut **tx)
    .await
    .map_err(io)?
    .into_request()
}

/// Reads only; returns a reason when the effect can no longer apply as bound.
async fn check_effect(
    tx: &mut Transaction<'_, Postgres>,
    effect: &GovernanceEffect,
) -> Result<Option<String>, ChangeStoreError> {
    match effect {
        GovernanceEffect::SetRetentionDays {
            expected_current, ..
        } => {
            let current: i32 = sqlx::query_scalar(
                "SELECT evidence_retention_days FROM tenant_settings WHERE id = 1 FOR UPDATE",
            )
            .fetch_one(&mut **tx)
            .await
            .map_err(io)?;
            Ok((i64::from(current) != i64::from(*expected_current)).then(|| {
                format!("retention changed: now {current} days, request bound to {expected_current}")
            }))
        }
        GovernanceEffect::Tombstone { evidence_id, .. } => {
            let (exists, tombstoned): (bool, bool) = sqlx::query_as(
                "SELECT EXISTS(SELECT 1 FROM decision_events WHERE evidence_id = $1), \
                    EXISTS(SELECT 1 FROM evidence_tombstones WHERE evidence_id = $1)",
            )
            .bind(evidence_id)
            .fetch_one(&mut **tx)
            .await
            .map_err(io)?;
            Ok(match (exists, tombstoned) {
                (false, _) => Some(format!("evidence not found: {evidence_id}")),
                (true, true) => Some(format!("evidence already tombstoned: {evidence_id}")),
                (true, false) => None,
            })
        }
        GovernanceEffect::TombstoneSet {
            cutoff,
            evidence_ids,
        } => {
            let current = retention_candidates(&mut **tx, *cutoff).await?;
            let mut expected = evidence_ids.clone();
            expected.sort();
            Ok((current != expected).then(|| {
                format!(
                    "retention set changed: {} candidates now, {} approved",
                    current.len(),
                    expected.len()
                )
            }))
        }
        _ => Ok(None),
    }
}

async fn apply_effect(
    tx: &mut Transaction<'_, Postgres>,
    effect: &GovernanceEffect,
    proposer: &str,
    approver: &str,
) -> Result<(), ChangeStoreError> {
    match effect {
        GovernanceEffect::None => {}
        GovernanceEffect::SetPointers(pointers) => {
            upsert_pointers(&mut **tx, pointers).await.map_err(io)?;
        }
        GovernanceEffect::SetRetentionDays { days, .. } => {
            sqlx::query(
                "UPDATE tenant_settings SET evidence_retention_days = $1, updated_at = NOW(), \
                    updated_by = $2, approved_by = $3 WHERE id = 1",
            )
            .bind(i32::try_from(*days).unwrap_or(i32::MAX))
            .bind(proposer)
            .bind(approver)
            .execute(&mut **tx)
            .await
            .map_err(io)?;
        }
        GovernanceEffect::Tombstone {
            evidence_id,
            reason,
        } => {
            insert_tombstones(
                tx,
                std::slice::from_ref(evidence_id),
                reason.as_str(),
                proposer,
                approver,
            )
            .await?;
        }
        GovernanceEffect::TombstoneSet { evidence_ids, .. } => {
            insert_tombstones(tx, evidence_ids, "retention", proposer, approver).await?;
        }
    }
    Ok(())
}

async fn insert_tombstones(
    tx: &mut Transaction<'_, Postgres>,
    evidence_ids: &[String],
    reason: &str,
    proposer: &str,
    approver: &str,
) -> Result<(), ChangeStoreError> {
    sqlx::query(
        "INSERT INTO evidence_tombstones (evidence_id, reason, actor_principal, approver_principal) \
        SELECT id, $2, $3, $4 FROM UNNEST($1::TEXT[]) AS id",
    )
    .bind(evidence_ids)
    .bind(reason)
    .bind(proposer)
    .bind(approver)
    .execute(&mut **tx)
    .await
    .map_err(io)?;
    Ok(())
}

/// Untombstoned evidence evaluated before `cutoff`, sorted by id.
pub(crate) async fn retention_candidates<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    cutoff: DateTime<Utc>,
) -> Result<Vec<String>, ChangeStoreError> {
    sqlx::query_scalar(
        "SELECT de.evidence_id FROM decision_events de \
        WHERE de.evaluated_at < $1 \
          AND NOT EXISTS (SELECT 1 FROM evidence_tombstones t WHERE t.evidence_id = de.evidence_id) \
        ORDER BY de.evidence_id",
    )
    .bind(cutoff)
    .fetch_all(executor)
    .await
    .map_err(io)
}

#[derive(sqlx::FromRow)]
struct Row {
    id: String,
    tenant_id: String,
    kind: String,
    params: Value,
    binding: Value,
    change_digest: String,
    reason: Option<String>,
    proposer: String,
    proposer_key: String,
    status: String,
    decided_by: Option<String>,
    decided_by_key: Option<String>,
    outcome: Option<Value>,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    decided_at: Option<DateTime<Utc>>,
}

impl Row {
    fn into_request(self) -> Result<ChangeRequest, ChangeStoreError> {
        Ok(ChangeRequest {
            kind: ChangeKind::parse(&self.kind)
                .ok_or_else(|| io(format!("unknown change kind {}", self.kind)))?,
            status: ChangeStatus::parse(&self.status)
                .ok_or_else(|| io(format!("unknown change status {}", self.status)))?,
            id: self.id,
            tenant_id: self.tenant_id,
            params: self.params,
            binding: self.binding,
            change_digest: self.change_digest,
            reason: self.reason,
            proposer: self.proposer,
            proposer_key: self.proposer_key,
            decided_by: self.decided_by,
            decided_by_key: self.decided_by_key,
            outcome: self.outcome,
            created_at: self.created_at,
            expires_at: self.expires_at,
            decided_at: self.decided_at,
        })
    }
}

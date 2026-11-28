//! PostgreSQL adapter for completed human-review approvals.

use chrono::{DateTime, Utc};
use kavach_ports::{PortError, ReviewApprovalRecord, ReviewApprovalStore, ReviewReleaseRecord};
use sqlx::{PgPool, Row};

#[derive(Clone)]
pub struct PostgresReviewApprovalStore {
    pool: PgPool,
}

impl PostgresReviewApprovalStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl ReviewApprovalStore for PostgresReviewApprovalStore {
    async fn insert(&self, record: ReviewApprovalRecord) -> Result<(), PortError> {
        record.validate()?;
        let result = sqlx::query(
            "INSERT INTO human_review_approvals \
                (tenant_id, approval_id, review_record_id, execution_id, action_hash, \
                 rendered_action, approver, step_up_ref, decision, \
                 single_use_credential_id, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(&record.tenant_id)
        .bind(&record.approval_id)
        .bind(&record.review_record_id)
        .bind(&record.execution_id)
        .bind(&record.action_hash)
        .bind(&record.rendered_action)
        .bind(&record.approver)
        .bind(&record.step_up_ref)
        .bind(record.decision.as_str())
        .bind(&record.single_use_credential_id)
        .bind(record.expires)
        .execute(&self.pool)
        .await;

        result.map(|_| ()).map_err(|error| {
            if error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .as_deref()
                == Some("23505")
            {
                PortError::rejected("review approval or credential id already exists")
            } else {
                PortError::unavailable("review approval storage is unavailable")
            }
        })
    }

    async fn release(
        &self,
        tenant_id: &str,
        approval_id: &str,
        execution_id: &str,
        action_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<ReviewReleaseRecord>, PortError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| PortError::unavailable("review approval storage is unavailable"))?;
        let row = sqlx::query(
            "UPDATE human_review_approvals \
             SET consumed_at = $4 \
             WHERE tenant_id = $1 AND approval_id = $2 AND action_hash = $3 \
               AND execution_id = $5 AND decision = 'approve' \
               AND expires_at > $4 AND consumed_at IS NULL \
             RETURNING review_record_id, approver, single_use_credential_id",
        )
        .bind(tenant_id)
        .bind(approval_id)
        .bind(action_hash)
        .bind(now)
        .bind(execution_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| PortError::unavailable("review approval storage is unavailable"))?;
        if let Some(row) = row {
            let release = ReviewReleaseRecord {
                tenant_id: tenant_id.to_owned(),
                approval_id: approval_id.to_owned(),
                review_record_id: row
                    .try_get("review_record_id")
                    .map_err(|_| PortError::unavailable("stored review approval is malformed"))?,
                execution_id: execution_id.to_owned(),
                action_hash: action_hash.to_owned(),
                single_use_credential_id: row
                    .try_get("single_use_credential_id")
                    .map_err(|_| PortError::unavailable("stored review approval is malformed"))?,
                approver: row
                    .try_get("approver")
                    .map_err(|_| PortError::unavailable("stored review approval is malformed"))?,
                released_at: now,
            };
            release.validate()?;
            sqlx::query(
                "INSERT INTO human_review_releases \
                    (tenant_id, execution_id, approval_id, review_record_id, action_hash, \
                     single_use_credential_id, approver, released_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            )
            .bind(&release.tenant_id)
            .bind(&release.execution_id)
            .bind(&release.approval_id)
            .bind(&release.review_record_id)
            .bind(&release.action_hash)
            .bind(&release.single_use_credential_id)
            .bind(&release.approver)
            .bind(release.released_at)
            .execute(&mut *tx)
            .await
            .map_err(|_| PortError::unavailable("human-review release could not be recorded"))?;
            tx.commit().await.map_err(|_| {
                PortError::unavailable("human-review release could not be committed")
            })?;
            return Ok(Some(release));
        }

        let existing = sqlx::query(
            "SELECT tenant_id, approval_id, review_record_id, execution_id, action_hash, \
                    single_use_credential_id, approver, released_at \
             FROM human_review_releases \
             WHERE tenant_id = $1 AND execution_id = $2 AND approval_id = $3 \
               AND action_hash = $4",
        )
        .bind(tenant_id)
        .bind(execution_id)
        .bind(approval_id)
        .bind(action_hash)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| PortError::unavailable("review release storage is unavailable"))?;
        tx.commit()
            .await
            .map_err(|_| PortError::unavailable("review release storage is unavailable"))?;
        existing.as_ref().map(stored_release).transpose()
    }
}

/// A release row read back from `human_review_releases`, validated.
fn stored_release(row: &sqlx::postgres::PgRow) -> Result<ReviewReleaseRecord, PortError> {
    let release = ReviewReleaseRecord {
        tenant_id: row
            .try_get("tenant_id")
            .map_err(|_| PortError::unavailable("stored review release is malformed"))?,
        approval_id: row
            .try_get("approval_id")
            .map_err(|_| PortError::unavailable("stored review release is malformed"))?,
        review_record_id: row
            .try_get("review_record_id")
            .map_err(|_| PortError::unavailable("stored review release is malformed"))?,
        execution_id: row
            .try_get("execution_id")
            .map_err(|_| PortError::unavailable("stored review release is malformed"))?,
        action_hash: row
            .try_get("action_hash")
            .map_err(|_| PortError::unavailable("stored review release is malformed"))?,
        single_use_credential_id: row
            .try_get("single_use_credential_id")
            .map_err(|_| PortError::unavailable("stored review release is malformed"))?,
        approver: row
            .try_get("approver")
            .map_err(|_| PortError::unavailable("stored review release is malformed"))?,
        released_at: row
            .try_get("released_at")
            .map_err(|_| PortError::unavailable("stored review release is malformed"))?,
    };
    release.validate()?;
    Ok(release)
}

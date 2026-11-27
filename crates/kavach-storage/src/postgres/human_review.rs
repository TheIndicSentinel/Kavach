//! PostgreSQL adapter for completed human-review approvals.

use chrono::{DateTime, Utc};
use kavach_ports::{PortError, ReviewApprovalRecord, ReviewApprovalStore, ReviewDecision};
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
                (tenant_id, approval_id, action_hash, rendered_action, approver, \
                 step_up_ref, decision, single_use_credential_id, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(&record.tenant_id)
        .bind(&record.approval_id)
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

    async fn consume(
        &self,
        tenant_id: &str,
        approval_id: &str,
        action_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<ReviewApprovalRecord>, PortError> {
        let row = sqlx::query(
            "UPDATE human_review_approvals \
             SET consumed_at = $4 \
             WHERE tenant_id = $1 AND approval_id = $2 AND action_hash = $3 \
               AND decision = 'approve' AND expires_at > $4 AND consumed_at IS NULL \
             RETURNING tenant_id, approval_id, action_hash, rendered_action, approver, \
                       step_up_ref, decision, single_use_credential_id, expires_at",
        )
        .bind(tenant_id)
        .bind(approval_id)
        .bind(action_hash)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| PortError::unavailable("review approval storage is unavailable"))?;

        row.map(|row| {
            let decision = row
                .try_get::<String, _>("decision")
                .map_err(|_| PortError::unavailable("stored review approval is malformed"))?;
            let decision = ReviewDecision::parse(&decision)
                .ok_or_else(|| PortError::unavailable("stored review decision is unknown"))?;
            let record = ReviewApprovalRecord {
                tenant_id: row
                    .try_get("tenant_id")
                    .map_err(|_| PortError::unavailable("stored review approval is malformed"))?,
                approval_id: row
                    .try_get("approval_id")
                    .map_err(|_| PortError::unavailable("stored review approval is malformed"))?,
                action_hash: row
                    .try_get("action_hash")
                    .map_err(|_| PortError::unavailable("stored review approval is malformed"))?,
                rendered_action: row
                    .try_get("rendered_action")
                    .map_err(|_| PortError::unavailable("stored review approval is malformed"))?,
                approver: row
                    .try_get("approver")
                    .map_err(|_| PortError::unavailable("stored review approval is malformed"))?,
                step_up_ref: row
                    .try_get("step_up_ref")
                    .map_err(|_| PortError::unavailable("stored review approval is malformed"))?,
                decision,
                single_use_credential_id: row
                    .try_get("single_use_credential_id")
                    .map_err(|_| PortError::unavailable("stored review approval is malformed"))?,
                expires: row
                    .try_get("expires_at")
                    .map_err(|_| PortError::unavailable("stored review approval is malformed"))?,
            };
            record
                .validate()
                .map_err(|_| PortError::unavailable("stored review approval is malformed"))?;
            Ok(record)
        })
        .transpose()
    }
}

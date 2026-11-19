//! PostgreSQL adapter for one-use server-side step-up challenge state.

use chrono::{DateTime, Utc};
use kavach_ports::{PortError, StepUpChallengeState, StepUpChallengeStore};
use sqlx::{PgPool, Row};

#[derive(Clone)]
pub struct PostgresStepUpChallengeStore {
    pool: PgPool,
}

impl PostgresStepUpChallengeStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl StepUpChallengeStore for PostgresStepUpChallengeStore {
    async fn insert(&self, state: StepUpChallengeState) -> Result<(), PortError> {
        state.validate(state.issued_at)?;
        let result = sqlx::query(
            "INSERT INTO human_review_step_up_challenges \
                (challenge_id, state_hash, nonce_hash, tenant_id, principal_key, action_hash, \
                 issued_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(&state.challenge_id)
        .bind(&state.state_hash)
        .bind(&state.nonce_hash)
        .bind(&state.tenant_id)
        .bind(&state.principal_key)
        .bind(&state.action_hash)
        .bind(state.issued_at)
        .bind(state.expires_at)
        .execute(&self.pool)
        .await;

        result.map(|_| ()).map_err(|error| {
            if error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .as_deref()
                == Some("23505")
            {
                PortError::rejected("step-up challenge already exists")
            } else {
                PortError::unavailable("step-up challenge storage is unavailable")
            }
        })
    }

    async fn get_live(
        &self,
        tenant_id: &str,
        state_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<StepUpChallengeState>, PortError> {
        let row = sqlx::query(
            "SELECT challenge_id, state_hash, nonce_hash, tenant_id, principal_key, action_hash, \
                    issued_at, expires_at \
             FROM human_review_step_up_challenges \
             WHERE tenant_id = $1 AND state_hash = $2 AND issued_at <= $3 AND expires_at > $3 \
               AND consumed_at IS NULL",
        )
        .bind(tenant_id)
        .bind(state_hash)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| PortError::unavailable("step-up challenge storage is unavailable"))?;

        row.as_ref().map(read_state).transpose()
    }

    async fn consume(
        &self,
        tenant_id: &str,
        state_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<StepUpChallengeState>, PortError> {
        let row = sqlx::query(
            "UPDATE human_review_step_up_challenges \
             SET consumed_at = $3 \
             WHERE tenant_id = $1 AND state_hash = $2 AND issued_at <= $3 AND expires_at > $3 \
               AND consumed_at IS NULL \
             RETURNING challenge_id, state_hash, nonce_hash, tenant_id, principal_key, \
                       action_hash, issued_at, expires_at",
        )
        .bind(tenant_id)
        .bind(state_hash)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| PortError::unavailable("step-up challenge storage is unavailable"))?;

        row.as_ref().map(read_state).transpose()
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> Result<u64, PortError> {
        sqlx::query("DELETE FROM human_review_step_up_challenges WHERE expires_at <= $1")
            .bind(now)
            .execute(&self.pool)
            .await
            .map(|result| result.rows_affected())
            .map_err(|_| PortError::unavailable("step-up challenge storage is unavailable"))
    }
}

fn read_state(row: &sqlx::postgres::PgRow) -> Result<StepUpChallengeState, PortError> {
    let state = StepUpChallengeState {
        challenge_id: row
            .try_get("challenge_id")
            .map_err(|_| PortError::unavailable("stored step-up challenge is malformed"))?,
        state_hash: row
            .try_get("state_hash")
            .map_err(|_| PortError::unavailable("stored step-up challenge is malformed"))?,
        nonce_hash: row
            .try_get("nonce_hash")
            .map_err(|_| PortError::unavailable("stored step-up challenge is malformed"))?,
        tenant_id: row
            .try_get("tenant_id")
            .map_err(|_| PortError::unavailable("stored step-up challenge is malformed"))?,
        principal_key: row
            .try_get("principal_key")
            .map_err(|_| PortError::unavailable("stored step-up challenge is malformed"))?,
        action_hash: row
            .try_get("action_hash")
            .map_err(|_| PortError::unavailable("stored step-up challenge is malformed"))?,
        issued_at: row
            .try_get("issued_at")
            .map_err(|_| PortError::unavailable("stored step-up challenge is malformed"))?,
        expires_at: row
            .try_get("expires_at")
            .map_err(|_| PortError::unavailable("stored step-up challenge is malformed"))?,
    };
    state
        .validate(state.issued_at)
        .map_err(|_| PortError::unavailable("stored step-up challenge is malformed"))?;
    Ok(state)
}

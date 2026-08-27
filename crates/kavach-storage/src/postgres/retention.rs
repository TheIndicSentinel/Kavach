use chrono::{DateTime, Utc};
use sqlx::PgPool;

use crate::retention::{
    RetentionApplyReport, RetentionSettings, RetentionStoreError, TombstoneReason, TombstoneRecord,
};

#[derive(Clone)]
pub struct PostgresRetentionStore {
    pool: PgPool,
}

impl PostgresRetentionStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn get_settings(&self) -> Result<RetentionSettings, RetentionStoreError> {
        let row = sqlx::query_as::<_, SettingsRow>(
            "SELECT evidence_retention_days, updated_at, updated_by, approved_by \
            FROM tenant_settings WHERE id = 1",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|err| RetentionStoreError::Io(err.to_string()))?;
        Ok(row.into_settings())
    }

    pub async fn set_settings(
        &self,
        evidence_retention_days: u32,
        actor: &str,
        approver: &str,
    ) -> Result<RetentionSettings, RetentionStoreError> {
        let row = sqlx::query_as::<_, SettingsRow>(
            "UPDATE tenant_settings \
            SET evidence_retention_days = $1, updated_at = NOW(), updated_by = $2, approved_by = $3 \
            WHERE id = 1 \
            RETURNING evidence_retention_days, updated_at, updated_by, approved_by",
        )
        .bind(i32::try_from(evidence_retention_days).unwrap_or(i32::MAX))
        .bind(actor)
        .bind(approver)
        .fetch_one(&self.pool)
        .await
        .map_err(|err| RetentionStoreError::Io(err.to_string()))?;
        Ok(row.into_settings())
    }

    pub async fn tombstone(
        &self,
        evidence_id: &str,
        reason: TombstoneReason,
        actor: &str,
        approver: &str,
    ) -> Result<TombstoneRecord, RetentionStoreError> {
        let exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM decision_events WHERE evidence_id = $1)",
        )
        .bind(evidence_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|err| RetentionStoreError::Io(err.to_string()))?;
        if !exists {
            return Err(RetentionStoreError::NotFound(evidence_id.into()));
        }

        let row = sqlx::query_as::<_, TombstoneRow>(
            "INSERT INTO evidence_tombstones \
                (evidence_id, reason, actor_principal, approver_principal) \
            VALUES ($1, $2, $3, $4) \
            ON CONFLICT (evidence_id) DO NOTHING \
            RETURNING evidence_id, reason, actor_principal, approver_principal, tombstoned_at",
        )
        .bind(evidence_id)
        .bind(reason.as_str())
        .bind(actor)
        .bind(approver)
        .fetch_optional(&self.pool)
        .await
        .map_err(|err| RetentionStoreError::Io(err.to_string()))?;

        row.map(TombstoneRow::into_record)
            .ok_or_else(|| RetentionStoreError::AlreadyTombstoned(evidence_id.into()))
    }

    pub async fn is_tombstoned(&self, evidence_id: &str) -> Result<bool, RetentionStoreError> {
        let exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM evidence_tombstones WHERE evidence_id = $1)",
        )
        .bind(evidence_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|err| RetentionStoreError::Io(err.to_string()))?;
        Ok(exists)
    }

    pub async fn list_tombstones(
        &self,
        limit: i64,
    ) -> Result<Vec<TombstoneRecord>, RetentionStoreError> {
        let rows = sqlx::query_as::<_, TombstoneRow>(
            "SELECT evidence_id, reason, actor_principal, approver_principal, tombstoned_at \
            FROM evidence_tombstones ORDER BY tombstoned_at DESC LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|err| RetentionStoreError::Io(err.to_string()))?;
        Ok(rows.into_iter().map(TombstoneRow::into_record).collect())
    }

    pub async fn apply_retention(
        &self,
        actor: &str,
        approver: &str,
    ) -> Result<RetentionApplyReport, RetentionStoreError> {
        let settings = self.get_settings().await?;
        let rows = sqlx::query_scalar::<_, String>(
            "INSERT INTO evidence_tombstones (evidence_id, reason, actor_principal, approver_principal) \
            SELECT de.evidence_id, 'retention', $1, $2 \
            FROM decision_events de \
            WHERE de.evaluated_at < NOW() - make_interval(days => $3) \
              AND NOT EXISTS ( \
                SELECT 1 FROM evidence_tombstones t WHERE t.evidence_id = de.evidence_id \
              ) \
            RETURNING evidence_id",
        )
        .bind(actor)
        .bind(approver)
        .bind(i32::try_from(settings.evidence_retention_days).unwrap_or(i32::MAX))
        .fetch_all(&self.pool)
        .await
        .map_err(|err| RetentionStoreError::Io(err.to_string()))?;

        Ok(RetentionApplyReport {
            tombstoned_count: rows.len(),
            evidence_ids: rows,
        })
    }
}

#[derive(sqlx::FromRow)]
struct SettingsRow {
    evidence_retention_days: i32,
    updated_at: DateTime<Utc>,
    updated_by: Option<String>,
    approved_by: Option<String>,
}

impl SettingsRow {
    fn into_settings(self) -> RetentionSettings {
        RetentionSettings {
            evidence_retention_days: u32::try_from(self.evidence_retention_days)
                .unwrap_or(u32::MAX),
            updated_at: self.updated_at,
            updated_by: self.updated_by,
            approved_by: self.approved_by,
        }
    }
}

#[derive(sqlx::FromRow)]
struct TombstoneRow {
    evidence_id: String,
    reason: String,
    actor_principal: String,
    approver_principal: String,
    tombstoned_at: DateTime<Utc>,
}

impl TombstoneRow {
    fn into_record(self) -> TombstoneRecord {
        TombstoneRecord {
            evidence_id: self.evidence_id,
            reason: TombstoneReason::parse(&self.reason).unwrap_or(TombstoneReason::DpdpErasure),
            actor_principal: self.actor_principal,
            approver_principal: self.approver_principal,
            tombstoned_at: self.tombstoned_at,
        }
    }
}

use chrono::{DateTime, Utc};
use kavach_evaluate::{EvaluateIncident, IncidentRecorder, IncidentWriteError};
use sqlx::PgPool;

use crate::incidents_store::{IncidentRecord, IncidentStoreError};

#[derive(Clone)]
pub struct PostgresIncidentStore {
    pool: PgPool,
    tenant_id: String,
}

impl PostgresIncidentStore {
    pub fn new(pool: PgPool) -> Self {
        Self::new_for_tenant(pool, "default")
    }

    pub fn new_for_tenant(pool: PgPool, tenant_id: &str) -> Self {
        Self {
            pool,
            tenant_id: tenant_id.into(),
        }
    }

    pub async fn list(&self, limit: i64) -> Result<Vec<IncidentRecord>, IncidentStoreError> {
        let rows = sqlx::query_as::<_, IncidentRow>(
            "SELECT id, tenant_id, correlation_id, model_id, reason, recorded_at \
            FROM evaluate_incidents WHERE tenant_id = $1 \
            ORDER BY recorded_at DESC LIMIT $2",
        )
        .bind(&self.tenant_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|err| IncidentStoreError::Io(err.to_string()))?;
        Ok(rows.into_iter().map(IncidentRow::into_record).collect())
    }

    fn record_sync(&self, incident: EvaluateIncident) -> Result<(), IncidentWriteError> {
        let pool = self.pool.clone();
        let tenant_id = self.tenant_id.clone();
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                sqlx::query(
                    "INSERT INTO evaluate_incidents (tenant_id, correlation_id, model_id, reason) VALUES ($1, $2, $3, $4)",
                )
                .bind(tenant_id)
                .bind(incident.correlation_id)
                .bind(incident.model_id)
                .bind(incident.reason)
                .execute(&pool)
                .await
                .map(|_| ())
                .map_err(|e| IncidentWriteError(e.to_string()))
            })
        })
    }
}

impl IncidentRecorder for PostgresIncidentStore {
    fn record(&mut self, incident: EvaluateIncident) -> Result<(), IncidentWriteError> {
        self.record_sync(incident)
    }
}

#[derive(sqlx::FromRow)]
struct IncidentRow {
    id: i64,
    tenant_id: String,
    correlation_id: String,
    model_id: String,
    reason: String,
    recorded_at: DateTime<Utc>,
}

impl IncidentRow {
    fn into_record(self) -> IncidentRecord {
        IncidentRecord {
            id: self.id,
            tenant_id: self.tenant_id,
            correlation_id: self.correlation_id,
            model_id: self.model_id,
            reason: self.reason,
            recorded_at: self.recorded_at,
        }
    }
}

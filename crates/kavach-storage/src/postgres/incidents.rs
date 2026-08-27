use chrono::{DateTime, Utc};
use kavach_evaluate::{EvaluateIncident, IncidentRecorder};
use sqlx::PgPool;

use crate::incidents_store::{IncidentRecord, IncidentStoreError};

#[derive(Clone)]
pub struct PostgresIncidentStore {
    pool: PgPool,
}

impl PostgresIncidentStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn list(&self, limit: i64) -> Result<Vec<IncidentRecord>, IncidentStoreError> {
        let rows = sqlx::query_as::<_, IncidentRow>(
            "SELECT id, correlation_id, model_id, reason, recorded_at \
            FROM evaluate_incidents ORDER BY recorded_at DESC LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|err| IncidentStoreError::Io(err.to_string()))?;
        Ok(rows.into_iter().map(IncidentRow::into_record).collect())
    }

    fn record_sync(&self, incident: EvaluateIncident) {
        let pool = self.pool.clone();
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                let _ = sqlx::query(
                    "INSERT INTO evaluate_incidents (correlation_id, model_id, reason) VALUES ($1, $2, $3)",
                )
                .bind(incident.correlation_id)
                .bind(incident.model_id)
                .bind(incident.reason)
                .execute(&pool)
                .await;
            });
        });
    }
}

impl IncidentRecorder for PostgresIncidentStore {
    fn record(&mut self, incident: EvaluateIncident) {
        self.record_sync(incident);
    }
}

#[derive(sqlx::FromRow)]
struct IncidentRow {
    id: i64,
    correlation_id: String,
    model_id: String,
    reason: String,
    recorded_at: DateTime<Utc>,
}

impl IncidentRow {
    fn into_record(self) -> IncidentRecord {
        IncidentRecord {
            id: self.id,
            correlation_id: self.correlation_id,
            model_id: self.model_id,
            reason: self.reason,
            recorded_at: self.recorded_at,
        }
    }
}

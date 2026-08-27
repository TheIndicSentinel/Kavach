use kavach_evaluate::{EvaluateIncident, IncidentRecorder};
use sqlx::PgPool;

#[derive(Clone)]
pub struct PostgresIncidentRecorder {
    pool: PgPool,
}

impl PostgresIncidentRecorder {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl IncidentRecorder for PostgresIncidentRecorder {
    fn record(&mut self, incident: EvaluateIncident) {
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

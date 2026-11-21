use std::future::Future;

use chrono::{DateTime, Utc};
use kavach_ports::{PortError, TaskTaint, TaskTaintSource, TaskTaintStore};
use sqlx::{PgPool, Row};

#[derive(Clone)]
pub struct PostgresTaskTaintStore {
    pool: PgPool,
}

impl PostgresTaskTaintStore {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    async fn get(&self, tenant_id: &str, mandate_id: &str) -> Result<Option<TaskTaint>, PortError> {
        let row = sqlx::query(
            "SELECT tenant_id, mandate_id, first_tainted_at, source \
             FROM agent_task_taint WHERE tenant_id = $1 AND mandate_id = $2",
        )
        .bind(tenant_id)
        .bind(mandate_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| PortError::unavailable(format!("task taint read failed: {error}")))?;

        row.map(|row| {
            let source: String = row.try_get("source").map_err(row_error)?;
            Ok(TaskTaint {
                tenant_id: row.try_get("tenant_id").map_err(row_error)?,
                mandate_id: row.try_get("mandate_id").map_err(row_error)?,
                first_tainted_at: row.try_get("first_tainted_at").map_err(row_error)?,
                source: parse_source(&source)?,
            })
        })
        .transpose()
    }
}

impl TaskTaintStore for PostgresTaskTaintStore {
    fn mark_tainted(
        &self,
        tenant_id: &str,
        mandate_id: &str,
        source: TaskTaintSource,
        at: DateTime<Utc>,
    ) -> impl Future<Output = Result<TaskTaint, PortError>> + Send {
        async move {
            sqlx::query(
                "INSERT INTO agent_task_taint (tenant_id, mandate_id, first_tainted_at, source) \
                 VALUES ($1, $2, $3, $4) ON CONFLICT (tenant_id, mandate_id) DO NOTHING",
            )
            .bind(tenant_id)
            .bind(mandate_id)
            .bind(at)
            .bind(source.as_str())
            .execute(&self.pool)
            .await
            .map_err(|error| PortError::unavailable(format!("task taint write failed: {error}")))?;

            self.get(tenant_id, mandate_id)
                .await?
                .ok_or_else(|| PortError::unavailable("task taint write was not visible"))
        }
    }

    fn get_taint(
        &self,
        tenant_id: &str,
        mandate_id: &str,
    ) -> impl Future<Output = Result<Option<TaskTaint>, PortError>> + Send {
        self.get(tenant_id, mandate_id)
    }
}

fn parse_source(value: &str) -> Result<TaskTaintSource, PortError> {
    match value {
        "governed_model_output" => Ok(TaskTaintSource::GovernedModelOutput),
        "external_untrusted" => Ok(TaskTaintSource::ExternalUntrusted),
        "user_content" => Ok(TaskTaintSource::UserContent),
        _ => Err(PortError::unavailable("task taint source is invalid")),
    }
}

fn row_error(error: sqlx::Error) -> PortError {
    PortError::unavailable(format!("task taint row is invalid: {error}"))
}

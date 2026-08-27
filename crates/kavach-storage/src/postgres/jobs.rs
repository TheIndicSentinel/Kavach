use chrono::{DateTime, Utc};
use kavach_domain::GovernanceMode;
use sqlx::PgPool;
use uuid::Uuid;

use crate::jobs_store::{BatchJobRecord, JobQueryError};

#[derive(Debug, Clone)]
pub struct BatchJobCreate {
    pub input_path: String,
    pub output_path: String,
    pub model_id: String,
    pub governance_mode: GovernanceMode,
}

pub trait BatchJobStore {
    fn create_pending(&mut self, create: &BatchJobCreate) -> Result<String, JobStoreError>;
    fn mark_running(&mut self, job_id: &str, total_rows: usize) -> Result<(), JobStoreError>;
    fn mark_completed(
        &mut self,
        job_id: &str,
        total_rows: usize,
        succeeded: usize,
        failed: usize,
        skipped: usize,
    ) -> Result<(), JobStoreError>;
    fn mark_failed(
        &mut self,
        job_id: &str,
        error_summary: &str,
        total_rows: usize,
        succeeded: usize,
        failed: usize,
        skipped: usize,
    ) -> Result<(), JobStoreError>;
}

#[derive(Debug, thiserror::Error)]
pub enum JobStoreError {
    #[error("postgres: {0}")]
    Postgres(String),
}

pub struct NoopBatchJobStore;

impl BatchJobStore for NoopBatchJobStore {
    fn create_pending(&mut self, _create: &BatchJobCreate) -> Result<String, JobStoreError> {
        Ok(Uuid::new_v4().to_string())
    }

    fn mark_running(&mut self, _job_id: &str, _total_rows: usize) -> Result<(), JobStoreError> {
        Ok(())
    }

    fn mark_completed(
        &mut self,
        _job_id: &str,
        _total_rows: usize,
        _succeeded: usize,
        _failed: usize,
        _skipped: usize,
    ) -> Result<(), JobStoreError> {
        Ok(())
    }

    fn mark_failed(
        &mut self,
        _job_id: &str,
        _error_summary: &str,
        _total_rows: usize,
        _succeeded: usize,
        _failed: usize,
        _skipped: usize,
    ) -> Result<(), JobStoreError> {
        Ok(())
    }
}

#[derive(Clone)]
pub struct PostgresBatchJobStore {
    pool: PgPool,
}

impl PostgresBatchJobStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn list(&self, limit: i64) -> Result<Vec<BatchJobRecord>, JobQueryError> {
        let rows = sqlx::query_as::<_, BatchJobRow>(
            "SELECT job_id, status, input_path, output_path, model_id, governance_mode, \
            total_rows, processed_rows, succeeded_rows, failed_rows, skipped_rows, error_summary, \
            created_at, started_at, completed_at \
            FROM batch_jobs ORDER BY created_at DESC LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|err| JobQueryError::Io(err.to_string()))?;
        Ok(rows
            .into_iter()
            .map(BatchJobRow::into_record)
            .map(BatchJobRecord::redacted_paths)
            .collect())
    }

    pub async fn get(&self, job_id: &str) -> Result<BatchJobRecord, JobQueryError> {
        let row = sqlx::query_as::<_, BatchJobRow>(
            "SELECT job_id, status, input_path, output_path, model_id, governance_mode, \
            total_rows, processed_rows, succeeded_rows, failed_rows, skipped_rows, error_summary, \
            created_at, started_at, completed_at \
            FROM batch_jobs WHERE job_id = $1",
        )
        .bind(job_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|err| JobQueryError::Io(err.to_string()))?;
        row.map(BatchJobRow::into_record)
            .map(BatchJobRecord::redacted_paths)
            .ok_or_else(|| JobQueryError::NotFound(job_id.to_string()))
    }
}

impl BatchJobStore for PostgresBatchJobStore {
    fn create_pending(&mut self, create: &BatchJobCreate) -> Result<String, JobStoreError> {
        let job_id = Uuid::new_v4().to_string();
        let pool = self.pool.clone();
        let job_id_clone = job_id.clone();
        let input_path = create.input_path.clone();
        let output_path = create.output_path.clone();
        let model_id = create.model_id.clone();
        let governance_mode = governance_mode_str(create.governance_mode);
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                sqlx::query(
                    r"
                    INSERT INTO batch_jobs (
                        job_id, status, input_path, output_path, model_id, governance_mode
                    ) VALUES ($1, 'pending', $2, $3, $4, $5)
                    ",
                )
                .bind(&job_id_clone)
                .bind(input_path)
                .bind(output_path)
                .bind(model_id)
                .bind(governance_mode)
                .execute(&pool)
                .await
                .map_err(|err| JobStoreError::Postgres(err.to_string()))
            })
        })?;
        Ok(job_id)
    }

    fn mark_running(&mut self, job_id: &str, total_rows: usize) -> Result<(), JobStoreError> {
        let pool = self.pool.clone();
        let job_id = job_id.to_string();
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                sqlx::query(
                    r"
                    UPDATE batch_jobs
                    SET status = 'running', started_at = $2, total_rows = $3, processed_rows = 0
                    WHERE job_id = $1
                    ",
                )
                .bind(job_id)
                .bind(Utc::now())
                .bind(i64::try_from(total_rows).unwrap_or(i64::MAX))
                .execute(&pool)
                .await
                .map_err(|err| JobStoreError::Postgres(err.to_string()))
            })
        })?;
        Ok(())
    }

    fn mark_completed(
        &mut self,
        job_id: &str,
        total_rows: usize,
        succeeded: usize,
        failed: usize,
        skipped: usize,
    ) -> Result<(), JobStoreError> {
        update_final_status(
            &self.pool,
            &BatchJobFinalStatus {
                job_id,
                status: "completed",
                error_summary: None,
                total_rows,
                succeeded,
                failed,
                skipped,
            },
        )
    }

    fn mark_failed(
        &mut self,
        job_id: &str,
        error_summary: &str,
        total_rows: usize,
        succeeded: usize,
        failed: usize,
        skipped: usize,
    ) -> Result<(), JobStoreError> {
        update_final_status(
            &self.pool,
            &BatchJobFinalStatus {
                job_id,
                status: "failed",
                error_summary: Some(error_summary),
                total_rows,
                succeeded,
                failed,
                skipped,
            },
        )
    }
}

struct BatchJobFinalStatus<'a> {
    job_id: &'a str,
    status: &'a str,
    error_summary: Option<&'a str>,
    total_rows: usize,
    succeeded: usize,
    failed: usize,
    skipped: usize,
}

fn update_final_status(
    pool: &PgPool,
    update: &BatchJobFinalStatus<'_>,
) -> Result<(), JobStoreError> {
    let pool = pool.clone();
    let job_id = update.job_id.to_string();
    let status = update.status.to_string();
    let error_summary = update.error_summary.map(str::to_string);
    let total_rows = update.total_rows;
    let succeeded = update.succeeded;
    let failed = update.failed;
    let skipped = update.skipped;
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(async move {
            sqlx::query(
                r"
                UPDATE batch_jobs
                SET status = $2,
                    completed_at = $3,
                    total_rows = $4,
                    processed_rows = $4,
                    succeeded_rows = $5,
                    failed_rows = $6,
                    skipped_rows = $7,
                    error_summary = $8
                WHERE job_id = $1
                ",
            )
            .bind(job_id)
            .bind(status)
            .bind(Utc::now())
            .bind(i64::try_from(total_rows).unwrap_or(i64::MAX))
            .bind(i64::try_from(succeeded).unwrap_or(i64::MAX))
            .bind(i64::try_from(failed).unwrap_or(i64::MAX))
            .bind(i64::try_from(skipped).unwrap_or(i64::MAX))
            .bind(error_summary)
            .execute(&pool)
            .await
            .map_err(|err| JobStoreError::Postgres(err.to_string()))
        })
    })?;
    Ok(())
}

fn governance_mode_str(mode: GovernanceMode) -> &'static str {
    match mode {
        GovernanceMode::Shadow => "shadow",
        GovernanceMode::Enforce => "enforce",
    }
}

#[derive(sqlx::FromRow)]
struct BatchJobRow {
    job_id: String,
    status: String,
    input_path: String,
    output_path: Option<String>,
    model_id: String,
    governance_mode: String,
    total_rows: i64,
    processed_rows: i64,
    succeeded_rows: i64,
    failed_rows: i64,
    skipped_rows: i64,
    error_summary: Option<String>,
    created_at: DateTime<Utc>,
    started_at: Option<DateTime<Utc>>,
    completed_at: Option<DateTime<Utc>>,
}

impl BatchJobRow {
    fn into_record(self) -> BatchJobRecord {
        BatchJobRecord {
            job_id: self.job_id,
            status: self.status,
            input_path: self.input_path,
            output_path: self.output_path,
            model_id: self.model_id,
            governance_mode: self.governance_mode,
            total_rows: self.total_rows,
            processed_rows: self.processed_rows,
            succeeded_rows: self.succeeded_rows,
            failed_rows: self.failed_rows,
            skipped_rows: self.skipped_rows,
            error_summary: self.error_summary,
            created_at: self.created_at,
            started_at: self.started_at,
            completed_at: self.completed_at,
        }
    }
}

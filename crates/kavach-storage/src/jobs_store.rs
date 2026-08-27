use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BatchJobRecord {
    pub job_id: String,
    pub status: String,
    pub input_path: String,
    pub output_path: Option<String>,
    pub model_id: String,
    pub governance_mode: String,
    pub total_rows: i64,
    pub processed_rows: i64,
    pub succeeded_rows: i64,
    pub failed_rows: i64,
    pub skipped_rows: i64,
    pub error_summary: Option<String>,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
}

impl BatchJobRecord {
    #[must_use]
    pub fn redacted_paths(mut self) -> Self {
        self.input_path = path_basename(&self.input_path);
        self.output_path = self.output_path.as_deref().map(path_basename);
        self
    }
}

pub fn path_basename(path: &str) -> String {
    Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(path)
        .to_string()
}

#[derive(Debug, thiserror::Error)]
pub enum JobQueryError {
    #[error("job store io: {0}")]
    Io(String),
    #[error("job not found: {0}")]
    NotFound(String),
}

#[derive(Default)]
pub struct MemoryBatchJobStore {
    jobs: Mutex<Vec<BatchJobRecord>>,
}

impl MemoryBatchJobStore {
    pub fn list(&self, limit: u32) -> Result<Vec<BatchJobRecord>, JobQueryError> {
        let jobs = self
            .jobs
            .lock()
            .map_err(|_| JobQueryError::Io("lock poisoned".into()))?;
        let start = jobs.len().saturating_sub(limit as usize);
        Ok(jobs[start..]
            .iter()
            .cloned()
            .map(BatchJobRecord::redacted_paths)
            .collect())
    }

    pub fn get(&self, job_id: &str) -> Result<BatchJobRecord, JobQueryError> {
        let jobs = self
            .jobs
            .lock()
            .map_err(|_| JobQueryError::Io("lock poisoned".into()))?;
        jobs.iter()
            .find(|job| job.job_id == job_id)
            .cloned()
            .map(BatchJobRecord::redacted_paths)
            .ok_or_else(|| JobQueryError::NotFound(job_id.to_string()))
    }

    pub fn insert(&self, record: BatchJobRecord) -> Result<(), JobQueryError> {
        self.jobs
            .lock()
            .map_err(|_| JobQueryError::Io("lock poisoned".into()))?
            .push(record);
        Ok(())
    }
}

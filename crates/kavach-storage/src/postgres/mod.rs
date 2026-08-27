//! Postgres persistence for evidence chain, incidents, and batch jobs.

mod admin;
mod evidence;
mod incidents;
mod jobs;
mod migrate;

pub use admin::PostgresAdminStore;

pub use evidence::PostgresEvidenceStore;
pub use incidents::PostgresIncidentRecorder;
pub use jobs::{
    BatchJobCreate, BatchJobStore, JobStoreError, NoopBatchJobStore, PostgresBatchJobStore,
};
pub use migrate::connect_pool;

use sqlx::PgPool;

/// Shared Postgres pool with schema migrations applied.
#[derive(Clone)]
pub struct StoragePool {
    pub pool: PgPool,
}

impl StoragePool {
    pub async fn connect(database_url: &str) -> Result<Self, kavach_evidence::EvidenceError> {
        connect_pool(database_url).await
    }

    pub fn evidence_store(&self) -> PostgresEvidenceStore {
        PostgresEvidenceStore::new(self.pool.clone())
    }

    pub fn incident_recorder(&self) -> PostgresIncidentRecorder {
        PostgresIncidentRecorder::new(self.pool.clone())
    }

    pub fn batch_job_store(&self) -> PostgresBatchJobStore {
        PostgresBatchJobStore::new(self.pool.clone())
    }

    pub fn admin_store(&self) -> PostgresAdminStore {
        PostgresAdminStore::new(self.pool.clone())
    }
}

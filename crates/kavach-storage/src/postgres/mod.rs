//! Postgres persistence for evidence chain, incidents, and batch jobs.

mod admin;
mod evidence;
mod incidents;
mod jobs;
mod migrate;
mod retention;

pub use admin::PostgresAdminStore;

pub use evidence::PostgresEvidenceStore;
pub use incidents::PostgresIncidentStore;
pub use jobs::{
    BatchJobCreate, BatchJobStore, JobStoreError, NoopBatchJobStore, PostgresBatchJobStore,
};
pub use migrate::connect_pool;
pub use retention::PostgresRetentionStore;

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

    pub fn incident_store(&self) -> PostgresIncidentStore {
        PostgresIncidentStore::new(self.pool.clone())
    }

    pub fn batch_job_store(&self) -> PostgresBatchJobStore {
        PostgresBatchJobStore::new(self.pool.clone())
    }

    pub fn admin_store(&self) -> PostgresAdminStore {
        PostgresAdminStore::new(self.pool.clone())
    }

    pub fn retention_store(&self) -> PostgresRetentionStore {
        PostgresRetentionStore::new(self.pool.clone())
    }
}

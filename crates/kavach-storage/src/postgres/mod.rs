//! Postgres persistence for evidence chain, incidents, and batch jobs.

mod admin;
mod change_requests;
mod evidence;
mod incidents;
mod jobs;
mod mandates;
mod migrate;
mod retention;

pub use admin::PostgresAdminStore;
pub use change_requests::PostgresChangeStore;

pub use evidence::PostgresEvidenceStore;
pub use incidents::PostgresIncidentStore;
pub use jobs::{
    BatchJobCreate, BatchJobStore, JobStoreError, NoopBatchJobStore, PostgresBatchJobStore,
};
pub use mandates::{PostgresMandateStore, PostgresReplayGuard};
pub use migrate::{connect_pool, connect_runtime, migrate};
pub use retention::PostgresRetentionStore;

use sqlx::PgPool;

/// Shared Postgres pool with schema migrations applied.
#[derive(Clone)]
pub struct StoragePool {
    pub pool: PgPool,
}

impl StoragePool {
    /// Migrates and connects with one role (development).
    pub async fn connect(database_url: &str) -> Result<Self, kavach_evidence::EvidenceError> {
        connect_pool(database_url).await
    }

    /// Migrates as `migration_url` (owner role) when given, then connects as
    /// `database_url` (runtime role) without migrating. Without a migration
    /// URL, one role does both.
    pub async fn connect_with_roles(
        database_url: &str,
        migration_url: Option<&str>,
    ) -> Result<Self, kavach_evidence::EvidenceError> {
        match migration_url {
            Some(owner) => {
                migrate(owner).await?;
                connect_runtime(database_url).await
            }
            None => connect_pool(database_url).await,
        }
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

    pub fn mandate_store(&self) -> PostgresMandateStore {
        PostgresMandateStore::new(self.pool.clone())
    }

    pub fn replay_guard(&self) -> PostgresReplayGuard {
        PostgresReplayGuard::new(self.pool.clone())
    }

    pub fn change_request_store(&self) -> PostgresChangeStore {
        PostgresChangeStore::new(self.pool.clone())
    }
}

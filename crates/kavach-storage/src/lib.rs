//! Postgres adapters for evidence chain, incidents, and batch jobs.

mod admin;
mod backends;
mod incidents_store;
mod jobs_store;
mod postgres;
mod retention;

pub use admin::{AdminStoreError, AuditEntry, AuditInsert, MemoryAdminStore, RuntimePointers};
pub use backends::{
    AdminBackend, BatchJobBackend, EvidenceBackend, IncidentBackend, RetentionBackend,
};
pub use incidents_store::{IncidentRecord, IncidentStoreError, MemoryIncidentStore};
pub use jobs_store::{BatchJobRecord, JobQueryError, MemoryBatchJobStore};
pub use postgres::{
    connect_pool, BatchJobCreate, BatchJobStore, JobStoreError, NoopBatchJobStore,
    PostgresAdminStore, PostgresBatchJobStore, PostgresEvidenceStore, PostgresIncidentStore,
    PostgresRetentionStore, StoragePool,
};
pub use retention::{
    MemoryRetentionStore, RetentionApplyReport, RetentionSettings, RetentionStoreError,
    TombstoneReason, TombstoneRecord,
};

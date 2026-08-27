//! Postgres adapters for evidence chain, incidents, and batch jobs.

mod admin;
mod backends;
mod postgres;
mod retention;

pub use admin::{AdminStoreError, AuditEntry, AuditInsert, MemoryAdminStore, RuntimePointers};
pub use backends::{AdminBackend, EvidenceBackend, IncidentBackend, RetentionBackend};
pub use postgres::{
    connect_pool, BatchJobCreate, BatchJobStore, JobStoreError, NoopBatchJobStore,
    PostgresAdminStore, PostgresBatchJobStore, PostgresEvidenceStore, PostgresIncidentRecorder,
    PostgresRetentionStore, StoragePool,
};
pub use retention::{
    MemoryRetentionStore, RetentionApplyReport, RetentionSettings, RetentionStoreError,
    TombstoneReason, TombstoneRecord,
};

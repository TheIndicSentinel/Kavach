//! Postgres adapters for evidence chain, incidents, and batch jobs.

mod admin;
mod backends;
mod postgres;

pub use admin::{AdminStoreError, AuditEntry, AuditInsert, MemoryAdminStore, RuntimePointers};
pub use backends::{AdminBackend, EvidenceBackend, IncidentBackend};
pub use postgres::{
    connect_pool, BatchJobCreate, BatchJobStore, JobStoreError, NoopBatchJobStore,
    PostgresAdminStore, PostgresBatchJobStore, PostgresEvidenceStore, PostgresIncidentRecorder,
    StoragePool,
};

//! Postgres adapters for evidence chain, incidents, and batch jobs.

mod backends;
mod postgres;

pub use backends::{EvidenceBackend, IncidentBackend};
pub use postgres::{
    connect_pool, BatchJobCreate, BatchJobStore, JobStoreError, NoopBatchJobStore,
    PostgresBatchJobStore, PostgresEvidenceStore, PostgresIncidentRecorder, StoragePool,
};

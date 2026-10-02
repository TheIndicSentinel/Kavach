//! Postgres adapters for evidence chain, incidents, and batch jobs.

mod admin;
mod agent_evidence;
mod backends;
mod change_requests;
mod incidents_store;
mod jobs_store;
mod model_governance;
mod postgres;
mod retention;
mod startup;
#[cfg(feature = "test-support")]
pub mod testing;

pub use admin::{
    mode_str, parse_mode, parse_status, status_str, AdminStoreError, AuditEntry, AuditInsert,
    MemoryAdminStore, ModelState, RuntimePointers,
};
pub use agent_evidence::MemoryAgentEvidenceStore;
pub use backends::{
    AdminBackend, BatchJobBackend, EvidenceBackend, IncidentBackend, RetentionBackend,
};
pub use change_requests::{
    decision_audit, evidence_set_digest, ApprovalCommit, ChangeKind, ChangeRequest,
    ChangeRequestBackend, ChangeStatus, ChangeStoreError, CloseRequest, GovernanceEffect,
    MemoryChangeStore,
};
pub use incidents_store::{IncidentRecord, IncidentStoreError, MemoryIncidentStore};
pub use jobs_store::{BatchJobRecord, JobQueryError, MemoryBatchJobStore};
pub use model_governance::{govern_model, GovernedModel, ModelStartupError, ModelStartupRole};
pub use postgres::{
    connect_options, connect_pool, connect_runtime, migrate, BatchJobCreate, BatchJobStore,
    DatabaseTls, DatabaseTlsError, EvidenceSnapshot, JobStoreError, NoopBatchJobStore,
    PostgresAdminStore, PostgresAgentEvidenceStore, PostgresBatchJobStore, PostgresChangeStore,
    PostgresEvidenceStore, PostgresIncidentStore, PostgresMandateStore, PostgresReplayGuard,
    PostgresRetentionStore, StoragePool,
};
pub use retention::{
    MemoryRetentionStore, RetentionApplyReport, RetentionSettings, RetentionStoreError,
    TombstoneReason, TombstoneRecord,
};
pub use startup::{check_startup_pack, StartupPackCheck, StartupPackError};

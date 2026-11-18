//! Postgres adapters for evidence chain, incidents, and batch jobs.

mod admin;
mod agent_evidence;
mod backends;
mod change_requests;
mod human_review;
mod incidents_store;
mod jobs_store;
mod model_governance;
mod postgres;
mod retention;
mod review_snapshots;
mod roles;
mod startup;
mod step_up;
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
pub use human_review::MemoryReviewApprovalStore;
pub use incidents_store::{IncidentRecord, IncidentStoreError, MemoryIncidentStore};
pub use jobs_store::{BatchJobRecord, JobQueryError, MemoryBatchJobStore};
pub use model_governance::{govern_model, GovernedModel, ModelStartupError, ModelStartupRole};
pub use postgres::{
    connect_options, connect_pool, connect_runtime, connect_runtime_sized, is_weakened, migrate,
    AppliedConsentGrant, AppliedConsentWithdrawal, AppliedPreferenceUpdate,
    AppliedReferenceDestination, BatchJobCreate, BatchJobStore, DatabaseTls, DatabaseTlsError,
    EncryptedDestination, EvidenceSnapshot, JobStoreError, NoopBatchJobStore, PostgresAdminStore,
    PostgresAgentEvidenceStore, PostgresAuthorityUpdateStore, PostgresBatchJobStore,
    PostgresChangeStore, PostgresConsentSource, PostgresContactPreferenceSource,
    PostgresEvidenceStore, PostgresIncidentStore, PostgresMandateStore,
    PostgresReferenceDestinationStore, PostgresReferenceResolver, PostgresReplayGuard,
    PostgresRetentionStore, PostgresReviewApprovalStore, PostgresReviewSnapshotStore,
    PostgresRoleStore, PostgresStepUpChallengeStore, ReferenceVaultKey, StoragePool,
    DEFAULT_POOL_SIZE,
};
pub use retention::{
    MemoryRetentionStore, RetentionApplyReport, RetentionSettings, RetentionStoreError,
    TombstoneReason, TombstoneRecord,
};
pub use review_snapshots::MemoryReviewSnapshotStore;
pub use roles::{
    binding_not_active_reason, duplicate_binding_reason, grant_refusal, last_admin_reason,
    revoke_target, BindingSubject, BootstrapOutcome, MemoryRoleStore, PrincipalRecord, Role,
    RoleBackend, RoleBinding, RoleStoreError, SubjectKind, BOOTSTRAP_ACTOR, BOOTSTRAP_AUDIT_ACTION,
    DISPLAY_NAME_MAX_CHARS, LAST_SEEN_GRANULARITY, ROLE_BINDING_RESOURCE,
};
pub use startup::{check_startup_pack, StartupPackCheck, StartupPackError};
pub use step_up::MemoryStepUpChallengeStore;

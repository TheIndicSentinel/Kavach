use std::sync::Arc;

use kavach_domain::DecisionEvent;
use kavach_evaluate::EvidenceStore;
use kavach_evidence::MemoryChain;

use crate::admin::{
    AdminStoreError, AuditEntry, AuditInsert, MemoryAdminStore, ModelState, RuntimePointers,
};
use crate::incidents_store::{IncidentRecord, IncidentStoreError, MemoryIncidentStore};
use crate::jobs_store::{BatchJobRecord, JobQueryError, MemoryBatchJobStore};
use crate::postgres::{
    PostgresAdminStore, PostgresBatchJobStore, PostgresEvidenceStore, PostgresIncidentStore,
    PostgresRetentionStore,
};
use crate::retention::{
    MemoryRetentionStore, RetentionApplyReport, RetentionSettings, RetentionStoreError,
    TombstoneReason, TombstoneRecord,
};

pub enum EvidenceBackend {
    Memory(MemoryChain),
    Postgres(PostgresEvidenceStore),
}

impl EvidenceBackend {
    #[must_use]
    pub fn memory_events(&self) -> Option<Vec<DecisionEvent>> {
        match self {
            Self::Memory(chain) => Some(chain.events().to_vec()),
            Self::Postgres(_) => None,
        }
    }
}

impl EvidenceStore for EvidenceBackend {
    fn append(
        &mut self,
        input: kavach_evidence::AppendDecisionEvent,
    ) -> Result<kavach_domain::DecisionEvent, kavach_evidence::EvidenceError> {
        match self {
            Self::Memory(chain) => chain.append(input),
            Self::Postgres(store) => store.append(input),
        }
    }
}

pub enum IncidentBackend {
    Memory(Arc<MemoryIncidentStore>),
    Postgres(PostgresIncidentStore),
}

impl IncidentBackend {
    pub fn memory() -> Self {
        Self::Memory(Arc::new(MemoryIncidentStore::default()))
    }

    pub async fn list(&self, limit: u32) -> Result<Vec<IncidentRecord>, IncidentStoreError> {
        match self {
            Self::Memory(store) => store.list(limit),
            Self::Postgres(store) => store.list(i64::from(limit)).await,
        }
    }
}

impl Clone for IncidentBackend {
    fn clone(&self) -> Self {
        match self {
            Self::Memory(store) => Self::Memory(Arc::clone(store)),
            Self::Postgres(store) => Self::Postgres(store.clone()),
        }
    }
}

impl kavach_evaluate::IncidentRecorder for IncidentBackend {
    fn record(
        &mut self,
        incident: kavach_evaluate::EvaluateIncident,
    ) -> Result<(), kavach_evaluate::IncidentWriteError> {
        match self {
            Self::Memory(store) => store
                .record_incident(incident)
                .map_err(|e| kavach_evaluate::IncidentWriteError(e.to_string())),
            Self::Postgres(store) => store.record(incident),
        }
    }
}

pub enum BatchJobBackend {
    Memory(Arc<MemoryBatchJobStore>),
    Postgres(PostgresBatchJobStore),
}

impl BatchJobBackend {
    pub fn memory() -> Self {
        Self::Memory(Arc::new(MemoryBatchJobStore::default()))
    }

    pub async fn list(&self, limit: u32) -> Result<Vec<BatchJobRecord>, JobQueryError> {
        match self {
            Self::Memory(store) => store.list(limit),
            Self::Postgres(store) => store.list(i64::from(limit)).await,
        }
    }

    pub async fn get(&self, job_id: &str) -> Result<BatchJobRecord, JobQueryError> {
        match self {
            Self::Memory(store) => store.get(job_id),
            Self::Postgres(store) => store.get(job_id).await,
        }
    }

    pub fn seed_test_job(&self, record: BatchJobRecord) {
        if let Self::Memory(store) = self {
            let _ = store.insert(record);
        }
    }
}

pub enum AdminBackend {
    Memory(Arc<MemoryAdminStore>),
    Postgres(PostgresAdminStore),
}

impl AdminBackend {
    pub fn memory() -> Self {
        Self::Memory(Arc::new(MemoryAdminStore::default()))
    }

    pub async fn append_audit(&self, insert: AuditInsert) -> Result<AuditEntry, AdminStoreError> {
        match self {
            Self::Memory(store) => store.append_audit(insert),
            Self::Postgres(store) => store.append_audit(insert).await,
        }
    }

    pub async fn list_audit(&self, limit: u32) -> Result<Vec<AuditEntry>, AdminStoreError> {
        match self {
            Self::Memory(store) => store.list_audit(limit),
            Self::Postgres(store) => store.list_audit(i64::from(limit)).await,
        }
    }

    pub async fn get_runtime_pointers(&self) -> Result<Option<RuntimePointers>, AdminStoreError> {
        match self {
            Self::Memory(store) => store.get_runtime_pointers(),
            Self::Postgres(store) => store.get_runtime_pointers().await,
        }
    }

    pub async fn set_runtime_pointers(
        &self,
        pointers: RuntimePointers,
    ) -> Result<(), AdminStoreError> {
        match self {
            Self::Memory(store) => store.set_runtime_pointers(pointers),
            Self::Postgres(store) => store.set_runtime_pointers(pointers).await,
        }
    }

    /// First-start baseline: writes only when no pointer exists.
    pub async fn insert_pointers_if_absent(
        &self,
        pointers: RuntimePointers,
    ) -> Result<bool, AdminStoreError> {
        match self {
            Self::Memory(store) => store.insert_pointers_if_absent(pointers),
            Self::Postgres(store) => store.insert_pointers_if_absent(&pointers).await,
        }
    }

    pub async fn get_model_state(
        &self,
        model_id: &str,
    ) -> Result<Option<ModelState>, AdminStoreError> {
        match self {
            Self::Memory(store) => store.get_model_state(model_id),
            Self::Postgres(store) => store.get_model_state(model_id).await,
        }
    }

    pub async fn list_model_states(&self) -> Result<Vec<ModelState>, AdminStoreError> {
        match self {
            Self::Memory(store) => store.list_model_states(),
            Self::Postgres(store) => store.list_model_states().await,
        }
    }

    pub async fn insert_model_state_if_absent(
        &self,
        state: ModelState,
    ) -> Result<bool, AdminStoreError> {
        match self {
            Self::Memory(store) => store.insert_model_state_if_absent(state),
            Self::Postgres(store) => store.insert_model_state_if_absent(&state).await,
        }
    }

    /// Most recent audit row for `action` on `resource_id`.
    pub async fn last_audit(
        &self,
        action: &str,
        resource_id: &str,
    ) -> Result<Option<AuditEntry>, AdminStoreError> {
        match self {
            Self::Memory(store) => store.last_audit(action, resource_id),
            Self::Postgres(store) => store.last_audit(action, resource_id).await,
        }
    }
}

pub enum RetentionBackend {
    Memory(Arc<MemoryRetentionStore>),
    Postgres(PostgresRetentionStore),
}

impl RetentionBackend {
    pub fn memory() -> Self {
        Self::Memory(Arc::new(MemoryRetentionStore::default()))
    }

    pub async fn get_settings(&self) -> Result<RetentionSettings, RetentionStoreError> {
        match self {
            Self::Memory(store) => store.get_settings(),
            Self::Postgres(store) => store.get_settings().await,
        }
    }

    pub async fn set_settings(
        &self,
        evidence_retention_days: u32,
        actor: &str,
        approver: &str,
    ) -> Result<RetentionSettings, RetentionStoreError> {
        match self {
            Self::Memory(store) => store.set_settings(evidence_retention_days, actor, approver),
            Self::Postgres(store) => {
                store
                    .set_settings(evidence_retention_days, actor, approver)
                    .await
            }
        }
    }

    pub async fn tombstone(
        &self,
        evidence_id: &str,
        reason: TombstoneReason,
        actor: &str,
        approver: &str,
    ) -> Result<TombstoneRecord, RetentionStoreError> {
        match self {
            Self::Memory(store) => store.tombstone(evidence_id, reason, actor, approver),
            Self::Postgres(store) => store.tombstone(evidence_id, reason, actor, approver).await,
        }
    }

    /// Postgres: untombstoned evidence older than `cutoff`, sorted. Memory
    /// returns `None`: the candidates come from the in-memory chain.
    pub async fn candidates(
        &self,
        cutoff: chrono::DateTime<chrono::Utc>,
    ) -> Result<Option<Vec<String>>, RetentionStoreError> {
        match self {
            Self::Memory(_) => Ok(None),
            Self::Postgres(store) => store.candidates(cutoff).await.map(Some),
        }
    }

    pub async fn is_tombstoned(&self, evidence_id: &str) -> Result<bool, RetentionStoreError> {
        match self {
            Self::Memory(store) => store.is_tombstoned(evidence_id),
            Self::Postgres(store) => store.is_tombstoned(evidence_id).await,
        }
    }

    pub async fn list_tombstones(
        &self,
        limit: u32,
    ) -> Result<Vec<TombstoneRecord>, RetentionStoreError> {
        match self {
            Self::Memory(store) => store.list_tombstones(limit),
            Self::Postgres(store) => store.list_tombstones(i64::from(limit)).await,
        }
    }

    pub async fn apply_retention(
        &self,
        memory_candidates: Option<&[String]>,
        actor: &str,
        approver: &str,
    ) -> Result<RetentionApplyReport, RetentionStoreError> {
        match self {
            Self::Memory(store) => {
                let candidates = memory_candidates.ok_or_else(|| {
                    RetentionStoreError::Io(
                        "memory retention requires candidate evidence ids".into(),
                    )
                })?;
                store.apply_retention(candidates, actor, approver)
            }
            Self::Postgres(store) => store.apply_retention(actor, approver).await,
        }
    }
}

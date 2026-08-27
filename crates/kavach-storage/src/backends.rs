use std::sync::Arc;

use kavach_domain::DecisionEvent;
use kavach_evaluate::EvidenceStore;
use kavach_evidence::MemoryChain;

use crate::admin::{AdminStoreError, AuditEntry, AuditInsert, MemoryAdminStore, RuntimePointers};
use crate::postgres::{
    PostgresAdminStore, PostgresEvidenceStore, PostgresIncidentRecorder, PostgresRetentionStore,
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
    Memory(kavach_evaluate::VecIncidentRecorder),
    Postgres(PostgresIncidentRecorder),
}

impl kavach_evaluate::IncidentRecorder for IncidentBackend {
    fn record(&mut self, incident: kavach_evaluate::EvaluateIncident) {
        match self {
            Self::Memory(recorder) => recorder.record(incident),
            Self::Postgres(recorder) => recorder.record(incident),
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

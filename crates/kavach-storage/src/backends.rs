use std::sync::Arc;

use kavach_evaluate::EvidenceStore;
use kavach_evidence::MemoryChain;

use crate::admin::{AdminStoreError, AuditEntry, AuditInsert, MemoryAdminStore, RuntimePointers};
use crate::postgres::{PostgresAdminStore, PostgresEvidenceStore, PostgresIncidentRecorder};

pub enum EvidenceBackend {
    Memory(MemoryChain),
    Postgres(PostgresEvidenceStore),
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

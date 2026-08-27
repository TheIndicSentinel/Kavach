use kavach_evaluate::EvidenceStore;
use kavach_evidence::MemoryChain;

use super::{PostgresEvidenceStore, PostgresIncidentRecorder};

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

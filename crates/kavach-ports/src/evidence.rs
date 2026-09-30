use kavach_domain::DecisionEvent;
use kavach_evidence::{AppendDecisionEvent, EvidenceError, MemoryChain};

/// Append-only evidence persistence.
///
/// Synchronous for now; the async migration lands with evidence v2 (ADR-005,
/// M2), which rewrites the storage adapter.
pub trait EvidenceStore {
    fn append(&mut self, input: AppendDecisionEvent) -> Result<DecisionEvent, EvidenceError>;
}

impl EvidenceStore for MemoryChain {
    fn append(&mut self, input: AppendDecisionEvent) -> Result<DecisionEvent, EvidenceError> {
        MemoryChain::append(self, input)
    }
}

/// An incident could not be persisted. Callers must surface it (metric, log);
/// infra failures must never become invisible (ADR-001 §5).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("incident write failed: {0}")]
pub struct IncidentWriteError(pub String);

/// Shadow-mode infra failure path — no fake evidence row (ADR-001 §5).
pub trait IncidentRecorder {
    fn record(&mut self, incident: EvaluateIncident) -> Result<(), IncidentWriteError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluateIncident {
    pub correlation_id: String,
    pub model_id: String,
    pub reason: String,
}

#[derive(Debug, Default)]
pub struct VecIncidentRecorder {
    pub incidents: Vec<EvaluateIncident>,
}

impl IncidentRecorder for VecIncidentRecorder {
    fn record(&mut self, incident: EvaluateIncident) -> Result<(), IncidentWriteError> {
        self.incidents.push(incident);
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct NoopIncidentRecorder;

impl IncidentRecorder for NoopIncidentRecorder {
    fn record(&mut self, _incident: EvaluateIncident) -> Result<(), IncidentWriteError> {
        Ok(())
    }
}

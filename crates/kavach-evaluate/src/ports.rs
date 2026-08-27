use kavach_domain::DecisionEvent;
use kavach_evidence::{AppendDecisionEvent, EvidenceError, MemoryChain};

/// Append-only evidence persistence (Postgres adapter in A.4).
pub trait EvidenceStore {
    fn append(&mut self, input: AppendDecisionEvent) -> Result<DecisionEvent, EvidenceError>;
}

impl EvidenceStore for MemoryChain {
    fn append(&mut self, input: AppendDecisionEvent) -> Result<DecisionEvent, EvidenceError> {
        MemoryChain::append(self, input)
    }
}

/// Shadow-mode infra failure path — no fake evidence row (ADR-001 §5).
pub trait IncidentRecorder {
    fn record(&mut self, incident: EvaluateIncident);
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
    fn record(&mut self, incident: EvaluateIncident) {
        self.incidents.push(incident);
    }
}

#[derive(Debug, Default)]
pub struct NoopIncidentRecorder;

impl IncidentRecorder for NoopIncidentRecorder {
    fn record(&mut self, _incident: EvaluateIncident) {}
}

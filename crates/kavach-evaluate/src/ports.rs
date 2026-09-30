//! Port traits moved to `kavach-ports` (ADR-006); re-exported here so existing
//! `kavach_evaluate::{EvidenceStore, IncidentRecorder, ...}` imports keep working.

pub use kavach_ports::{
    EvaluateIncident, EvidenceStore, IncidentRecorder, IncidentWriteError, NoopIncidentRecorder,
    VecIncidentRecorder,
};

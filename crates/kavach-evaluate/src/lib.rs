//! Evaluate pipeline orchestration — ADR-001 hot path (auth handled in `kavach-api`).

mod error;
mod ports;
mod service;
mod validation;

pub use error::EvaluateError;
pub use kavach_domain::EvaluatePath;
pub use ports::{
    EvaluateIncident, EvidenceStore, IncidentRecorder, NoopIncidentRecorder, VecIncidentRecorder,
};
pub use service::{EvaluateConfig, EvaluateResult, EvaluateService};
pub use validation::{
    compile_input_validator, validate_input, validate_model_binding, validate_supplier_controls,
};

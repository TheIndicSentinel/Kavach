//! NDJSON batch evaluate worker — ADR-001 batch path semantics.

mod error;
mod export;
mod fairness;
mod ingest;
mod worker;

pub use error::BatchError;
pub use export::{BatchResultRow, BatchRowStatus};
pub use fairness::{
    build_disparity_report, build_inclusion_report, run_disparity_report, run_inclusion_report,
    DisparityReport, FairnessConfig, FairnessReport, InclusionReport,
};
pub use ingest::parse_ndjson_requests;
pub use worker::{run_batch, BatchConfig, BatchJobReport, BatchRunContext};

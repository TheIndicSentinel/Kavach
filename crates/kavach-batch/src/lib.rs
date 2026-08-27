//! NDJSON batch evaluate worker — ADR-001 batch path semantics.

mod error;
mod export;
mod ingest;
mod worker;

pub use error::BatchError;
pub use export::{BatchResultRow, BatchRowStatus};
pub use ingest::parse_ndjson_requests;
pub use worker::{run_batch, BatchConfig, BatchJobReport};

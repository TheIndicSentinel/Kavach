//! Hash-chained decision evidence — append, export, offline verify.

mod canonical;
mod chain;
mod error;
mod store;
mod tombstone;
mod verify;

pub use canonical::GENESIS_HASH;
pub use chain::{at_storage_precision, compute_event_hash, verify_event_hash};
pub use error::EvidenceError;
pub use store::{check_idempotent_replay, AppendDecisionEvent, IdempotencyKey, MemoryChain};
pub use tombstone::{
    redact_tombstoned_event, TOMBSTONE_CORRELATION_ID, TOMBSTONE_INPUT_DIGEST,
    TOMBSTONE_SERVICE_IDENTITY,
};
pub use verify::{
    check_event, mixed_chain, parse_export, verify_chain, verify_export_file, EventCheck,
    VerifyReport,
};

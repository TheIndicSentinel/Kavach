//! Hash-chained decision evidence — append, export, offline verify.

mod canonical;
mod chain;
mod error;
mod store;
mod tombstone;
mod verify;

pub use canonical::GENESIS_HASH;
pub use chain::{compute_event_hash, verify_event_hash};
pub use error::EvidenceError;
pub use store::{AppendDecisionEvent, IdempotencyKey, MemoryChain};
pub use tombstone::{
    redact_tombstoned_event, TOMBSTONE_CORRELATION_ID, TOMBSTONE_INPUT_DIGEST,
    TOMBSTONE_SERVICE_IDENTITY,
};
pub use verify::{verify_chain, verify_export_file, VerifyReport};

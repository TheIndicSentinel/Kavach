use thiserror::Error;

#[derive(Debug, Error)]
pub enum EvidenceError {
    #[error("invalid hash `{hash}`: {reason}")]
    InvalidHash { hash: String, reason: String },

    #[error("chain break at event {event_id}: expected prev_hash {expected}, got {actual}")]
    ChainBreak {
        event_id: String,
        expected: String,
        actual: String,
    },

    #[error("hash mismatch at event {event_id}: stored {stored}, computed {computed}")]
    HashMismatch {
        event_id: String,
        stored: String,
        computed: String,
    },

    #[error("duplicate idempotency key for model {model_id}: {correlation_id}")]
    DuplicateIdempotency {
        model_id: String,
        correlation_id: String,
    },

    #[error("empty evidence chain")]
    EmptyChain,

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("domain error: {0}")]
    Domain(#[from] kavach_domain::DomainError),
}

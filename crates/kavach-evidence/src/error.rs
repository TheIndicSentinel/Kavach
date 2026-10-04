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

    /// Same idempotency key, different request (ADR-001 §11): the stored
    /// decision must not be returned for different input.
    #[error("idempotency conflict for model {model_id}, correlation {correlation_id}: {reason}")]
    IdempotencyConflict {
        model_id: String,
        correlation_id: String,
        reason: String,
    },

    /// A record older than the schema of a record before it: a 1.1.0 chain
    /// never goes back to an earlier schema, so this is tampering.
    #[error("event {event_id} has schema {schema_version} after a later-schema event")]
    SchemaRegression {
        event_id: String,
        schema_version: String,
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

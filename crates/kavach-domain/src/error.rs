use thiserror::Error;

#[derive(Debug, Error)]
pub enum DomainError {
    #[error("invalid decision: {0}")]
    InvalidDecision(String),

    #[error("invalid governance mode: {0}")]
    InvalidGovernanceMode(String),

    #[error("clock skew exceeded: {skew_seconds}s > max {max_seconds}s")]
    ClockSkew { skew_seconds: i64, max_seconds: i64 },

    #[error("consent purpose mismatch: expected {expected}, got {actual}")]
    ConsentPurposeMismatch { expected: String, actual: String },

    #[error("missing required field: {0}")]
    MissingField(&'static str),

    #[error("golden fixture error: {0}")]
    Golden(String),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

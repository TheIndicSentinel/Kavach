use thiserror::Error;

use kavach_domain::DomainError;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("failed to read pack: {0}")]
    Io(#[from] std::io::Error),

    #[error("failed to parse pack YAML: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("failed to serialize request: {0}")]
    Json(#[from] serde_json::Error),

    #[error("CEL compile error in rule `{rule_id}`: {message}")]
    CelCompile { rule_id: String, message: String },

    #[error("CEL execution error in rule `{rule_id}`: {message}")]
    CelExecute { rule_id: String, message: String },

    #[error("CEL evaluation timed out after {timeout_ms}ms")]
    Timeout { timeout_ms: u64 },

    #[error("domain error: {0}")]
    Domain(#[from] DomainError),

    #[error("pack validation: {0}")]
    Validation(String),
}

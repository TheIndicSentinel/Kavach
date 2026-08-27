use thiserror::Error;

use kavach_evaluate::EvaluateError;

#[derive(Debug, Error)]
pub enum BatchError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("yaml: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("policy: {0}")]
    Policy(#[from] kavach_policy::PolicyError),

    #[error("evaluate: {0}")]
    Evaluate(#[from] EvaluateError),

    #[error("parse line {line_number}: {message}")]
    ParseLine { line_number: usize, message: String },
}

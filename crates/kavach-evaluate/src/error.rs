use thiserror::Error;

use kavach_domain::DomainError;
use kavach_policy::PolicyError;

#[derive(Debug, Error)]
pub enum EvaluateError {
    #[error("validation: {0}")]
    Validation(String),

    #[error("model mismatch: {0}")]
    ModelMismatch(String),

    #[error("pack not effective at decision_time")]
    PackNotEffective,

    #[error("policy: {0}")]
    Policy(#[from] PolicyError),

    #[error("domain: {0}")]
    Domain(#[from] DomainError),
}

impl EvaluateError {
    #[must_use]
    pub fn validation(message: impl Into<String>) -> Self {
        Self::Validation(message.into())
    }

    pub fn from_domain(err: DomainError) -> Self {
        match err {
            DomainError::ClockSkew { .. } | DomainError::ConsentPurposeMismatch { .. } => {
                Self::Validation(err.to_string())
            }
            other => Self::Domain(other),
        }
    }
}

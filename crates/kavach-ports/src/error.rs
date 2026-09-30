use thiserror::Error;

/// Classification of every port failure (ADR-006 §3). It drives the
/// fail-closed mapping uniformly across dependencies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorClass {
    /// Dependency down, timed out or not trustworthy (e.g. clock unsynced).
    Unavailable,
    /// Dependency answered "no" (bad signature, unknown key, replay, revoked).
    Rejected,
    /// Malformed input.
    Invalid,
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[error("{class:?}: {message}")]
pub struct PortError {
    pub class: ErrorClass,
    pub message: String,
}

impl PortError {
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self {
            class: ErrorClass::Unavailable,
            message: message.into(),
        }
    }

    pub fn rejected(message: impl Into<String>) -> Self {
        Self {
            class: ErrorClass::Rejected,
            message: message.into(),
        }
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self {
            class: ErrorClass::Invalid,
            message: message.into(),
        }
    }
}

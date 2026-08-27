use thiserror::Error;

use axum::http::StatusCode;
use kavach_evaluate::EvaluateError;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("unauthorized")]
    Unauthorized,

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("evaluate: {0}")]
    Evaluate(#[from] EvaluateError),

    #[error("internal: {0}")]
    Internal(String),
}

impl ApiError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::BadRequest(_)
            | Self::Evaluate(
                EvaluateError::Validation(_)
                | EvaluateError::ModelMismatch(_)
                | EvaluateError::PackNotEffective,
            ) => StatusCode::BAD_REQUEST,
            Self::Evaluate(EvaluateError::Policy(kavach_policy::PolicyError::Timeout {
                ..
            })) => StatusCode::SERVICE_UNAVAILABLE,
            Self::Evaluate(_) | Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    #[must_use]
    pub fn is_client_error(&self) -> bool {
        self.status_code().is_client_error()
    }
}

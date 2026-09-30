use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("read policy {path}: {source}")]
    ReadPolicy {
        path: String,
        source: std::io::Error,
    },

    #[error("read entities {path}: {source}")]
    ReadEntities {
        path: String,
        source: std::io::Error,
    },

    #[error("parse policy: {0}")]
    ParsePolicy(String),

    #[error("cedar schema: {0}")]
    Schema(String),

    #[error("policy fails schema validation: {0}")]
    InvalidPolicy(String),

    #[error("parse entities: {0}")]
    ParseEntities(String),

    #[error("invalid principal: {0}")]
    InvalidPrincipal(String),

    #[error("cedar request: {0}")]
    Request(String),
}

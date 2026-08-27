//! HTTP API server for sync evaluate (gRPC follows in A.4).

mod error;
mod http;
mod state;

pub use error::ApiError;
pub use http::router;
pub use state::AppState;

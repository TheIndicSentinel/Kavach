//! Sync evaluate API — HTTP and gRPC (mTLS follows in A.4).

pub mod convert;
pub mod error;
pub mod grpc;
pub mod http;
pub mod proto;
pub mod state;

pub use error::ApiError;
pub use grpc::{status_from_api, GrpcEvaluateService};
pub use http::router;
pub use proto::kavach::v1::evaluate_service_server::EvaluateServiceServer;
pub use state::AppState;

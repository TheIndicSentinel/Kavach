//! Sync evaluate API — HTTP and gRPC (mTLS, Postgres evidence, metrics).

pub mod auth;
pub mod config;
pub mod console;
pub mod convert;
pub mod error;
pub mod governance;
pub mod grpc;
pub mod http;
pub mod metrics;
pub mod proto;
pub mod registry;
pub mod state;
pub mod tls;

pub use config::{AccessControlKind, ApiConfig, EvidenceStoreKind, TlsConfig};
pub use error::ApiError;
pub use grpc::{status_from_api, GrpcEvaluateService};
pub use http::router;
pub use metrics::Metrics;
pub use proto::kavach::v1::evaluate_service_server::EvaluateServiceServer;
pub use state::AppState;
pub use tls::{grpc_server_tls_config, serve_http};

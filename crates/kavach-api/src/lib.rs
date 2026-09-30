//! Sync evaluate API — HTTP and gRPC (mTLS, Postgres evidence, metrics).

pub mod auth;
pub mod batch_jobs;
pub mod config;
pub mod console;
pub mod convert;
pub mod error;
pub mod governance;
pub mod grpc;
pub mod hmac_auth;
pub mod http;
pub mod incidents;
pub mod lifecycle;
pub mod metrics;
pub mod mtls;
pub mod oidc;
pub mod proto;
pub mod registry;
pub mod retention;
pub mod state;
pub mod tls;

pub use config::{
    resolve_access_control, validate_principal_sources, AccessControlKind, AccessControlMode,
    ApiConfig, EvidenceStoreKind, TlsConfig,
};
pub use error::ApiError;
pub use grpc::{status_from_api, GrpcEvaluateService};
pub use http::router;
pub use metrics::Metrics;
pub use mtls::{MtlsSanKind, PeerCertificate};
pub use oidc::{JwksSource, OidcConfig, OidcVerifier};
pub use proto::kavach::v1::evaluate_service_server::EvaluateServiceServer;
pub use state::AppState;
pub use tls::{grpc_server_tls_config, serve_http, serve_http_on};

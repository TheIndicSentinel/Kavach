//! Sync evaluate API — HTTP and gRPC (mTLS, Postgres evidence, metrics).

pub mod agent_state_evidence;
pub mod agents;
pub mod auth;
pub mod batch_jobs;
pub mod change_requests;
pub mod checkpoints;
pub mod closed_records;
pub mod config;
pub mod console;
pub mod convert;
pub mod correlation;
pub mod dataplane;
pub mod dev_clock;
pub mod error;
pub mod evidence_read;
pub mod forward;
pub mod governance;
pub mod grpc;
pub mod hmac_auth;
pub mod http;
pub mod incidents;
pub mod lifecycle;
pub mod metrics;
pub mod mtls;
pub mod oidc;
pub mod outcome_reconciler;
pub mod problem;
pub mod proto;
pub mod registry;
pub mod retention;
pub mod revocation_audit;
pub mod revocation_evidence;
pub mod shutdown;
pub mod signing;
pub mod state;
pub mod strict_json;
pub mod tls;

pub use config::{
    resolve_access_control, validate_hmac_secret, validate_principal_sources, AccessControlKind,
    AccessControlMode, ApiConfig, EvidenceStoreKind, TlsConfig, MIN_HMAC_SECRET_BYTES,
};
pub use error::ApiError;
pub use grpc::{status_from_api, GrpcEvaluateService};
pub use http::router;
pub use kavach_storage::{DatabaseTls, DEFAULT_POOL_SIZE};
pub use metrics::Metrics;
pub use mtls::{MtlsSanKind, PeerCertificate};
pub use oidc::{JwksSource, OidcConfig, OidcVerifier};
pub use proto::kavach::v1::evaluate_service_server::EvaluateServiceServer;
pub use state::{AppState, ChangeProposal, DEFAULT_CHANGE_TTL_HOURS};
pub use tls::{
    grpc_server_tls_config, serve_http, serve_http_on, serve_http_on_until, serve_http_until,
};

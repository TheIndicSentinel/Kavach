use std::sync::Arc;

use kavach_auth::KavachAction;
use tonic::{Request, Response, Status};

use tonic::transport::server::TlsConnectInfo;

use crate::auth::authorize_metadata;
use crate::limits::{ConnHandle, ListenerLimits, RequestGate};
use crate::mtls::PeerCertificate;

use crate::convert::{domain_to_proto, proto_to_domain};
use crate::error::ApiError;
use crate::proto::kavach::v1::evaluate_service_server::EvaluateService;
use crate::proto::kavach::v1::{
    EvaluateRequest as ProtoEvaluateRequest, EvaluateResponse as ProtoEvaluateResponse,
};
use crate::state::AppState;

#[derive(Clone)]
pub struct GrpcEvaluateService {
    state: Arc<AppState>,
    gate: RequestGate,
}

impl GrpcEvaluateService {
    /// With the default listener limits' in-flight cap.
    #[must_use]
    pub fn new(state: Arc<AppState>) -> Self {
        Self::with_limits(state, &ListenerLimits::default())
    }

    /// With `limits.max_in_flight` calls handled at once; a call over it is
    /// answered `UNAVAILABLE` (with `retry-after`) at once.
    #[must_use]
    pub fn with_limits(state: Arc<AppState>, limits: &ListenerLimits) -> Self {
        Self {
            state,
            gate: RequestGate::new(limits),
        }
    }
}

/// The client's leaf certificate: from our own TLS stream
/// ([`crate::tls::serve_grpc_until`]) or from tonic's.
fn peer_certificate<T>(request: &Request<T>) -> Option<PeerCertificate> {
    request
        .extensions()
        .get::<TlsConnectInfo<ConnHandle>>()
        .and_then(TlsConnectInfo::peer_certs)
        .or_else(|| request.peer_certs())
        .and_then(|chain| {
            chain
                .first()
                .map(|leaf| PeerCertificate::from_der(leaf.as_ref()))
        })
}

/// The connection's request state, when served by
/// [`crate::tls::serve_grpc_until`].
fn connection<T>(request: &Request<T>) -> Option<ConnHandle> {
    let extensions = request.extensions();
    extensions.get::<ConnHandle>().cloned().or_else(|| {
        extensions
            .get::<TlsConnectInfo<ConnHandle>>()
            .map(|info| info.get_ref().clone())
    })
}

#[tonic::async_trait]
impl EvaluateService for GrpcEvaluateService {
    async fn evaluate(
        &self,
        request: Request<ProtoEvaluateRequest>,
    ) -> Result<Response<ProtoEvaluateResponse>, Status> {
        let (_in_progress, _permit) =
            crate::limits::grpc_enter(&self.gate, connection(&request).as_ref())
                .map_err(|status| *status)?;
        let peer = peer_certificate(&request);
        authorize_metadata(
            self.state.as_ref(),
            request.metadata(),
            peer.as_ref(),
            KavachAction::Evaluate,
        )
        .await
        .map_err(|e| status_from_api(&e))?;
        self.state
            .ensure_runtime_pointer_current()
            .await
            .map_err(|e| status_from_api(&e))?;
        let domain_request =
            proto_to_domain(request.into_inner()).map_err(|e| status_from_api(&e))?;
        let response = self
            .state
            .evaluate("grpc", &domain_request)
            .map_err(|e| status_from_api(&e))?;
        Ok(Response::new(domain_to_proto(response)))
    }
}

pub fn status_from_api(err: &ApiError) -> Status {
    let code = match err {
        ApiError::Unauthorized => tonic::Code::Unauthenticated,
        ApiError::Forbidden | ApiError::ForbiddenBecause(_) => tonic::Code::PermissionDenied,
        ApiError::BadRequest(_)
        | ApiError::Evaluate(
            kavach_evaluate::EvaluateError::Validation(_)
            | kavach_evaluate::EvaluateError::ModelMismatch(_)
            | kavach_evaluate::EvaluateError::PackNotEffective,
        ) => tonic::Code::InvalidArgument,
        ApiError::Unavailable(_)
        | ApiError::Evaluate(kavach_evaluate::EvaluateError::Policy(
            kavach_policy::PolicyError::Timeout { .. },
        )) => tonic::Code::Unavailable,
        ApiError::NotFound(_) => tonic::Code::NotFound,
        ApiError::Evaluate(kavach_evaluate::EvaluateError::IdempotencyConflict(_)) => {
            tonic::Code::AlreadyExists
        }
        ApiError::Conflict(_) => tonic::Code::FailedPrecondition,
        ApiError::Evaluate(_) | ApiError::Internal(_) => tonic::Code::Internal,
    };
    Status::new(code, err.to_string())
}

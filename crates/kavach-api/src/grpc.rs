use std::sync::Arc;

use tonic::{Request, Response, Status};

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
}

impl GrpcEvaluateService {
    #[must_use]
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl EvaluateService for GrpcEvaluateService {
    async fn evaluate(
        &self,
        request: Request<ProtoEvaluateRequest>,
    ) -> Result<Response<ProtoEvaluateResponse>, Status> {
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
        ApiError::BadRequest(_)
        | ApiError::Evaluate(
            kavach_evaluate::EvaluateError::Validation(_)
            | kavach_evaluate::EvaluateError::ModelMismatch(_)
            | kavach_evaluate::EvaluateError::PackNotEffective,
        ) => tonic::Code::InvalidArgument,
        ApiError::Evaluate(kavach_evaluate::EvaluateError::Policy(
            kavach_policy::PolicyError::Timeout { .. },
        )) => tonic::Code::Unavailable,
        ApiError::Evaluate(_) | ApiError::Internal(_) => tonic::Code::Internal,
    };
    Status::new(code, err.to_string())
}

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::State,
    http::header,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};

use kavach_domain::EvaluateRequest;

use kavach_auth::KavachAction;

use crate::auth::{authorize_credentials, Credentials};
use crate::batch_jobs::{get_batch_job, list_batch_jobs};
use crate::change_requests;
use crate::error::ApiError;
use crate::governance::{
    get_model_record, get_policy_pack, list_model_records, list_policy_packs, runtime,
};
use crate::incidents::list_incidents;
use crate::lifecycle::list_audit_log;
use crate::retention::{get_retention_settings, list_tombstones};
use crate::state::AppState;

pub fn router(state: Arc<AppState>) -> Router {
    let router = Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .route("/v1/evaluate", post(evaluate))
        .route("/v1/runtime", get(runtime))
        .route("/v1/packs", get(list_policy_packs))
        .route("/v1/packs/{pack_id}", get(get_policy_pack))
        .route("/v1/models", get(list_model_records))
        .route("/v1/models/{model_id}", get(get_model_record))
        .route(
            "/v1/change-requests",
            get(change_requests::list).post(change_requests::propose),
        )
        .route("/v1/change-requests/{id}", get(change_requests::get))
        .route(
            "/v1/change-requests/{id}/approve",
            post(change_requests::approve),
        )
        .route(
            "/v1/change-requests/{id}/reject",
            post(change_requests::reject),
        )
        .route(
            "/v1/change-requests/{id}/cancel",
            post(change_requests::cancel),
        )
        .route("/v1/admin/audit", get(list_audit_log))
        .route(
            "/v1/agent-decisions/{record_id}",
            get(crate::evidence_read::read_agent_decision),
        )
        .route("/v1/dev/clock", post(crate::dev_clock::set_dev_clock))
        .route(
            "/v1/decision-events/{evidence_id}",
            get(crate::evidence_read::read_decision_event),
        )
        .route("/v1/admin/retention", get(get_retention_settings))
        .route("/v1/admin/tombstones", get(list_tombstones))
        .route("/v1/admin/incidents", get(list_incidents))
        .route("/v1/admin/batch-jobs", get(list_batch_jobs))
        .route("/v1/admin/batch-jobs/{job_id}", get(get_batch_job));

    // The governance console, when it was built into this binary; else an
    // unknown path is a problem.
    #[cfg(console_embedded)]
    let router = router.fallback(crate::console::fallback);
    #[cfg(not(console_embedded))]
    let router = router.fallback(crate::problem::not_found);

    router
        .method_not_allowed_fallback(crate::problem::method_not_allowed)
        .route_layer(axum::middleware::from_fn(crate::correlation::correlate))
        .with_state(state)
}

async fn health(
    State(state): State<Arc<AppState>>,
    credentials: Credentials,
) -> Result<Json<serde_json::Value>, ApiError> {
    authorize_credentials(&state, &credentials, KavachAction::ReadHealth)?;
    Ok(Json(serde_json::json!({ "status": "ok" })))
}

async fn metrics(
    State(state): State<Arc<AppState>>,
    credentials: Credentials,
) -> Result<impl IntoResponse, ApiError> {
    authorize_credentials(&state, &credentials, KavachAction::ReadMetrics)?;
    let body = state
        .metrics()
        .gather_text()
        .map_err(|e| ApiError::Internal(format!("metrics gather: {e}")))?;
    Ok((
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    ))
}

async fn evaluate(
    State(state): State<Arc<AppState>>,
    method: axum::http::Method,
    uri: axum::http::Uri,
    credentials: Credentials,
    body: Bytes,
) -> Result<Json<kavach_domain::EvaluateResponse>, ApiError> {
    if let Some(secret) = state.hmac_secret() {
        let path = uri.path_and_query().map_or(uri.path(), |pq| pq.as_str());
        crate::hmac_auth::verify(
            secret,
            state.nonces(),
            &credentials.headers,
            method.as_str(),
            path,
            &body,
            chrono::Utc::now().timestamp(),
        )?;
    }
    authorize_credentials(state.as_ref(), &credentials, KavachAction::Evaluate)?;
    if crate::strict_json::uses_raw_value_key(&body) {
        return Err(ApiError::BadRequest(crate::strict_json::refusal_message()));
    }
    let request: EvaluateRequest = serde_json::from_slice(&body).map_err(|e| {
        ApiError::BadRequest(format!(
            "invalid JSON body: {}",
            crate::problem::json_error_detail(&e)
        ))
    })?;
    let response = state.evaluate("http", &request)?;
    Ok(Json(response))
}

impl From<ApiError> for crate::problem::Problem {
    fn from(error: ApiError) -> Self {
        use crate::problem::Problem;
        use kavach_evaluate::EvaluateError as E;
        let status = error.status_code();
        match error {
            ApiError::Unauthorized => {
                Problem::new(status, "unauthorized", "a valid bearer token is required")
            }
            ApiError::Forbidden => {
                Problem::new(status, "forbidden", "this principal may not do this")
            }
            ApiError::ForbiddenBecause(why) => Problem::new(status, "forbidden", why),
            ApiError::BadRequest(why) => Problem::new(status, "bad_request", why),
            ApiError::NotFound(what) => Problem::new(status, "not_found", what),
            ApiError::Conflict(why) => Problem::new(status, "conflict", why),
            ApiError::Evaluate(E::Validation(why)) => Problem::new(status, "validation", why),
            ApiError::Evaluate(E::ModelMismatch(why)) => {
                Problem::new(status, "model_mismatch", why)
            }
            ApiError::Evaluate(E::PackNotEffective) => Problem::new(
                status,
                "pack_not_effective",
                "no policy pack is effective at server time",
            ),
            ApiError::Evaluate(E::IdempotencyConflict(why)) => {
                Problem::new(status, "conflict", why)
            }
            ApiError::Evaluate(e) if status == axum::http::StatusCode::SERVICE_UNAVAILABLE => {
                Problem::unavailable(&e)
            }
            ApiError::Evaluate(e) => Problem::internal(&e),
            ApiError::Internal(cause) => Problem::internal(&cause),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        crate::problem::Problem::from(self).into_response()
    }
}

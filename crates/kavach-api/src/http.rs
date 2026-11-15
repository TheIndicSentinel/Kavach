use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::State,
    http::{header, HeaderValue},
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

/// The operator router. In agent-only mode (hosted builds, where the credit
/// track is frozen) it serves the operator surface of the agent path alone:
/// health, metrics, runtime, change requests, the audit log and the evidence
/// reads. Every other API route is an unknown path. The console is served
/// in both modes (see [`crate::console`]).
pub fn router(state: Arc<AppState>) -> Router {
    let agent_only = state
        .dataplane()
        .is_some_and(crate::dataplane::Dataplane::agent_only);
    let router = Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .route("/v1/runtime", get(runtime))
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
        .route(
            "/v1/agent-revocations/{system}/{event_id}",
            get(crate::evidence_read::read_revocation_record),
        )
        .route(
            "/v1/reconciliation/closed-records",
            post(crate::closed_records::reconcile_closed_records),
        )
        .route("/v1/agents", get(crate::agents::list_agents))
        .route("/v1/agents/{agent_id}", get(crate::agents::get_agent))
        .route(
            "/v1/agents/{agent_id}/restrict",
            post(crate::agents::restrict),
        )
        .route(
            "/v1/agents/{agent_id}/quarantine",
            post(crate::agents::quarantine),
        )
        .route("/v1/agents/{agent_id}/revoke", post(crate::agents::revoke));
    // The development clock endpoint is not mounted at all under
    // `--require-hardening` (it answers 404), not merely refused.
    let router = if state.require_hardening() {
        router
    } else {
        router.route("/v1/dev/clock", post(crate::dev_clock::set_dev_clock))
    };

    // The credit track: Decision Governance (evaluate, packs, models,
    // decision events, retention, tombstones, incidents, batch). The console
    // is served in both modes and leaves these pages out when agent-only.
    let router = if agent_only {
        router
    } else {
        router
            .route("/v1/evaluate", post(evaluate))
            .route("/v1/packs", get(list_policy_packs))
            .route("/v1/packs/{pack_id}", get(get_policy_pack))
            .route("/v1/models", get(list_model_records))
            .route("/v1/models/{model_id}", get(get_model_record))
            .route(
                "/v1/decision-events/{evidence_id}",
                get(crate::evidence_read::read_decision_event),
            )
            .route("/v1/admin/retention", get(get_retention_settings))
            .route("/v1/admin/tombstones", get(list_tombstones))
            .route("/v1/admin/incidents", get(list_incidents))
            .route("/v1/admin/batch-jobs", get(list_batch_jobs))
            .route("/v1/admin/batch-jobs/{job_id}", get(get_batch_job))
    };

    // The governance console, in both modes: the built console when this
    // binary has one, else a plain "not built" page. API paths stay problems.
    let router = router.fallback(crate::console::fallback);

    router
        .method_not_allowed_fallback(crate::problem::method_not_allowed)
        .route_layer(axum::middleware::from_fn(crate::correlation::correlate))
        .layer(api_security_headers())
        .with_state(state)
}

/// The API's Content-Security-Policy. The API serves no HTML, so nothing
/// may load from a response and nothing may frame one.
pub const API_CONTENT_SECURITY_POLICY: &str = "default-src 'none'; frame-ancestors 'none'";

/// The API's cache policy: no response is stored.
pub const API_CACHE_CONTROL: &str = "no-store";

/// The function [`api_security_headers`] maps each response with.
pub type SetApiHeaders = fn(Response) -> std::future::Ready<Response>;

/// The layer that sets the security headers on every response of an HTTP
/// listener (the operator, agent and system-of-record routers), problems,
/// 404 and 405 included. Install with `layer`, not `route_layer`, so the
/// fallbacks are covered too. A header the response already carries is
/// kept: the console's responses set their own policy and cache policy
/// ([`crate::console::security_headers`]), and those stand.
pub fn api_security_headers() -> axum::middleware::MapResponseLayer<SetApiHeaders, (), ()> {
    axum::middleware::map_response(set_api_headers as SetApiHeaders)
}

fn set_api_headers(mut response: Response) -> std::future::Ready<Response> {
    let headers = response.headers_mut();
    for (name, value) in [
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::CACHE_CONTROL, API_CACHE_CONTROL),
        (header::REFERRER_POLICY, "no-referrer"),
        (header::CONTENT_SECURITY_POLICY, API_CONTENT_SECURITY_POLICY),
    ] {
        headers
            .entry(name)
            .or_insert_with(|| HeaderValue::from_static(value));
    }
    std::future::ready(response)
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
            ApiError::Unavailable(cause) => Problem::unavailable(&cause),
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

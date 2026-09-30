use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::State,
    http::header,
    http::HeaderMap,
    response::{IntoResponse, Response},
    routing::{get, patch, post},
    Json, Router,
};

use kavach_domain::EvaluateRequest;

use kavach_auth::KavachAction;

use crate::auth::authorize_headers;
use crate::batch_jobs::{get_batch_job, list_batch_jobs};
use crate::error::ApiError;
use crate::governance::{
    get_model_record, get_policy_pack, list_model_records, list_policy_packs, runtime,
};
use crate::incidents::list_incidents;
use crate::lifecycle::{activate_pack, list_audit_log, rollback_pack, update_model_record};
use crate::retention::{
    apply_retention, erase_evidence, get_retention_settings, list_tombstones,
    update_retention_settings,
};
use crate::state::AppState;

pub fn router(state: Arc<AppState>) -> Router {
    let mut router = Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .route("/v1/evaluate", post(evaluate))
        .route("/v1/runtime", get(runtime))
        .route("/v1/packs", get(list_policy_packs))
        .route("/v1/packs/{pack_id}", get(get_policy_pack))
        .route("/v1/models", get(list_model_records))
        .route("/v1/models/{model_id}", get(get_model_record))
        .route("/v1/models/{model_id}", patch(update_model_record))
        .route("/v1/packs/{pack_id}/activate", post(activate_pack))
        .route("/v1/packs/rollback", post(rollback_pack))
        .route("/v1/admin/audit", get(list_audit_log))
        .route("/v1/admin/retention", get(get_retention_settings))
        .route("/v1/admin/retention", patch(update_retention_settings))
        .route("/v1/admin/retention/apply", post(apply_retention))
        .route("/v1/admin/tombstones", get(list_tombstones))
        .route("/v1/admin/incidents", get(list_incidents))
        .route("/v1/admin/batch-jobs", get(list_batch_jobs))
        .route("/v1/admin/batch-jobs/{job_id}", get(get_batch_job))
        .route(
            "/v1/admin/evidence/{evidence_id}/erase",
            post(erase_evidence),
        );

    #[cfg(console_embedded)]
    {
        router = router.fallback(crate::console::fallback);
    }

    router.with_state(state)
}

async fn health(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    authorize_headers(&state, &headers, KavachAction::ReadHealth)?;
    Ok(Json(serde_json::json!({ "status": "ok" })))
}

async fn metrics(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    authorize_headers(&state, &headers, KavachAction::ReadMetrics)?;
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
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<kavach_domain::EvaluateResponse>, ApiError> {
    if let Some(secret) = state.hmac_secret() {
        let path = uri.path_and_query().map_or(uri.path(), |pq| pq.as_str());
        crate::hmac_auth::verify(
            secret,
            state.nonces(),
            &headers,
            method.as_str(),
            path,
            &body,
            chrono::Utc::now().timestamp(),
        )?;
    }
    authorize_headers(state.as_ref(), &headers, KavachAction::Evaluate)?;
    let request: EvaluateRequest = serde_json::from_slice(&body)
        .map_err(|e| ApiError::BadRequest(format!("invalid JSON body: {e}")))?;
    let response = state.evaluate("http", &request)?;
    Ok(Json(response))
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let body = Json(serde_json::json!({ "error": self.to_string() }));
        (status, body).into_response()
    }
}

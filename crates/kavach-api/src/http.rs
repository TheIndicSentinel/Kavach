use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::State,
    http::header,
    http::HeaderMap,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};

use hmac::{Hmac, Mac};
use kavach_domain::EvaluateRequest;
use sha2::Sha256;

use crate::error::ApiError;
use crate::state::AppState;

type HmacSha256 = Hmac<Sha256>;

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .route("/v1/evaluate", post(evaluate))
        .with_state(state)
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn metrics(State(state): State<Arc<AppState>>) -> Result<impl IntoResponse, ApiError> {
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
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<kavach_domain::EvaluateResponse>, ApiError> {
    verify_hmac_if_configured(state.as_ref(), &headers, &body)?;
    let request: EvaluateRequest = serde_json::from_slice(&body)
        .map_err(|e| ApiError::BadRequest(format!("invalid JSON body: {e}")))?;
    let response = state.evaluate("http", &request)?;
    Ok(Json(response))
}

fn verify_hmac_if_configured(
    state: &AppState,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(), ApiError> {
    let Some(secret) = state.hmac_secret() else {
        return Ok(());
    };

    let signature = headers
        .get("x-kavach-signature")
        .and_then(|value| value.to_str().ok())
        .ok_or(ApiError::Unauthorized)?;

    let expected = format!("sha256={}", hex_hmac(secret, body));
    if constant_time_eq(signature.as_bytes(), expected.as_bytes()) {
        Ok(())
    } else {
        Err(ApiError::Unauthorized)
    }
}

fn hex_hmac(secret: &str, body: &[u8]) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let body = Json(serde_json::json!({ "error": self.to_string() }));
        (status, body).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_hmac_is_deterministic() {
        let digest = hex_hmac("secret", b"{}");
        assert_eq!(digest.len(), 64);
        assert_eq!(digest, hex_hmac("secret", b"{}"));
    }
}

//! Request correlation (H5b): every request gets a correlation id and one
//! log line with method, route template, status and latency.
//!
//! - A caller's `x-request-id` is kept only if it is short and plain
//!   (`[A-Za-z0-9._-]{1,64}`); anything else is replaced by a fresh UUID, so
//!   a header cannot inject text into logs.
//! - The id is echoed in the response and set on a `tracing` span, so every
//!   log line written while handling the request carries it.
//! - The route is the matched template (`/v1/tools/{tool}`), never the raw
//!   path or query, which can carry caller-controlled text.

use std::time::Instant;

use axum::extract::{MatchedPath, Request};
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use tracing::Instrument;

pub const REQUEST_ID_HEADER: &str = "x-request-id";

/// The id for this request: the caller's if well-formed, else a new UUID.
fn request_id(req: &Request) -> String {
    req.headers()
        .get(REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .filter(|v| kavach_telemetry::valid_request_id(v))
        .map_or_else(|| uuid::Uuid::new_v4().to_string(), str::to_string)
}

/// Axum middleware (install with `route_layer`, so the route is known).
pub async fn correlate(req: Request, next: Next) -> Response {
    let (id, span) = begin(&req);
    let started = Instant::now();
    let response = next.run(req).instrument(span.clone()).await;
    finish(&id, &span, started, response).await
}

/// Correlates a router fallback's response the same way: `route_layer`
/// does not wrap fallbacks, so they call this themselves.
pub async fn unmatched(req: Request, response: Response) -> Response {
    let (id, span) = begin(&req);
    drop(req);
    finish(&id, &span, Instant::now(), response).await
}

fn begin(req: &Request) -> (String, tracing::Span) {
    let id = request_id(req);
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map_or("unmatched", MatchedPath::as_str)
        .to_string();
    let method = req.method().clone();
    let span = tracing::info_span!("request", request_id = %id, method = %method, route = %route);
    (id, span)
}

async fn finish(
    id: &str,
    span: &tracing::Span,
    started: Instant,
    mut response: Response,
) -> Response {
    let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    span.in_scope(|| {
        tracing::info!(status = response.status().as_u16(), latency_ms, "handled");
    });
    if let Ok(value) = HeaderValue::from_str(id) {
        response.headers_mut().insert(REQUEST_ID_HEADER, value);
    }
    with_request_id(response, id).await
}

/// Adds `request_id` to a problem body (RFC 9457 extension), so a caller
/// can quote it to support; other responses pass through untouched.
async fn with_request_id(response: Response, id: &str) -> Response {
    let is_problem = response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with(crate::problem::CONTENT_TYPE));
    if !is_problem {
        // An extractor's own rejection (axum's text, which can quote the
        // caller's input): replaced by a generic problem for its status.
        let status = response.status();
        if !(status.is_client_error() || status.is_server_error()) {
            return response;
        }
        let mut generic = crate::problem::Problem::generic(status).into_response();
        if let Some(value) = response.headers().get(REQUEST_ID_HEADER) {
            generic
                .headers_mut()
                .insert(REQUEST_ID_HEADER, value.clone());
        }
        return Box::pin(with_request_id(generic, id)).await;
    }
    let (mut parts, body) = response.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, 64 * 1024).await else {
        return Response::from_parts(parts, axum::body::Body::empty());
    };
    let body = match serde_json::from_slice::<serde_json::Value>(&bytes) {
        Ok(mut problem) => {
            problem["request_id"] = id.into();
            problem.to_string().into_bytes()
        }
        Err(_) => bytes.to_vec(),
    };
    parts.headers.remove(axum::http::header::CONTENT_LENGTH);
    Response::from_parts(parts, axum::body::Body::from(body))
}

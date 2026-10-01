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
use axum::response::Response;
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
    let id = request_id(&req);
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map_or("unmatched", MatchedPath::as_str)
        .to_string();
    let method = req.method().clone();
    let span = tracing::info_span!("request", request_id = %id, method = %method, route = %route);
    let started = Instant::now();
    let mut response = next.run(req).instrument(span.clone()).await;
    let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    span.in_scope(|| {
        tracing::info!(status = response.status().as_u16(), latency_ms, "handled");
    });
    if let Ok(value) = HeaderValue::from_str(&id) {
        response.headers_mut().insert(REQUEST_ID_HEADER, value);
    }
    response
}

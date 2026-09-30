//! Change-request helpers shared by the API integration tests.
#![allow(dead_code)]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

/// Credentials for one request: `(header, value)` pairs.
pub type Creds = Vec<(&'static str, String)>;

#[must_use]
pub fn as_principal(id: &str) -> Creds {
    vec![("x-kavach-principal", id.to_string())]
}

pub async fn call(
    app: &axum::Router,
    method: &str,
    uri: &str,
    creds: &Creds,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut req = Request::builder().method(method).uri(uri);
    for (k, v) in creds {
        req = req.header(*k, v);
    }
    let body = match body {
        Some(value) => {
            req = req.header("content-type", "application/json");
            Body::from(value.to_string())
        }
        None => Body::empty(),
    };
    let response = app.clone().oneshot(req.body(body).unwrap()).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

pub async fn propose(
    app: &axum::Router,
    creds: &Creds,
    kind: &str,
    params: Value,
) -> (StatusCode, Value) {
    call(
        app,
        "POST",
        "/v1/change-requests",
        creds,
        Some(json!({ "kind": kind, "params": params })),
    )
    .await
}

pub async fn approve(app: &axum::Router, creds: &Creds, request: &Value) -> (StatusCode, Value) {
    let id = request["id"].as_str().expect("request id");
    call(
        app,
        "POST",
        &format!("/v1/change-requests/{id}/approve"),
        creds,
        Some(json!({ "change_digest": request["change_digest"] })),
    )
    .await
}

/// Proposes as `proposer` and approves as `approver`; returns the first
/// non-success status, or the approval's.
pub async fn apply_change(
    app: &axum::Router,
    kind: &str,
    params: Value,
    proposer: &Creds,
    approver: &Creds,
) -> StatusCode {
    let (status, request) = propose(app, proposer, kind, params).await;
    if status != StatusCode::CREATED {
        return status;
    }
    approve(app, approver, &request).await.0
}

/// Header principals for development-mode tests (`--insecure-dev`).
pub async fn apply_as_admins(app: &axum::Router, kind: &str, params: Value) -> StatusCode {
    apply_change(
        app,
        kind,
        params,
        &as_principal("admin-1"),
        &as_principal("admin-2"),
    )
    .await
}

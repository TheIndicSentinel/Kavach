//! Contract checks (C6b): every response an integration test sees is held
//! to `docs/openapi.yaml`. The routers here wrap the real ones with a layer
//! that checks the status is documented for the route, the content type is
//! the documented one, and the body validates against the schema.
//!
//! A route or status the spec does not document fails the test that hit it,
//! so the spec cannot drift from what the API returns.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use axum::body::Body;
use axum::extract::Request;
use axum::http::header::CONTENT_TYPE;
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::Router;
use kavach_api::AppState;
use serde_json::{json, Value};

pub fn spec() -> &'static Value {
    static SPEC: OnceLock<Value> = OnceLock::new();
    SPEC.get_or_init(|| {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/openapi.yaml");
        let text = std::fs::read_to_string(path).expect("docs/openapi.yaml");
        serde_yaml::from_str(&text).expect("docs/openapi.yaml is YAML")
    })
}

pub fn router(state: Arc<AppState>) -> Router {
    checked(kavach_api::router(state), "operator")
}

pub fn agent_router(state: Arc<AppState>) -> Router {
    checked(kavach_api::dataplane::agent_router(state), "agent")
}

pub fn sor_router(state: Arc<AppState>) -> Router {
    checked(kavach_api::dataplane::sor_router(state), "sor")
}

/// `app` (the `listener` named in the spec's `x-kavach-listeners`), with
/// every response checked against the spec.
pub fn checked(app: Router, listener: &'static str) -> Router {
    app.layer(middleware::from_fn(move |req: Request, next: Next| {
        check(listener, req, next)
    }))
}

async fn check(listener: &'static str, req: Request, next: Next) -> Response {
    let method = req.method().as_str().to_ascii_lowercase();
    let path = req.uri().path().to_string();
    let response = next.run(req).await;
    let (parts, body) = response.into_parts();
    let bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .expect("a response body");
    let content_type = parts
        .headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_string();
    validate(
        listener,
        &method,
        &path,
        parts.status.as_u16(),
        &content_type,
        &bytes,
    );
    Response::from_parts(parts, Body::from(bytes))
}

/// The listeners that serve a path (`x-kavach-listeners`; operator if absent).
pub fn listeners(item: &Value) -> Vec<&str> {
    item["x-kavach-listeners"].as_array().map_or_else(
        || vec!["operator"],
        |l| l.iter().filter_map(Value::as_str).collect(),
    )
}

/// The spec's path template on `listener` that `path` matches (`{x}` is
/// one segment).
pub fn template_for(listener: &str, path: &str) -> Option<&'static str> {
    let segments: Vec<&str> = path.split('/').collect();
    spec()["paths"]
        .as_object()?
        .iter()
        .filter(|(_, item)| listeners(item).contains(&listener))
        .map(|(template, _)| template)
        .find(|template| {
            let parts: Vec<&str> = template.split('/').collect();
            parts.len() == segments.len()
                && parts.iter().zip(&segments).all(|(t, s)| {
                    (t.starts_with('{') && t.ends_with('}') && !s.is_empty()) || t == s
                })
        })
        .map(String::as_str)
}

/// Follows a local `$ref` (`#/components/...`).
fn resolve(value: &'static Value) -> &'static Value {
    match value["$ref"].as_str() {
        Some(pointer) => resolve(
            spec()
                .pointer(pointer.trim_start_matches('#'))
                .unwrap_or_else(|| panic!("the spec has no {pointer}")),
        ),
        None => value,
    }
}

/// Checks one response against the spec; panics with what differs.
pub fn validate(
    listener: &str,
    method: &str,
    path: &str,
    status: u16,
    content_type: &str,
    body: &[u8],
) {
    let shown = format!("{} {path} -> {status} ({listener})", method.to_uppercase());
    let Some(template) = template_for(listener, path) else {
        // Not an API path: the console's pages, or a not-found problem.
        if status == 200 && content_type.starts_with("text/") {
            return;
        }
        let problem = &spec()["components"]["responses"]["Problem"];
        return check_content(&shown, problem, content_type, body);
    };
    let item = &spec()["paths"][template];
    let Some(operation) = item.get(method) else {
        assert_eq!(
            status, 405,
            "{shown}: the spec has no {method} on {template}"
        );
        let problem = &spec()["components"]["responses"]["Problem"];
        return check_content(&shown, problem, content_type, body);
    };
    let responses = &operation["responses"];
    let response = responses
        .get(status.to_string())
        .or_else(|| responses.get("default"))
        .unwrap_or_else(|| {
            panic!("{shown}: status {status} is not documented for {method} {template}")
        });
    check_content(&shown, resolve(response), content_type, body);
}

fn check_content(shown: &str, response: &'static Value, content_type: &str, body: &[u8]) {
    let Some(content) = response["content"].as_object().filter(|c| !c.is_empty()) else {
        assert!(body.is_empty(), "{shown}: the spec documents no body");
        return;
    };
    let media = content.get(content_type).unwrap_or_else(|| {
        panic!(
            "{shown}: content type {content_type:?} is not documented ({:?})",
            content.keys().collect::<Vec<_>>()
        )
    });
    if !(content_type.ends_with("json")) {
        return;
    }
    let instance: Value = serde_json::from_slice(body)
        .unwrap_or_else(|e| panic!("{shown}: the body is not JSON ({e})"));
    let schema = &media["schema"];
    let validator = validator_for(schema);
    let errors: Vec<String> = validator
        .iter_errors(&instance)
        .map(|e| format!("{} at {}: {e}", e.schema_path, e.instance_path))
        .collect();
    assert!(
        errors.is_empty(),
        "{shown}: the body does not match the spec:\n  {}\nbody: {instance}",
        errors.join("\n  ")
    );
}

/// A validator for one schema of the spec, with the spec's components in
/// reach of its `$ref`s; compiled once per schema.
fn validator_for(schema: &'static Value) -> Arc<jsonschema::Validator> {
    static CACHE: OnceLock<Mutex<HashMap<usize, Arc<jsonschema::Validator>>>> = OnceLock::new();
    let key = std::ptr::from_ref(schema) as usize;
    let mut cache = CACHE.get_or_init(Default::default).lock().unwrap();
    Arc::clone(cache.entry(key).or_insert_with(|| {
        let root = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "components": spec()["components"],
            "allOf": [schema],
        });
        Arc::new(jsonschema::validator_for(&root).expect("a valid schema in docs/openapi.yaml"))
    }))
}

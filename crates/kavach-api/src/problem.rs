//! RFC 9457 problem details: the one shape every refusal takes.
//!
//! `application/problem+json` with `type`, `title`, `status`, `detail`, and
//! three extensions: `code` (a stable machine code, from [`CODES`]),
//! `request_id` (the request's correlation id, added by the correlation
//! layer, to quote to support) and, until v0.1 ends, `error` (the text
//! `detail` holds, for clients written against the old `{"error": …}`).
//!
//! - `type` is a relative URI, `/problems/<code>`: valid under RFC 9457,
//!   documented in the OpenAPI file, and not meant to be dereferenced yet.
//! - A 5xx never carries its cause: `detail` is generic, the cause goes to
//!   the (redacted) log, linked by the request id.
//! - Messages never echo caller input beyond plain identifiers; a test
//!   sends hostile input and checks no problem body repeats it.
//! - Headers: `WWW-Authenticate` on 401 (RFC 6750), `Retry-After` on 429
//!   and 503.
//!
//! Decisions are not problems: a BLOCK or HUMAN_REVIEW is a 200 reply with
//! reasons.

use axum::extract::rejection::JsonRejection;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::json;

pub const CONTENT_TYPE: &str = "application/problem+json";

/// Every problem code, its title, and the usual way out.
pub const CODES: &[(&str, &str, &str)] = &[
    // The API.
    (
        "bad_request",
        "Bad request",
        "fix the request; the detail says what is wrong",
    ),
    ("unauthorized", "Unauthorized", "send a valid bearer token"),
    (
        "forbidden",
        "Forbidden",
        "use a principal allowed to do this",
    ),
    ("not_found", "Not found", "check the path or the id"),
    (
        "method_not_allowed",
        "Method not allowed",
        "use the method the API documents for this path",
    ),
    (
        "conflict",
        "Conflict",
        "the resource changed or the id was used for something else; reload and retry",
    ),
    (
        "rate_limited",
        "Too many requests",
        "retry after the time in Retry-After",
    ),
    (
        "unavailable",
        "Service unavailable",
        "retry after the time in Retry-After",
    ),
    (
        "internal",
        "Internal error",
        "quote the request_id when reporting it",
    ),
    (
        "not_forwardable",
        "Not forwardable",
        "this tool cannot be executed through the gateway",
    ),
    (
        "in_flight",
        "In flight",
        "an identical earlier call is still running; it is never run again: send it again later for its outcome",
    ),
    (
        "no_passport",
        "No passport",
        "the agent needs a passport in the mandate configuration",
    ),
    (
        "event_rejected",
        "Event rejected",
        "the system-of-record event is stale, unsigned, or outside its template",
    ),
    (
        "unprocessable",
        "Unprocessable content",
        "fix the body against the request's documented shape",
    ),
    (
        "payload_too_large",
        "Payload too large",
        "send a smaller body",
    ),
    (
        "unsupported_media_type",
        "Unsupported media type",
        "send Content-Type: application/json",
    ),
    // Tool requests (the signed registry).
    (
        "unknown_tool",
        "Unknown tool",
        "call a tool the registry lists",
    ),
    (
        "invalid_envelope",
        "Invalid envelope",
        "send a mandate_id and a request_id of 1-128 plain characters",
    ),
    (
        "unknown_parameter",
        "Unknown parameter",
        "send only the parameters the registry lists for this tool",
    ),
    (
        "missing_parameter",
        "Missing parameter",
        "send every required parameter the registry lists",
    ),
    (
        "invalid_parameter",
        "Invalid parameter",
        "send each parameter with the type and size the registry declares",
    ),
    // Decision requests (evaluate).
    (
        "validation",
        "Invalid decision request",
        "fix the request against the model's input schema and clock rules",
    ),
    (
        "model_mismatch",
        "Model mismatch",
        "send the model id and version the deployment runs",
    ),
    (
        "pack_not_effective",
        "Policy pack not effective",
        "activate a pack effective at server time",
    ),
];

fn title_of(code: &str) -> (&'static str, &'static str) {
    CODES
        .iter()
        .find(|(c, _, _)| *c == code)
        .map_or(("Error", ""), |(_, title, fix)| (title, fix))
}

/// One refusal.
#[derive(Debug, Clone)]
pub struct Problem {
    status: StatusCode,
    code: &'static str,
    detail: String,
}

impl Problem {
    /// A refusal with a stable `code` (from [`CODES`]) and a `detail` that
    /// must not repeat caller input beyond plain identifiers.
    pub fn new(status: StatusCode, code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            status,
            code,
            detail: detail.into(),
        }
    }

    /// A refusal whose code follows from its status (the API's own codes).
    /// A 503 or 5xx detail is replaced by a generic one, with the given
    /// text logged instead.
    pub fn for_status(status: StatusCode, detail: impl Into<String>) -> Self {
        let detail = detail.into();
        let code = match status.as_u16() {
            400 => "bad_request",
            401 => "unauthorized",
            403 => "forbidden",
            404 => "not_found",
            405 => "method_not_allowed",
            409 => "conflict",
            413 => "payload_too_large",
            415 => "unsupported_media_type",
            422 => "unprocessable",
            429 => "rate_limited",
            501 => "not_forwardable",
            503 => return Self::unavailable(&detail),
            s if s >= 500 => return Self::internal(&detail),
            _ => "bad_request",
        };
        Self::new(status, code, detail)
    }

    /// A refused JSON body. The parser's own message can quote the caller's
    /// values, so it is never returned: only the field it names, when that
    /// is a schema field (`missing field`) or a plain identifier.
    #[must_use]
    pub fn from_json_rejection(rejection: &JsonRejection) -> Self {
        let status = rejection.status();
        match rejection {
            JsonRejection::JsonDataError(e) => {
                Self::for_status(status, data_error_detail(&e.body_text()))
            }
            JsonRejection::JsonSyntaxError(_) => Self::new(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "the body is not valid JSON",
            ),
            JsonRejection::MissingJsonContentType(_) => Self::new(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "unsupported_media_type",
                "the body must be sent with Content-Type: application/json",
            ),
            _ if status == StatusCode::PAYLOAD_TOO_LARGE => {
                Self::for_status(status, "the body is larger than this endpoint takes")
            }
            _ => Self::for_status(status, "the body could not be read"),
        }
    }

    /// A refusal that did not come from [`Problem`] (an extractor's own
    /// rejection): its text is dropped, since it can quote the caller's
    /// input, and only the status is kept.
    #[must_use]
    pub fn generic(status: StatusCode) -> Self {
        Self::for_status(
            status,
            format!(
                "the request was refused ({})",
                status.canonical_reason().unwrap_or("error").to_lowercase()
            ),
        )
    }

    /// A 5xx: the cause is logged (redacted), never returned.
    pub fn internal(cause: &impl std::fmt::Display) -> Self {
        tracing::error!(cause = %cause, "internal error");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "an internal error occurred; quote the request_id when reporting it",
        )
    }

    /// A 503: the cause is logged, never returned.
    pub fn unavailable(cause: &impl std::fmt::Display) -> Self {
        tracing::warn!(cause = %cause, "dependency unavailable");
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "a dependency is unavailable; retry later",
        )
    }

    #[must_use]
    pub fn status(&self) -> StatusCode {
        self.status
    }

    #[must_use]
    pub fn code(&self) -> &'static str {
        self.code
    }

    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl IntoResponse for Problem {
    fn into_response(self) -> Response {
        let (title, fix) = title_of(self.code);
        let mut body = json!({
            "type": format!("/problems/{}", self.code.replace('_', "-")),
            "title": title,
            "status": self.status.as_u16(),
            "detail": self.detail,
            "code": self.code,
            "error": self.detail,
        });
        if !fix.is_empty() {
            body["fix"] = fix.into();
        }
        let mut response = (self.status, body.to_string()).into_response();
        let headers = response.headers_mut();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(CONTENT_TYPE));
        match self.status {
            StatusCode::UNAUTHORIZED => {
                headers.insert(
                    header::WWW_AUTHENTICATE,
                    HeaderValue::from_static(r#"Bearer realm="kavach""#),
                );
            }
            StatusCode::TOO_MANY_REQUESTS => {
                headers.insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
            }
            StatusCode::SERVICE_UNAVAILABLE => {
                headers.insert(header::RETRY_AFTER, HeaderValue::from_static("5"));
            }
            _ => {}
        }
        response
    }
}

/// What a refusal may say about a body serde could not read: where the
/// syntax broke, or the field a data error names (never a value).
#[must_use]
pub fn json_error_detail(error: &serde_json::Error) -> String {
    match error.classify() {
        serde_json::error::Category::Data => data_error_detail(&error.to_string()),
        _ => format!(
            "the body is not valid JSON (line {}, column {})",
            error.line(),
            error.column()
        ),
    }
}

/// What a serde data error may say: the schema field it names, or an
/// unknown key if it is a plain identifier, never a value.
fn data_error_detail(text: &str) -> String {
    let named = |prefix: &str| {
        text.find(prefix).and_then(|at| {
            let rest = &text[at + prefix.len()..];
            rest.find('`').map(|end| &rest[..end])
        })
    };
    let plain = |name: &&str| {
        (1..=64).contains(&name.len())
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    };
    if let Some(field) = named("missing field `").filter(plain) {
        return format!("missing field {field}");
    }
    if text.contains("unknown field `") {
        return named("unknown field `").filter(plain).map_or_else(
            || "unknown field (not an identifier)".to_string(),
            |field| format!("unknown field {field}"),
        );
    }
    "a field has the wrong type or value".to_string()
}

/// A router's fallback: the problem for an unknown path, correlated like
/// a route's response.
pub async fn not_found(req: axum::extract::Request) -> Response {
    let problem = Problem::new(StatusCode::NOT_FOUND, "not_found", "no such path").into_response();
    crate::correlation::unmatched(req, problem).await
}

/// The problem for a known path with the wrong method (inside the routes'
/// `route_layer`, so already correlated).
pub async fn method_not_allowed() -> Problem {
    Problem::new(
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
        "this path does not take that method",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_unique_plain_and_titled() {
        let mut seen = std::collections::BTreeSet::new();
        for (code, title, _) in CODES {
            assert!(seen.insert(code), "{code} twice");
            assert!(
                code.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                "{code}"
            );
            assert!(!title.is_empty());
        }
    }

    #[test]
    fn the_registry_and_evaluate_codes_are_all_here() {
        use kavach_dataplane::RefusalCode::*;
        for code in [
            UnknownTool,
            InvalidEnvelope,
            UnknownParameter,
            MissingParameter,
            InvalidParameter,
        ] {
            assert!(
                CODES.iter().any(|(c, _, _)| *c == code.as_str()),
                "{}",
                code.as_str()
            );
        }
    }

    #[tokio::test]
    async fn problems_carry_type_code_and_standard_headers() {
        use http_body_util::BodyExt;
        let response = Problem::new(StatusCode::UNAUTHORIZED, "unauthorized", "token required")
            .into_response();
        assert_eq!(response.headers()[header::CONTENT_TYPE], CONTENT_TYPE);
        assert!(response.headers().contains_key(header::WWW_AUTHENTICATE));
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["type"], "/problems/unauthorized");
        assert_eq!(body["status"], 401);
        assert_eq!(body["code"], "unauthorized");
        assert_eq!(body["error"], body["detail"]);

        let busy = Problem::new(StatusCode::TOO_MANY_REQUESTS, "rate_limited", "slow down")
            .into_response();
        assert_eq!(busy.headers()[header::RETRY_AFTER], "1");
        let down =
            Problem::unavailable(&"db: connection refused to postgres://u:p@h/db").into_response();
        assert_eq!(down.headers()[header::RETRY_AFTER], "5");
        let detail: serde_json::Value =
            serde_json::from_slice(&down.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert!(!detail.to_string().contains("postgres"), "{detail}");
    }

    #[tokio::test]
    async fn internal_errors_never_carry_their_cause() {
        use http_body_util::BodyExt;
        let response =
            Problem::internal(&"SELECT * FROM agent_decisions WHERE ... password=secret")
                .into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let text = String::from_utf8(
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        for leak in ["SELECT", "agent_decisions", "secret"] {
            assert!(!text.contains(leak), "{text}");
        }
    }
}

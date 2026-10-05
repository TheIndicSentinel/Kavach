//! The API's refusals: RFC 9457 problems (`application/problem+json`),
//! read into the CLI's error with their `code` and `request_id`.
//!
//! The server's `fix` is generic (one per code); a caller that knows the
//! situation better gives its own with [`CliError::fix`] afterwards.

use serde_json::Value;

use crate::output::{CliError, ProblemRef};

/// The refusal in `body`, as `what`'s error: the `detail` (or the status,
/// for a body that is not a problem), the server's `fix`, and the `code`
/// and `request_id` to quote.
pub fn error(what: impl Into<String>, status: u16, body: &Value) -> CliError {
    let mut error = CliError::new(what, detail(status, body));
    if let Some(fix) = body["fix"].as_str() {
        error = error.fix(fix);
    }
    error.problem = body["code"].as_str().map(|code| {
        Box::new(ProblemRef {
            code: code.to_string(),
            request_id: body["request_id"].as_str().map(str::to_string),
        })
    });
    error
}

/// The refusal's text: `detail`, else the old `error` member, else the
/// status.
pub fn detail(status: u16, body: &Value) -> String {
    body["detail"]
        .as_str()
        .or_else(|| body["error"].as_str())
        .map_or_else(|| format!("HTTP {status}"), str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_problem_becomes_an_error_with_its_code_fix_and_request_id() {
        let body = json!({
            "type": "/problems/unknown-parameter", "title": "Unknown parameter",
            "status": 400, "detail": "send_reminder has no parameter amount",
            "code": "unknown_parameter", "fix": "send only the parameters the registry lists",
            "request_id": "req-1", "error": "send_reminder has no parameter amount",
        });
        let error = error("the gateway refused the call (400)", 400, &body);
        assert_eq!(error.why, "send_reminder has no parameter amount");
        assert_eq!(
            error.fix.as_deref(),
            Some("send only the parameters the registry lists")
        );
        let problem = error.problem.unwrap();
        assert_eq!(problem.code, "unknown_parameter");
        assert_eq!(problem.request_id.as_deref(), Some("req-1"));
    }

    #[test]
    fn a_body_that_is_not_a_problem_still_reads() {
        assert_eq!(detail(502, &Value::Null), "HTTP 502");
        assert_eq!(detail(400, &json!({ "error": "old shape" })), "old shape");
        assert!(error("refused", 502, &Value::Null).problem.is_none());
    }
}

use cel::objects::Value;
use cel::{to_value, Context};
use chrono::{DateTime, Utc};
use kavach_domain::EvaluateRequest;
use serde::Serialize;

use crate::error::PolicyError;

fn context_err(message: impl std::fmt::Display) -> PolicyError {
    PolicyError::CelExecute {
        rule_id: "context".to_string(),
        message: message.to_string(),
    }
}

/// Build a CEL context binding `value` as variable `name` plus the trusted
/// server time as `now` (a CEL timestamp). Rules must use `now` for time
/// decisions, never client-supplied timestamps (ADR-003 §8).
pub fn build_named_context<'a, T: Serialize>(
    name: &str,
    value: &T,
    now: DateTime<Utc>,
) -> Result<Context<'a>, PolicyError> {
    let mut context = Context::default();
    context
        .add_variable(name.to_string(), to_value(value).map_err(context_err)?)
        .map_err(context_err)?;
    context.add_variable_from_value("now", Value::Timestamp(now.fixed_offset()));
    Ok(context)
}

/// Build a CEL context with the evaluate request bound as `request` and the
/// trusted server time as `now`.
pub fn build_context(
    request: &EvaluateRequest,
    now: DateTime<Utc>,
) -> Result<Context<'_>, PolicyError> {
    build_named_context("request", request, now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cel::objects::Value;
    use chrono::Utc;
    use kavach_domain::Consent;

    #[test]
    fn builds_context_for_sample_request() {
        let request = EvaluateRequest {
            model_id: "m".into(),
            model_version: "1".into(),
            purpose: "credit_decision".into(),
            consent: Some(Consent {
                purpose_id: "credit_decision".into(),
                timestamp: Utc::now(),
                valid: None,
            }),
            input: serde_json::json!({ "debt_ratio": 0.32 }),
            output: None,
            score: None,
            confidence: Some(0.9),
            decision_time: Utc::now(),
            correlation_id: "c1".into(),
            idempotency_key: None,
        };
        let ctx = build_context(&request, Utc::now()).expect("context");
        let program = cel::Program::compile("request.input.debt_ratio < 0.40").unwrap();
        let result = program.execute(&ctx).unwrap();
        assert_eq!(result, Value::Bool(true));
    }
}

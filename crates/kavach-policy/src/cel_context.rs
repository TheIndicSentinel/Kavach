use cel_interpreter::{to_value, Context};
use kavach_domain::EvaluateRequest;

use crate::error::PolicyError;

/// Build a CEL context with the evaluate request bound as `request`.
pub fn build_context(request: &EvaluateRequest) -> Result<Context<'_>, PolicyError> {
    let cel_request = to_value(request).map_err(|e| PolicyError::CelExecute {
        rule_id: "context".to_string(),
        message: e.to_string(),
    })?;
    let mut context = Context::default();
    context
        .add_variable("request", cel_request)
        .map_err(|e| PolicyError::CelExecute {
            rule_id: "context".to_string(),
            message: e.to_string(),
        })?;
    Ok(context)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cel_interpreter::objects::Value;
    use chrono::Utc;
    use kavach_domain::Consent;

    #[test]
    fn builds_context_for_sample_request() {
        let request = EvaluateRequest {
            model_id: "m".into(),
            model_version: "1".into(),
            purpose: "credit_decision".into(),
            consent: Consent {
                purpose_id: "credit_decision".into(),
                timestamp: Utc::now(),
                valid: None,
            },
            input: serde_json::json!({ "debt_ratio": 0.32 }),
            output: None,
            score: None,
            confidence: Some(0.9),
            decision_time: Utc::now(),
            correlation_id: "c1".into(),
            idempotency_key: None,
        };
        let ctx = build_context(&request).expect("context");
        let program = cel_interpreter::Program::compile("request.input.debt_ratio < 0.40").unwrap();
        let result = program.execute(&ctx).unwrap();
        assert_eq!(result, Value::Bool(true));
    }
}

use jsonschema::Validator;
use kavach_domain::{EvaluateRequest, ModelRecord};
use serde_json::Value;

use crate::error::EvaluateError;

pub fn compile_input_validator(schema: &Value) -> Result<Validator, EvaluateError> {
    Validator::new(schema)
        .map_err(|e| EvaluateError::validation(format!("invalid input_schema: {e}")))
}

pub fn validate_input(validator: &Validator, input: &Value) -> Result<(), EvaluateError> {
    let errors: Vec<String> = validator.iter_errors(input).map(|e| describe(&e)).collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(EvaluateError::validation(format!(
            "input schema validation failed: {}",
            errors.join("; ")
        )))
    }
}

/// One schema failure, without the value that failed (the caller's data,
/// which a refusal must not repeat): the field's path, when it is plain,
/// and the schema keyword it failed.
fn describe(error: &jsonschema::ValidationError<'_>) -> String {
    let path = error.instance_path.to_string();
    let field = if path.is_empty() {
        "the input".to_string()
    } else if path.len() <= 128
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/_-.".contains(&b))
    {
        path
    } else {
        "a field whose name is not an identifier".to_string()
    };
    if let jsonschema::error::ValidationErrorKind::Required { property } = &error.kind {
        if let Some(name) = property.as_str() {
            return format!("{field}: missing required {name}");
        }
    }
    let schema_path = error.schema_path.to_string();
    let keyword = schema_path.rsplit('/').next().unwrap_or_default();
    format!("{field} fails {keyword}")
}

pub fn validate_supplier_controls(model: &ModelRecord) -> Result<(), EvaluateError> {
    use kavach_domain::{GovernanceMode, ModelOrigin, ModelStatus};

    if model.origin == ModelOrigin::Vendor
        && model.governance_mode == GovernanceMode::Enforce
        && model.status != ModelStatus::Production
    {
        return Err(EvaluateError::validation(
            "vendor model cannot run in enforce mode until promoted to production",
        ));
    }
    Ok(())
}

pub fn validate_model_binding(
    model: &ModelRecord,
    request: &EvaluateRequest,
) -> Result<(), EvaluateError> {
    if request.model_id != model.model_id {
        return Err(EvaluateError::ModelMismatch(format!(
            "model_id: expected {}, got {}",
            model.model_id, request.model_id
        )));
    }
    if request.model_version != model.version {
        return Err(EvaluateError::ModelMismatch(format!(
            "model_version: expected {}, got {}",
            model.version, request.model_version
        )));
    }
    if request.purpose != model.purpose {
        return Err(EvaluateError::ModelMismatch(format!(
            "purpose: expected {}, got {}",
            model.purpose, request.purpose
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn schema_failures_name_the_field_never_the_value() {
        let validator = compile_input_validator(&json!({
            "type": "object",
            "required": ["income"],
            "properties": {
                "income": { "type": "integer", "minimum": 0 },
                "pan": { "type": "string", "maxLength": 3 }
            },
            "additionalProperties": { "type": "integer" }
        }))
        .unwrap();
        let input = json!({
            "pan": "ABCPE1234F",
            "ABCPE1234F' OR 1=1": "+91 98765 43210"
        });
        let message = validate_input(&validator, &input).unwrap_err().to_string();
        for leak in ["ABCPE1234F", "98765", "OR 1=1"] {
            assert!(!message.contains(leak), "{message}");
        }
        assert!(message.contains("missing required income"), "{message}");
        assert!(message.contains("/pan fails maxLength"), "{message}");
    }
}

use jsonschema::Validator;
use kavach_domain::{EvaluateRequest, ModelRecord};
use serde_json::Value;

use crate::error::EvaluateError;

pub fn compile_input_validator(schema: &Value) -> Result<Validator, EvaluateError> {
    Validator::new(schema)
        .map_err(|e| EvaluateError::validation(format!("invalid input_schema: {e}")))
}

pub fn validate_input(validator: &Validator, input: &Value) -> Result<(), EvaluateError> {
    let errors: Vec<String> = validator
        .iter_errors(input)
        .map(|e| e.to_string())
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(EvaluateError::validation(format!(
            "input schema validation failed: {}",
            errors.join("; ")
        )))
    }
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

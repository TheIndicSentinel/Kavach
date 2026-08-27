use std::io::{BufRead, BufReader};
use std::path::Path;

use kavach_domain::Decision;

use crate::error::BatchError;
use crate::export::{BatchResultRow, BatchRowStatus};

#[derive(Debug, Clone)]
pub struct FairnessRow {
    pub line_number: usize,
    pub correlation_id: String,
    pub attribute_value: String,
    pub returned_decision: Option<Decision>,
    pub status: BatchRowStatus,
    pub inclusion_value: Option<bool>,
}

pub fn join_batch_rows(
    requests_path: &Path,
    results_path: &Path,
    attribute_path: &str,
    inclusion_field: &str,
) -> Result<Vec<FairnessRow>, BatchError> {
    let requests = parse_request_lines(requests_path)?;
    let results = parse_result_lines(results_path)?;

    if requests.len() != results.len() {
        return Err(BatchError::Fairness(format!(
            "request/result row count mismatch: {} requests vs {} results",
            requests.len(),
            results.len()
        )));
    }

    let mut rows = Vec::with_capacity(requests.len());
    for ((line_number, request), result) in requests.into_iter().zip(results) {
        if result.line_number != line_number {
            return Err(BatchError::Fairness(format!(
                "line_number mismatch at row {line_number}: result has {}",
                result.line_number
            )));
        }
        if result.correlation_id != request.correlation_id {
            return Err(BatchError::Fairness(format!(
                "correlation_id mismatch at line {line_number}"
            )));
        }

        let attribute_value = extract_dot_path(&request.body, attribute_path).ok_or_else(|| {
            BatchError::Fairness(format!(
                "missing attribute `{attribute_path}` at line {line_number}"
            ))
        })?;
        let inclusion_value = extract_bool_path(&request.body, inclusion_field);

        rows.push(FairnessRow {
            line_number,
            correlation_id: result.correlation_id,
            attribute_value,
            returned_decision: result.returned_decision,
            status: result.status,
            inclusion_value,
        });
    }

    Ok(rows)
}

struct ParsedRequest {
    correlation_id: String,
    body: serde_json::Value,
}

fn parse_request_lines(path: &Path) -> Result<Vec<(usize, ParsedRequest)>, BatchError> {
    let file = std::fs::File::open(path)?;
    parse_request_reader(BufReader::new(file))
}

fn parse_request_reader<R: BufRead>(reader: R) -> Result<Vec<(usize, ParsedRequest)>, BatchError> {
    let mut rows = Vec::new();
    for (index, line) in BufReader::new(reader).lines().enumerate() {
        let line_number = index + 1;
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let body: serde_json::Value =
            serde_json::from_str(trimmed).map_err(|err| BatchError::ParseLine {
                line_number,
                message: err.to_string(),
            })?;
        let correlation_id = body
            .get("correlation_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                BatchError::Fairness(format!("missing correlation_id at line {line_number}"))
            })?
            .to_string();
        rows.push((
            line_number,
            ParsedRequest {
                correlation_id,
                body,
            },
        ));
    }
    Ok(rows)
}

fn parse_result_lines(path: &Path) -> Result<Vec<BatchResultRow>, BatchError> {
    let file = std::fs::File::open(path)?;
    parse_result_reader(BufReader::new(file))
}

fn parse_result_reader<R: BufRead>(reader: R) -> Result<Vec<BatchResultRow>, BatchError> {
    let mut rows = Vec::new();
    for (index, line) in BufReader::new(reader).lines().enumerate() {
        let line_number = index + 1;
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let row: BatchResultRow =
            serde_json::from_str(trimmed).map_err(|err| BatchError::ParseLine {
                line_number,
                message: err.to_string(),
            })?;
        rows.push(row);
    }
    Ok(rows)
}

fn extract_dot_path(value: &serde_json::Value, path: &str) -> Option<String> {
    let mut current = value;
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    value_to_string(current)
}

fn extract_bool_path(value: &serde_json::Value, path: &str) -> Option<bool> {
    let mut current = value;
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    current.as_bool()
}

fn value_to_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

pub fn is_approved(decision: Option<Decision>) -> bool {
    matches!(decision, Some(Decision::Pass))
}

pub fn evaluable_row(row: &FairnessRow) -> bool {
    row.status == BatchRowStatus::Ok && row.returned_decision.is_some()
}

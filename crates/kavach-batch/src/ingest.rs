use std::io::{BufRead, BufReader};

use kavach_domain::EvaluateRequest;

use crate::error::BatchError;

pub fn parse_ndjson_requests<R: BufRead>(
    reader: R,
) -> Result<Vec<(usize, EvaluateRequest)>, BatchError> {
    let mut rows = Vec::new();
    for (index, line) in BufReader::new(reader).lines().enumerate() {
        let line_number = index + 1;
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let request: EvaluateRequest =
            serde_json::from_str(trimmed).map_err(|err| BatchError::ParseLine {
                line_number,
                message: err.to_string(),
            })?;
        rows.push((line_number, request));
    }
    Ok(rows)
}

use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};

use chrono::Utc;
use kavach_domain::{EvaluatePath, ModelRecord};
use kavach_evaluate::{
    EvaluateConfig, EvaluateError, EvaluateService, EvidenceStore, IncidentRecorder,
};
use kavach_policy::PackLoader;
use uuid::Uuid;

use crate::error::BatchError;
use crate::export::{BatchResultRow, BatchRowStatus};
use crate::ingest::parse_ndjson_requests;

#[derive(Debug, Clone)]
pub struct BatchConfig {
    pub pack_path: PathBuf,
    pub model_path: PathBuf,
    pub service_identity_id: String,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            pack_path: PathBuf::new(),
            model_path: PathBuf::new(),
            service_identity_id: "kavach-batch-worker".into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchJobReport {
    pub job_id: String,
    pub total_rows: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub skipped: usize,
}

pub fn run_batch<R, W, S, I>(
    input: R,
    output: &mut W,
    config: &BatchConfig,
    evidence: S,
    incidents: I,
) -> Result<BatchJobReport, BatchError>
where
    R: Read,
    W: Write,
    S: EvidenceStore,
    I: IncidentRecorder,
{
    let pack = PackLoader::load_from_path(&config.pack_path)?;
    let model = load_model_record(&config.model_path)?;
    let rows = parse_ndjson_requests(BufReader::new(input))?;

    let mut service = EvaluateService::new(
        pack,
        model,
        evidence,
        incidents,
        EvaluateConfig {
            service_identity_id: config.service_identity_id.clone(),
            ..EvaluateConfig::default()
        },
    )?;

    let job_id = Uuid::new_v4().to_string();
    let mut report = BatchJobReport {
        job_id,
        total_rows: rows.len(),
        succeeded: 0,
        failed: 0,
        skipped: 0,
    };

    let server_now = Utc::now();
    let mut seen_evidence: std::collections::HashSet<String> = std::collections::HashSet::new();

    for (line_number, request) in rows {
        let correlation_id = request.correlation_id.clone();
        match service.evaluate(EvaluatePath::Batch, &request, server_now) {
            Ok(result) => {
                let row = ok_result_row(
                    line_number,
                    correlation_id,
                    result,
                    &mut report,
                    &mut seen_evidence,
                );
                row.write_ndjson_line(output)?;
            }
            Err(EvaluateError::Validation(message) | EvaluateError::ModelMismatch(message)) => {
                validation_error_row(line_number, correlation_id, message, &mut report)
                    .write_ndjson_line(output)?;
            }
            Err(EvaluateError::PackNotEffective) => {
                validation_error_row(
                    line_number,
                    correlation_id,
                    "pack not effective at decision_time".into(),
                    &mut report,
                )
                .write_ndjson_line(output)?;
            }
            Err(err) => return Err(BatchError::Evaluate(err)),
        }
    }

    Ok(report)
}

fn ok_result_row(
    line_number: usize,
    correlation_id: String,
    result: kavach_evaluate::EvaluateResult,
    report: &mut BatchJobReport,
    seen_evidence: &mut std::collections::HashSet<String>,
) -> BatchResultRow {
    if result.incident.is_some() {
        report.failed += 1;
        return BatchResultRow {
            line_number,
            correlation_id,
            status: BatchRowStatus::EvidenceError,
            policy_decision: Some(result.response.policy_decision),
            returned_decision: Some(result.response.returned_decision),
            evidence_id: None,
            reason_codes: result.response.reason_codes,
            policy_hits: result.response.policy_hits,
            error: result.incident.map(|i| i.reason),
        };
    }

    if let Some(evidence_id) = &result.response.evidence_id {
        if seen_evidence.insert(evidence_id.clone()) {
            report.succeeded += 1;
        } else {
            report.skipped += 1;
        }
        return BatchResultRow {
            line_number,
            correlation_id,
            status: BatchRowStatus::Ok,
            policy_decision: Some(result.response.policy_decision),
            returned_decision: Some(result.response.returned_decision),
            evidence_id: result.response.evidence_id,
            reason_codes: result.response.reason_codes,
            policy_hits: result.response.policy_hits,
            error: None,
        };
    }

    report.failed += 1;
    BatchResultRow {
        line_number,
        correlation_id,
        status: BatchRowStatus::EvidenceError,
        policy_decision: Some(result.response.policy_decision),
        returned_decision: Some(result.response.returned_decision),
        evidence_id: None,
        reason_codes: result.response.reason_codes,
        policy_hits: result.response.policy_hits,
        error: Some("missing evidence_id".into()),
    }
}

fn validation_error_row(
    line_number: usize,
    correlation_id: String,
    message: String,
    report: &mut BatchJobReport,
) -> BatchResultRow {
    report.failed += 1;
    BatchResultRow {
        line_number,
        correlation_id,
        status: BatchRowStatus::ValidationError,
        policy_decision: None,
        returned_decision: None,
        evidence_id: None,
        reason_codes: Vec::new(),
        policy_hits: Vec::new(),
        error: Some(message),
    }
}

fn load_model_record(path: &Path) -> Result<ModelRecord, BatchError> {
    let content = std::fs::read_to_string(path)?;
    Ok(serde_yaml::from_str(&content)?)
}

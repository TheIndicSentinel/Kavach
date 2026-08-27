use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};

use chrono::Utc;
use kavach_domain::{EvaluatePath, ModelRecord};
use kavach_evaluate::{
    EvaluateConfig, EvaluateError, EvaluateService, EvidenceStore, IncidentRecorder,
};
use kavach_policy::PackLoader;
use kavach_storage::{BatchJobCreate, BatchJobStore};

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

#[derive(Debug, Clone)]
pub struct BatchRunContext {
    pub input_path: String,
    pub output_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchJobReport {
    pub job_id: String,
    pub total_rows: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub skipped: usize,
}

pub fn run_batch<R, W, S, I, J>(
    input: R,
    output: &mut W,
    config: &BatchConfig,
    context: &BatchRunContext,
    evidence: S,
    incidents: I,
    job_store: &mut J,
) -> Result<BatchJobReport, BatchError>
where
    R: Read,
    W: Write,
    S: EvidenceStore,
    I: IncidentRecorder,
    J: BatchJobStore,
{
    let pack = PackLoader::load_from_path(&config.pack_path)?;
    let model = load_model_record(&config.model_path)?;

    let job_id = job_store
        .create_pending(&BatchJobCreate {
            input_path: context.input_path.clone(),
            output_path: context.output_path.clone(),
            model_id: model.model_id.clone(),
            governance_mode: model.governance_mode,
        })
        .map_err(BatchError::JobStore)?;

    let rows = match parse_ndjson_requests(BufReader::new(input)) {
        Ok(rows) => rows,
        Err(err) => {
            let _ = job_store.mark_failed(&job_id, &err.to_string(), 0, 0, 0, 0);
            return Err(err);
        }
    };

    job_store
        .mark_running(&job_id, rows.len())
        .map_err(BatchError::JobStore)?;

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

    let mut report = BatchJobReport {
        job_id: job_id.clone(),
        total_rows: rows.len(),
        succeeded: 0,
        failed: 0,
        skipped: 0,
    };

    let server_now = Utc::now();
    let mut seen_evidence: std::collections::HashSet<String> = std::collections::HashSet::new();

    for (line_number, request) in rows {
        process_evaluate_row(
            &mut service,
            output,
            &mut ProcessRowInput {
                line_number,
                request: &request,
                server_now,
                report: &mut report,
                seen_evidence: &mut seen_evidence,
                job_id: &job_id,
            },
            job_store,
        )?;
    }

    finalize_batch_job(job_store, &job_id, &report)?;
    Ok(report)
}

struct ProcessRowInput<'a> {
    line_number: usize,
    request: &'a kavach_domain::EvaluateRequest,
    server_now: chrono::DateTime<Utc>,
    report: &'a mut BatchJobReport,
    seen_evidence: &'a mut std::collections::HashSet<String>,
    job_id: &'a str,
}

fn process_evaluate_row<W, J>(
    service: &mut EvaluateService<impl EvidenceStore, impl IncidentRecorder>,
    output: &mut W,
    input: &mut ProcessRowInput<'_>,
    job_store: &mut J,
) -> Result<(), BatchError>
where
    W: Write,
    J: BatchJobStore,
{
    let correlation_id = input.request.correlation_id.clone();
    match service.evaluate(EvaluatePath::Batch, input.request, input.server_now) {
        Ok(result) => {
            let row = ok_result_row(
                input.line_number,
                correlation_id,
                result,
                input.report,
                input.seen_evidence,
            );
            row.write_ndjson_line(output)?;
        }
        Err(EvaluateError::Validation(message) | EvaluateError::ModelMismatch(message)) => {
            validation_error_row(input.line_number, correlation_id, message, input.report)
                .write_ndjson_line(output)?;
        }
        Err(EvaluateError::PackNotEffective) => {
            validation_error_row(
                input.line_number,
                correlation_id,
                "pack not effective at decision_time".into(),
                input.report,
            )
            .write_ndjson_line(output)?;
        }
        Err(err) => {
            let _ = job_store.mark_failed(
                input.job_id,
                &err.to_string(),
                input.report.total_rows,
                input.report.succeeded,
                input.report.failed,
                input.report.skipped,
            );
            return Err(BatchError::Evaluate(err));
        }
    }
    Ok(())
}

fn finalize_batch_job<J>(
    job_store: &mut J,
    job_id: &str,
    report: &BatchJobReport,
) -> Result<(), BatchError>
where
    J: BatchJobStore,
{
    if report.failed > 0 {
        job_store
            .mark_failed(
                job_id,
                "one or more rows failed validation or evidence append",
                report.total_rows,
                report.succeeded,
                report.failed,
                report.skipped,
            )
            .map_err(BatchError::JobStore)
    } else {
        job_store
            .mark_completed(
                job_id,
                report.total_rows,
                report.succeeded,
                report.failed,
                report.skipped,
            )
            .map_err(BatchError::JobStore)
    }
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

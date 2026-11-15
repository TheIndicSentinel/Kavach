use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};

use chrono::Utc;
use kavach_domain::{EvaluatePath, ModelRecord};
use kavach_evaluate::{
    DecisionTimeCheck, EvaluateConfig, EvaluateError, EvaluateService, EvidenceStore,
    IncidentRecorder,
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
    /// Expected SHA-256 of the pack file; the job fails before processing on mismatch.
    pub pack_sha256: Option<String>,
    /// How each row's `decision_time` is validated. Historical exports use a
    /// declared window; the default is the sync skew check against now.
    pub time_check: DecisionTimeCheck,
    /// The governed model (Postgres mode, ADR-010). When `None`, the model
    /// YAML at `model_path` is used as is (development).
    pub governed_model: Option<ModelRecord>,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            pack_path: PathBuf::new(),
            model_path: PathBuf::new(),
            service_identity_id: "kavach-batch-worker".into(),
            pack_sha256: None,
            time_check: DecisionTimeCheck::Skew,
            governed_model: None,
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
    pack.verify_pin(config.pack_sha256.as_deref())?;
    let model = match &config.governed_model {
        Some(model) => model.clone(),
        None => load_model_record(&config.model_path)?,
    };
    let job = BatchJobCreate {
        input_path: context.input_path.clone(),
        output_path: context.output_path.clone(),
        model_id: model.model_id.clone(),
        governance_mode: model.governance_mode,
    };
    // Set up before the job exists, like the pack and model: a setup error
    // records no job rather than leaving one behind.
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

    let job_id = job_store
        .create_pending(&job)
        .map_err(BatchError::JobStore)?;
    let mut report = BatchJobReport {
        job_id,
        total_rows: 0,
        succeeded: 0,
        failed: 0,
        skipped: 0,
    };

    // From here on every error marks the job failed (L20): a failed input
    // read, output write or flush, or status write must not leave the job
    // recorded as pending or running.
    if let Err(failure) = run_job(input, output, config, &mut service, job_store, &mut report) {
        record_failure(job_store, &report, &failure.summary);
        return Err(failure.error);
    }

    finalize_batch_job(job_store, &report.job_id, &report)?;
    Ok(report)
}

/// An error after the job was created, with the summary stored for it.
struct JobFailure {
    /// A fixed description of the failure (and at most an input line
    /// number), never a path, a record's contents or an error's own text:
    /// the stored summary is served by the admin API.
    summary: String,
    error: BatchError,
}

impl JobFailure {
    fn reading_input(error: BatchError) -> Self {
        let summary = match &error {
            BatchError::ParseLine { line_number, .. } => {
                format!("input line {line_number} is not a valid request")
            }
            _ => "input could not be read".into(),
        };
        Self { summary, error }
    }

    fn recording_status(error: kavach_storage::JobStoreError) -> Self {
        Self {
            summary: "job status could not be recorded".into(),
            error: BatchError::JobStore(error),
        }
    }

    fn writing_output(error: std::io::Error) -> Self {
        Self {
            summary: "output could not be written".into(),
            error: BatchError::Io(error),
        }
    }

    fn evaluating(error: EvaluateError) -> Self {
        let summary = match &error {
            EvaluateError::Policy(_) => "evaluate failed: policy error",
            EvaluateError::Domain(_) => "evaluate failed: domain error",
            _ => "evaluate failed",
        };
        Self {
            summary: summary.into(),
            error: BatchError::Evaluate(error),
        }
    }
}

/// Reads the input, marks the job running, evaluates every row and flushes
/// the output. The flush is here, before the job can be marked completed, so
/// that output still buffered by the caller's writer cannot fail unseen.
fn run_job<R, W, J>(
    input: R,
    output: &mut W,
    config: &BatchConfig,
    service: &mut EvaluateService<impl EvidenceStore, impl IncidentRecorder>,
    job_store: &mut J,
    report: &mut BatchJobReport,
) -> Result<(), JobFailure>
where
    R: Read,
    W: Write,
    J: BatchJobStore,
{
    let rows = parse_ndjson_requests(BufReader::new(input)).map_err(JobFailure::reading_input)?;
    report.total_rows = rows.len();

    job_store
        .mark_running(&report.job_id, rows.len())
        .map_err(JobFailure::recording_status)?;

    let server_now = Utc::now();
    let mut seen_evidence: std::collections::HashSet<String> = std::collections::HashSet::new();

    for (line_number, request) in rows {
        process_evaluate_row(
            service,
            output,
            &mut ProcessRowInput {
                line_number,
                request: &request,
                server_now,
                time_check: config.time_check,
                report,
                seen_evidence: &mut seen_evidence,
            },
        )?;
    }

    output.flush().map_err(JobFailure::writing_output)
}

/// Marks the job failed, once. If the store refuses that too, the job keeps
/// the status it last recorded (pending or running); the run still returns
/// its own error, and this warning names the job (by id only).
fn record_failure<J: BatchJobStore>(job_store: &mut J, report: &BatchJobReport, summary: &str) {
    let marked = job_store.mark_failed(
        &report.job_id,
        summary,
        report.total_rows,
        report.succeeded,
        report.failed,
        report.skipped,
    );
    if marked.is_err() {
        tracing::warn!(
            "ALERT kavach-batch: job {} failed and could not be marked failed; the job store keeps its last recorded status",
            report.job_id
        );
    }
}

struct ProcessRowInput<'a> {
    line_number: usize,
    request: &'a kavach_domain::EvaluateRequest,
    server_now: chrono::DateTime<Utc>,
    time_check: DecisionTimeCheck,
    report: &'a mut BatchJobReport,
    seen_evidence: &'a mut std::collections::HashSet<String>,
}

fn process_evaluate_row<W>(
    service: &mut EvaluateService<impl EvidenceStore, impl IncidentRecorder>,
    output: &mut W,
    input: &mut ProcessRowInput<'_>,
) -> Result<(), JobFailure>
where
    W: Write,
{
    let correlation_id = input.request.correlation_id.clone();
    match service.evaluate_with_time_check(
        EvaluatePath::Batch,
        input.request,
        input.server_now,
        input.time_check,
    ) {
        Ok(result) => {
            if let Some(err) = &result.incident_write_error {
                tracing::warn!(
                    "ALERT kavach-batch: incident not persisted (line {}, correlation_id={correlation_id}): {err}",
                    input.line_number
                );
            }
            let row = ok_result_row(
                input.line_number,
                correlation_id,
                result,
                input.report,
                input.seen_evidence,
            );
            row.write_ndjson_line(output)
        }
        Err(
            EvaluateError::Validation(message)
            | EvaluateError::ModelMismatch(message)
            | EvaluateError::IdempotencyConflict(message),
        ) => validation_error_row(input.line_number, correlation_id, message, input.report)
            .write_ndjson_line(output),
        Err(EvaluateError::PackNotEffective) => validation_error_row(
            input.line_number,
            correlation_id,
            "pack not effective at server time".into(),
            input.report,
        )
        .write_ndjson_line(output),
        Err(err) => return Err(JobFailure::evaluating(err)),
    }
    .map_err(JobFailure::writing_output)
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

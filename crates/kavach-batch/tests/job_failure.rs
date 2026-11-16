//! L20: an I/O failure during a batch run marks the job failed, with a
//! fixed summary (no path, no record contents), and never leaves it
//! recorded as pending or running.

use std::io::{self, Cursor, Read, Write};
use std::path::PathBuf;

use chrono::Utc;
use kavach_batch::{run_batch, BatchConfig, BatchError, BatchRunContext};
use kavach_domain::ModelRecord;
use kavach_evaluate::VecIncidentRecorder;
use kavach_evidence::MemoryChain;
use kavach_storage::{BatchJobCreate, BatchJobStore, JobStoreError};

/// A job store that keeps the last status written, and can refuse writes.
#[derive(Default)]
struct Jobs {
    created: bool,
    status: Option<&'static str>,
    summary: Option<String>,
    mark_failed_calls: usize,
    refuse_mark_running: bool,
    refuse_mark_failed: bool,
}

fn refused() -> JobStoreError {
    JobStoreError::Postgres("store unavailable".into())
}

impl BatchJobStore for Jobs {
    fn create_pending(&mut self, _: &BatchJobCreate) -> Result<String, JobStoreError> {
        self.created = true;
        self.status = Some("pending");
        Ok("job-1".into())
    }
    fn mark_running(&mut self, _: &str, _: usize) -> Result<(), JobStoreError> {
        if self.refuse_mark_running {
            return Err(refused());
        }
        self.status = Some("running");
        Ok(())
    }
    fn mark_completed(
        &mut self,
        _: &str,
        _: usize,
        _: usize,
        _: usize,
        _: usize,
    ) -> Result<(), JobStoreError> {
        self.status = Some("completed");
        Ok(())
    }
    fn mark_failed(
        &mut self,
        _: &str,
        summary: &str,
        _: usize,
        _: usize,
        _: usize,
        _: usize,
    ) -> Result<(), JobStoreError> {
        self.mark_failed_calls += 1;
        if self.refuse_mark_failed {
            return Err(refused());
        }
        self.status = Some("failed");
        self.summary = Some(summary.to_string());
        Ok(())
    }
}

/// Every write fails, as on a full or vanished disk.
struct BrokenWriter;

impl Write for BrokenWriter {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("no space left on device"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Writes are accepted into a buffer; the flush fails, as a `BufWriter`
/// over a full disk does when the whole output fitted in its buffer.
#[derive(Default)]
struct FlushFails(Vec<u8>);

impl Write for FlushFails {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("no space left on device"))
    }
}

/// Every read fails, as on an input removed or unreadable mid-run.
struct BrokenReader;

impl Read for BrokenReader {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("input/output error"))
    }
}

fn workspace(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

fn config() -> BatchConfig {
    BatchConfig {
        pack_path: workspace("packs/finance/v0.yaml"),
        model_path: workspace("models/finance/credit-underwriting-v1.yaml"),
        ..BatchConfig::default()
    }
}

/// Paths that look like they name a person: none of it may reach the summary.
fn context() -> BatchRunContext {
    BatchRunContext {
        input_path: "/home/ramesh/loans-ramesh.ndjson".into(),
        output_path: "/home/ramesh/results-ramesh.ndjson".into(),
    }
}

/// One clean row that evaluates to PASS and writes evidence.
fn clean_row() -> String {
    let fixture: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(workspace("golden/finance/v0/credit_clean.json")).unwrap(),
    )
    .unwrap();
    let mut request = fixture["request"].clone();
    let now = Utc::now().to_rfc3339();
    request["decision_time"] = serde_json::Value::String(now.clone());
    request["consent"]["timestamp"] = serde_json::Value::String(now);
    format!("{request}\n")
}

fn run<R: Read, W: Write>(
    input: R,
    output: &mut W,
    config: &BatchConfig,
    jobs: &mut Jobs,
) -> Result<kavach_batch::BatchJobReport, BatchError> {
    run_batch(
        input,
        output,
        config,
        &context(),
        MemoryChain::new(),
        VecIncidentRecorder::default(),
        jobs,
    )
}

fn assert_failed_with(jobs: &Jobs, summary: &str) {
    assert_eq!(jobs.status, Some("failed"), "job left {:?}", jobs.status);
    assert_eq!(jobs.summary.as_deref(), Some(summary));
    assert!(!summary.contains("ramesh"), "a path reached the summary");
    assert_eq!(jobs.mark_failed_calls, 1);
}

#[test]
fn an_output_write_failure_marks_the_job_failed_not_running() {
    let mut jobs = Jobs::default();
    let err = run(
        Cursor::new(clean_row()),
        &mut BrokenWriter,
        &config(),
        &mut jobs,
    )
    .unwrap_err();
    assert!(matches!(err, BatchError::Io(_)), "{err}");
    assert_failed_with(&jobs, "output could not be written");
}

#[test]
fn an_output_flush_failure_marks_the_job_failed_not_completed() {
    let mut jobs = Jobs::default();
    let mut output = FlushFails::default();
    let err = run(Cursor::new(clean_row()), &mut output, &config(), &mut jobs).unwrap_err();
    assert!(matches!(err, BatchError::Io(_)), "{err}");
    assert!(!output.0.is_empty(), "the row was written before the flush");
    assert_failed_with(&jobs, "output could not be written");
}

#[test]
fn an_input_read_failure_marks_the_job_failed() {
    let mut jobs = Jobs::default();
    let err = run(BrokenReader, &mut Vec::new(), &config(), &mut jobs).unwrap_err();
    assert!(matches!(err, BatchError::Io(_)), "{err}");
    assert_failed_with(&jobs, "input could not be read");
}

#[test]
fn an_unparseable_line_stores_its_number_not_its_contents() {
    let mut jobs = Jobs::default();
    // serde_json's own message would quote this value back.
    let input = format!("{}\"Ramesh Kumar 9876543210\"\n", clean_row());
    let err = run(Cursor::new(input), &mut Vec::new(), &config(), &mut jobs).unwrap_err();
    assert!(
        matches!(err, BatchError::ParseLine { line_number: 2, .. }),
        "{err}"
    );
    assert_failed_with(&jobs, "input line 2 is not a valid request");
}

#[test]
fn a_status_write_failure_after_create_marks_the_job_failed() {
    let mut jobs = Jobs {
        refuse_mark_running: true,
        ..Jobs::default()
    };
    let err = run(
        Cursor::new(clean_row()),
        &mut Vec::new(),
        &config(),
        &mut jobs,
    )
    .unwrap_err();
    assert!(matches!(err, BatchError::JobStore(_)), "{err}");
    assert_failed_with(&jobs, "job status could not be recorded");
}

/// The store is down: one attempt to mark the job failed, no retry loop and
/// no panic; the run returns its own error, and the job keeps the status it
/// last recorded.
#[test]
fn a_store_that_cannot_mark_failed_gets_one_attempt_and_the_run_error_is_kept() {
    let mut jobs = Jobs {
        refuse_mark_failed: true,
        ..Jobs::default()
    };
    let err = run(
        Cursor::new(clean_row()),
        &mut BrokenWriter,
        &config(),
        &mut jobs,
    )
    .unwrap_err();
    assert!(matches!(err, BatchError::Io(_)), "{err}");
    assert_eq!(jobs.mark_failed_calls, 1);
    assert_eq!(jobs.status, Some("running"));
}

/// A setup error (here a model whose input schema does not compile) happens
/// before the job is created, so no job is left behind.
#[test]
fn a_setup_failure_creates_no_job() {
    let mut model: ModelRecord = serde_yaml::from_str(
        &std::fs::read_to_string(workspace("models/finance/credit-underwriting-v1.yaml")).unwrap(),
    )
    .unwrap();
    model.input_schema = serde_json::json!({ "type": 12 });
    let config = BatchConfig {
        governed_model: Some(model),
        ..config()
    };
    let mut jobs = Jobs::default();
    let err = run(
        Cursor::new(clean_row()),
        &mut Vec::new(),
        &config,
        &mut jobs,
    )
    .unwrap_err();
    assert!(matches!(err, BatchError::Evaluate(_)), "{err}");
    assert!(
        !jobs.created,
        "a job was created for a run that never started"
    );
}

/// The happy path still completes (the added flush succeeds on a `Vec`).
#[test]
fn a_clean_run_still_completes() {
    let mut jobs = Jobs::default();
    let report = run(
        Cursor::new(clean_row()),
        &mut Vec::new(),
        &config(),
        &mut jobs,
    )
    .unwrap();
    assert_eq!(report.succeeded, 1);
    assert_eq!(jobs.status, Some("completed"));
    assert_eq!(jobs.mark_failed_calls, 0);
}

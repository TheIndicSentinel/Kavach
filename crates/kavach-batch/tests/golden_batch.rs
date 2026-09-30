//! Batch evaluate golden tests — batch shadow returns policy_decision.

use chrono::Utc;
use kavach_domain::{
    golden::{load_fixtures, workspace_golden_v0_dir},
    GovernanceMode, ModelRecord,
};
use kavach_evaluate::{EvaluateConfig, EvaluatePath, EvaluateService, VecIncidentRecorder};
use kavach_evidence::MemoryChain;
use kavach_policy::PackLoader;
use std::io::Cursor;
use std::path::PathBuf;

use kavach_batch::{run_batch, BatchConfig, BatchRunContext};
use kavach_storage::NoopBatchJobStore;

fn finance_pack() -> kavach_policy::LoadedPolicyPack {
    PackLoader::load_from_path(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packs/finance/v0.yaml"),
    )
    .expect("load pack")
}

fn finance_model_record(governance_mode: GovernanceMode) -> ModelRecord {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../models/finance/credit-underwriting-v1.yaml");
    let content = std::fs::read_to_string(&path).expect("read model");
    let mut model: ModelRecord = serde_yaml::from_str(&content).expect("parse model");
    model.governance_mode = governance_mode;
    model
}

#[test]
fn golden_v0_batch_shadow_matches_policy_decision() {
    let pack = finance_pack();
    let fixtures = load_fixtures(&workspace_golden_v0_dir()).expect("fixtures");
    let model = finance_model_record(GovernanceMode::Shadow);
    let chain = MemoryChain::new();
    let incidents = VecIncidentRecorder::default();
    let mut service =
        EvaluateService::new(pack, model, chain, incidents, EvaluateConfig::default())
            .expect("service");

    for fixture in fixtures {
        if fixture.name == "credit_missing_consent" {
            continue;
        }
        let Some(expected_policy) = fixture.expect.policy_decision else {
            continue;
        };

        let result = service
            .evaluate(
                EvaluatePath::Batch,
                &fixture.request,
                fixture.request.decision_time,
            )
            .unwrap_or_else(|e| panic!("{}: {e}", fixture.name));

        assert_eq!(
            result.response.returned_decision, expected_policy,
            "{}",
            fixture.name
        );
        assert_eq!(
            result.response.policy_decision, expected_policy,
            "{}",
            fixture.name
        );
    }
}

#[test]
fn run_batch_writes_ndjson_results_for_clean_fixture() {
    let fixture_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../golden/finance/v0/credit_clean.json");
    let fixture: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(fixture_path).unwrap()).unwrap();
    let mut request = fixture["request"].clone();
    let now = Utc::now();
    request["decision_time"] = serde_json::Value::String(now.to_rfc3339());
    request["consent"]["timestamp"] = serde_json::Value::String(now.to_rfc3339());
    let input = format!("{request}\n");

    let mut output = Vec::new();
    let context = BatchRunContext {
        input_path: "stdin".into(),
        output_path: "stdout".into(),
    };
    let mut job_store = NoopBatchJobStore;
    let report = run_batch(
        Cursor::new(input),
        &mut output,
        &BatchConfig {
            pack_path: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../packs/finance/v0.yaml"),
            model_path: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../models/finance/credit-underwriting-v1.yaml"),
            ..BatchConfig::default()
        },
        &context,
        MemoryChain::new(),
        VecIncidentRecorder::default(),
        &mut job_store,
    )
    .expect("batch run");

    assert_eq!(report.total_rows, 1);
    assert_eq!(report.succeeded, 1);
    let line: serde_json::Value =
        serde_json::from_slice(output.split(|b| *b == b'\n').next().unwrap()).unwrap();
    assert_eq!(line["status"], "ok");
    assert_eq!(line["returned_decision"], "PASS");
    assert_eq!(line["policy_decision"], "PASS");
    assert!(line["evidence_id"].as_str().is_some());
}

#[test]
fn run_batch_marks_validation_errors_without_evidence() {
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../golden/finance/v0/credit_missing_consent.json");
    let fixture: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(fixture_path).unwrap()).unwrap();
    let input = format!("{}\n", fixture["request"]);

    let mut output = Vec::new();
    let context = BatchRunContext {
        input_path: "stdin".into(),
        output_path: "stdout".into(),
    };
    let mut job_store = NoopBatchJobStore;
    let report = run_batch(
        Cursor::new(input),
        &mut output,
        &BatchConfig {
            pack_path: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../packs/finance/v0.yaml"),
            model_path: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../models/finance/credit-underwriting-v1.yaml"),
            ..BatchConfig::default()
        },
        &context,
        MemoryChain::new(),
        VecIncidentRecorder::default(),
        &mut job_store,
    )
    .expect("batch run");

    assert_eq!(report.failed, 1);
    let line: serde_json::Value =
        serde_json::from_slice(output.split(|b| *b == b'\n').next().unwrap()).unwrap();
    assert_eq!(line["status"], "validation_error");
}

#[test]
fn run_batch_processes_partner_finance_sample() {
    let batch_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../partner/finance/credit_underwriting_v1_batch.ndjson");
    let ndjson = std::fs::read_to_string(&batch_path).expect("read partner batch");
    let now = Utc::now().to_rfc3339();
    let mut lines = Vec::new();
    for line in ndjson.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let mut request: serde_json::Value = serde_json::from_str(line).expect("parse line");
        request["decision_time"] = serde_json::Value::String(now.clone());
        request["consent"]["timestamp"] = serde_json::Value::String(now.clone());
        lines.push(request.to_string());
    }
    let input = format!("{}\n", lines.join("\n"));

    let mut output = Vec::new();
    let context = BatchRunContext {
        input_path: "partner-batch".into(),
        output_path: "stdout".into(),
    };
    let mut job_store = NoopBatchJobStore;
    let report = run_batch(
        Cursor::new(input),
        &mut output,
        &BatchConfig {
            pack_path: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../packs/finance/v0.yaml"),
            model_path: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../models/finance/credit-underwriting-v1.yaml"),
            ..BatchConfig::default()
        },
        &context,
        MemoryChain::new(),
        VecIncidentRecorder::default(),
        &mut job_store,
    )
    .expect("partner batch run");

    assert_eq!(report.total_rows, 3);
    assert_eq!(report.succeeded, 3);
    let result_lines: Vec<&[u8]> = output
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .collect();
    assert_eq!(result_lines.len(), 3);
    let first: serde_json::Value = serde_json::from_slice(result_lines[0]).unwrap();
    assert_eq!(first["status"], "ok");
    assert_eq!(first["policy_decision"], "PASS");
}

/// Records what the worker declares for the job.
#[derive(Default)]
struct RecordingJobs {
    mode: Option<GovernanceMode>,
}

impl kavach_storage::BatchJobStore for RecordingJobs {
    fn create_pending(
        &mut self,
        create: &kavach_storage::BatchJobCreate,
    ) -> Result<String, kavach_storage::JobStoreError> {
        self.mode = Some(create.governance_mode);
        Ok("job-1".into())
    }
    fn mark_running(&mut self, _: &str, _: usize) -> Result<(), kavach_storage::JobStoreError> {
        Ok(())
    }
    fn mark_completed(
        &mut self,
        _: &str,
        _: usize,
        _: usize,
        _: usize,
        _: usize,
    ) -> Result<(), kavach_storage::JobStoreError> {
        Ok(())
    }
    fn mark_failed(
        &mut self,
        _: &str,
        _: &str,
        _: usize,
        _: usize,
        _: usize,
        _: usize,
    ) -> Result<(), kavach_storage::JobStoreError> {
        Ok(())
    }
}

/// ADR-010: with a governed model, batch runs (and records the job) in the
/// governed mode, not the one in the YAML file.
#[test]
fn run_batch_uses_the_governed_model() {
    let mut jobs = RecordingJobs::default();
    run_batch(
        Cursor::new(String::new()),
        &mut Vec::new(),
        &BatchConfig {
            pack_path: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../packs/finance/v0.yaml"),
            model_path: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../models/finance/credit-underwriting-v1.yaml"),
            governed_model: Some(finance_model_record(GovernanceMode::Enforce)),
            ..BatchConfig::default()
        },
        &BatchRunContext {
            input_path: "stdin".into(),
            output_path: "stdout".into(),
        },
        MemoryChain::new(),
        VecIncidentRecorder::default(),
        &mut jobs,
    )
    .expect("batch run");
    assert_eq!(jobs.mode, Some(GovernanceMode::Enforce));
}

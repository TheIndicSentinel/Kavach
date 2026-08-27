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

use kavach_batch::{run_batch, BatchConfig};

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
        MemoryChain::new(),
        VecIncidentRecorder::default(),
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
        MemoryChain::new(),
        VecIncidentRecorder::default(),
    )
    .expect("batch run");

    assert_eq!(report.failed, 1);
    let line: serde_json::Value =
        serde_json::from_slice(output.split(|b| *b == b'\n').next().unwrap()).unwrap();
    assert_eq!(line["status"], "validation_error");
}

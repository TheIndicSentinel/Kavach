//! End-to-end evaluate pipeline against golden v0 fixtures.

use chrono::{TimeZone, Utc};
use kavach_domain::{
    golden::{load_fixtures, workspace_golden_v0_dir},
    GovernanceMode, ModelRecord,
};
use kavach_evaluate::{EvaluateConfig, EvaluateError, EvaluateService, VecIncidentRecorder};
use kavach_evidence::MemoryChain;
use kavach_policy::{LoadedPolicyPack, PackLoader};
use std::path::PathBuf;

fn finance_pack() -> LoadedPolicyPack {
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

fn server_now_for(request_time: chrono::DateTime<Utc>) -> chrono::DateTime<Utc> {
    request_time
}

#[test]
fn golden_v0_enforce_evaluate_matches_expectations() {
    let pack = finance_pack();
    let fixtures = load_fixtures(&workspace_golden_v0_dir()).expect("fixtures");
    let model = finance_model_record(GovernanceMode::Enforce);
    let chain = MemoryChain::new();
    let incidents = VecIncidentRecorder::default();
    let mut service =
        EvaluateService::new(pack, model, chain, incidents, EvaluateConfig::default())
            .expect("service");

    let mut evaluated = 0usize;

    for fixture in fixtures {
        if fixture.name == "credit_missing_consent" {
            continue;
        }

        let Some(expected_policy) = fixture.expect.policy_decision else {
            continue;
        };
        let Some(expected_returned) = fixture.expect.returned_decision_enforce else {
            continue;
        };

        let result = service
            .evaluate(
                &fixture.request,
                server_now_for(fixture.request.decision_time),
            )
            .unwrap_or_else(|e| panic!("{}: {e}", fixture.name));

        assert_eq!(
            result.response.policy_decision, expected_policy,
            "{}",
            fixture.name
        );
        assert_eq!(
            result.response.returned_decision, expected_returned,
            "{}",
            fixture.name
        );
        assert!(
            result.response.evidence_id.is_some(),
            "{}: expected evidence row",
            fixture.name
        );
        assert!(result.incident.is_none());
        for code in &fixture.expect.reason_codes_contains {
            assert!(
                result.response.reason_codes.iter().any(|c| c == code),
                "{}: missing {code}",
                fixture.name
            );
        }
        evaluated += 1;
    }

    assert_eq!(evaluated, 3);
    assert_eq!(service.evidence_store().events().len(), 3);
}

#[test]
fn golden_v0_shadow_sync_masks_non_pass_returned_decision() {
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

        let Some(expected_returned) = fixture.expect.returned_decision_sync_shadow else {
            continue;
        };

        let result = service
            .evaluate(
                &fixture.request,
                server_now_for(fixture.request.decision_time),
            )
            .unwrap_or_else(|e| panic!("{}: {e}", fixture.name));

        assert_eq!(
            result.response.returned_decision, expected_returned,
            "{}",
            fixture.name
        );
    }
}

#[test]
fn consent_mismatch_is_validation_error_not_rpc_decision() {
    let pack = finance_pack();
    let fixtures = load_fixtures(&workspace_golden_v0_dir()).expect("fixtures");
    let fixture = fixtures
        .into_iter()
        .find(|f| f.name == "credit_missing_consent")
        .expect("fixture");

    let model = finance_model_record(GovernanceMode::Enforce);
    let chain = MemoryChain::new();
    let incidents = VecIncidentRecorder::default();
    let mut service =
        EvaluateService::new(pack, model, chain, incidents, EvaluateConfig::default())
            .expect("service");

    let err = service
        .evaluate(
            &fixture.request,
            server_now_for(fixture.request.decision_time),
        )
        .expect_err("consent mismatch");

    assert!(matches!(err, EvaluateError::Validation(_)));
    assert!(service.evidence_store().events().is_empty());
}

#[test]
fn evidence_failure_enforce_returns_block_without_row() {
    struct FailingStore;

    impl kavach_evaluate::EvidenceStore for FailingStore {
        fn append(
            &mut self,
            _input: kavach_evidence::AppendDecisionEvent,
        ) -> Result<kavach_domain::DecisionEvent, kavach_evidence::EvidenceError> {
            Err(kavach_evidence::EvidenceError::InvalidHash {
                hash: "simulated".into(),
                reason: "store unavailable".into(),
            })
        }
    }

    let pack = finance_pack();
    let fixtures = load_fixtures(&workspace_golden_v0_dir()).expect("fixtures");
    let fixture = fixtures
        .into_iter()
        .find(|f| f.name == "credit_clean")
        .expect("fixture");

    let model = finance_model_record(GovernanceMode::Enforce);
    let store = FailingStore;
    let incidents = VecIncidentRecorder::default();
    let mut service =
        EvaluateService::new(pack, model, store, incidents, EvaluateConfig::default())
            .expect("service");

    let result = service
        .evaluate(
            &fixture.request,
            server_now_for(fixture.request.decision_time),
        )
        .expect("infra path");

    assert_eq!(
        result.response.returned_decision,
        kavach_domain::Decision::Block
    );
    assert!(result.response.evidence_id.is_none());
    assert!(result.incident.is_some());
    assert_eq!(service.incidents().incidents.len(), 1);
}

#[test]
fn evidence_failure_shadow_returns_pass_without_row() {
    struct FailingStore;

    impl kavach_evaluate::EvidenceStore for FailingStore {
        fn append(
            &mut self,
            _input: kavach_evidence::AppendDecisionEvent,
        ) -> Result<kavach_domain::DecisionEvent, kavach_evidence::EvidenceError> {
            Err(kavach_evidence::EvidenceError::InvalidHash {
                hash: "simulated".into(),
                reason: "store unavailable".into(),
            })
        }
    }

    let pack = finance_pack();
    let fixtures = load_fixtures(&workspace_golden_v0_dir()).expect("fixtures");
    let fixture = fixtures
        .into_iter()
        .find(|f| f.name == "credit_high_dti")
        .expect("fixture");

    let model = finance_model_record(GovernanceMode::Shadow);
    let store = FailingStore;
    let incidents = VecIncidentRecorder::default();
    let mut service =
        EvaluateService::new(pack, model, store, incidents, EvaluateConfig::default())
            .expect("service");

    let result = service
        .evaluate(
            &fixture.request,
            server_now_for(fixture.request.decision_time),
        )
        .expect("infra path");

    assert_eq!(
        result.response.returned_decision,
        kavach_domain::Decision::Pass
    );
    assert_eq!(
        result.response.policy_decision,
        kavach_domain::Decision::Alert
    );
    assert!(result.response.evidence_id.is_none());
    assert_eq!(service.incidents().incidents.len(), 1);
}

#[test]
fn idempotent_retry_returns_same_evidence_id() {
    let pack = finance_pack();
    let fixtures = load_fixtures(&workspace_golden_v0_dir()).expect("fixtures");
    let fixture = fixtures
        .into_iter()
        .find(|f| f.name == "credit_clean")
        .expect("fixture");

    let model = finance_model_record(GovernanceMode::Enforce);
    let chain = MemoryChain::new();
    let incidents = VecIncidentRecorder::default();
    let mut service =
        EvaluateService::new(pack, model, chain, incidents, EvaluateConfig::default())
            .expect("service");

    let now = server_now_for(fixture.request.decision_time);
    let first = service.evaluate(&fixture.request, now).expect("first");
    let second = service.evaluate(&fixture.request, now).expect("second");

    assert_eq!(first.response.evidence_id, second.response.evidence_id);
    assert_eq!(service.evidence_store().events().len(), 1);
}

#[test]
fn clock_skew_rejected() {
    let pack = finance_pack();
    let fixtures = load_fixtures(&workspace_golden_v0_dir()).expect("fixtures");
    let fixture = fixtures
        .into_iter()
        .find(|f| f.name == "credit_clean")
        .expect("fixture");

    let model = finance_model_record(GovernanceMode::Enforce);
    let chain = MemoryChain::new();
    let incidents = VecIncidentRecorder::default();
    let mut service = EvaluateService::new(
        pack,
        model,
        chain,
        incidents,
        EvaluateConfig {
            clock_skew_max_seconds: 60,
            ..EvaluateConfig::default()
        },
    )
    .expect("service");

    let skewed_now = Utc.with_ymd_and_hms(2026, 8, 2, 0, 0, 0).unwrap();
    let err = service
        .evaluate(&fixture.request, skewed_now)
        .expect_err("skew");

    assert!(matches!(err, EvaluateError::Validation(_)));
}

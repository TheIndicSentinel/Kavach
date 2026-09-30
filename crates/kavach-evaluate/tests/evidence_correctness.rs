//! H1 evidence-correctness fixes: pack id from the loaded pack, idempotent
//! replay returns the stored decisions (or conflicts), CEL errors become a
//! recorded BLOCK, incident write failures are surfaced, and batch windows.

use std::path::PathBuf;

use chrono::{DateTime, Duration, TimeZone, Utc};
use kavach_domain::{
    golden::{load_fixtures, workspace_golden_v0_dir},
    Decision, EvaluateRequest, GovernanceMode, ModelRecord,
};
use kavach_evaluate::{
    DecisionTimeCheck, EvaluateConfig, EvaluateError, EvaluateIncident, EvaluatePath,
    EvaluateService, IncidentRecorder, IncidentWriteError, VecIncidentRecorder,
    POLICY_EVALUATION_ERROR,
};
use kavach_evidence::MemoryChain;
use kavach_policy::{LoadedPolicyPack, PackLoader};

fn finance_pack() -> LoadedPolicyPack {
    PackLoader::load_from_path(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packs/finance/v0.yaml"),
    )
    .expect("load pack")
}

fn model(mode: GovernanceMode) -> ModelRecord {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../models/finance/credit-underwriting-v1.yaml");
    let mut model: ModelRecord =
        serde_yaml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    model.governance_mode = mode;
    model
}

fn clean_request() -> EvaluateRequest {
    load_fixtures(&workspace_golden_v0_dir())
        .unwrap()
        .into_iter()
        .find(|f| f.name == "credit_clean")
        .expect("credit_clean")
        .request
}

/// A pack whose single rule raises a CEL execution error.
fn erroring_pack() -> LoadedPolicyPack {
    let mut pack = finance_pack().pack;
    pack.rules.truncate(1);
    pack.rules[0].expression = "request.input.no_such_field.deeper > 1".into();
    PackLoader::load_from_pack(pack).expect("compiles")
}

fn service<I: IncidentRecorder>(
    pack: LoadedPolicyPack,
    mode: GovernanceMode,
    incidents: I,
) -> EvaluateService<MemoryChain, I> {
    EvaluateService::new(
        pack,
        model(mode),
        MemoryChain::new(),
        incidents,
        EvaluateConfig::default(),
    )
    .expect("service")
}

#[test]
fn evidence_records_the_loaded_pack_id() {
    let mut pack = finance_pack();
    pack.pack.id = "finance-v1-activated".into();
    let mut svc = service(
        pack,
        GovernanceMode::Enforce,
        VecIncidentRecorder::default(),
    );
    let request = clean_request();
    svc.evaluate(EvaluatePath::Sync, &request, request.decision_time)
        .unwrap();
    let event = &svc.evidence_store().events()[0];
    assert_eq!(event.pack_id, "finance-v1-activated");
}

#[test]
fn idempotent_retry_returns_stored_decisions_even_if_policy_changed() {
    let mut svc = service(
        finance_pack(),
        GovernanceMode::Enforce,
        VecIncidentRecorder::default(),
    );
    let request = clean_request();
    let first = svc
        .evaluate(EvaluatePath::Sync, &request, request.decision_time)
        .unwrap()
        .response;
    assert_eq!(first.policy_decision, Decision::Pass);

    // Reload with a pack that would now BLOCK the same request.
    let model = svc.model().clone();
    svc.reload_pack_and_model(erroring_pack(), model).unwrap();
    let retry = svc
        .evaluate(EvaluatePath::Sync, &request, request.decision_time)
        .unwrap()
        .response;
    assert_eq!(retry.evidence_id, first.evidence_id);
    assert_eq!(retry.policy_decision, first.policy_decision);
    assert_eq!(retry.returned_decision, first.returned_decision);
    assert_eq!(svc.evidence_store().events().len(), 1);
}

#[test]
fn same_key_different_input_is_a_conflict() {
    let mut svc = service(
        finance_pack(),
        GovernanceMode::Enforce,
        VecIncidentRecorder::default(),
    );
    let request = clean_request();
    svc.evaluate(EvaluatePath::Sync, &request, request.decision_time)
        .unwrap();

    let mut changed = request.clone();
    changed.input["debt_ratio"] = serde_json::json!(0.99);
    let err = svc
        .evaluate(EvaluatePath::Sync, &changed, request.decision_time)
        .unwrap_err();
    assert!(
        matches!(err, EvaluateError::IdempotencyConflict(_)),
        "{err}"
    );
    assert_eq!(svc.evidence_store().events().len(), 1);
}

#[test]
fn cel_error_is_a_recorded_block_with_an_incident() {
    let request = clean_request();

    let mut enforce = service(
        erroring_pack(),
        GovernanceMode::Enforce,
        VecIncidentRecorder::default(),
    );
    let result = enforce
        .evaluate(EvaluatePath::Sync, &request, request.decision_time)
        .expect("CEL error is a decision, not a transport error");
    assert_eq!(result.response.policy_decision, Decision::Block);
    assert_eq!(result.response.returned_decision, Decision::Block);
    assert_eq!(
        result.response.reason_codes,
        vec![POLICY_EVALUATION_ERROR.to_string()]
    );
    assert!(result.response.evidence_id.is_some());
    assert!(result.incident.is_some());
    assert_eq!(enforce.incidents().incidents.len(), 1);

    let mut shadow = service(
        erroring_pack(),
        GovernanceMode::Shadow,
        VecIncidentRecorder::default(),
    );
    let result = shadow
        .evaluate(EvaluatePath::Sync, &request, request.decision_time)
        .unwrap();
    assert_eq!(result.response.policy_decision, Decision::Block);
    assert_eq!(result.response.returned_decision, Decision::Pass);
    assert_eq!(shadow.incidents().incidents.len(), 1);
}

struct FailingIncidents;

impl IncidentRecorder for FailingIncidents {
    fn record(&mut self, _incident: EvaluateIncident) -> Result<(), IncidentWriteError> {
        Err(IncidentWriteError("incident store down".into()))
    }
}

#[test]
fn incident_write_failure_is_surfaced() {
    let request = clean_request();
    let mut svc = service(erroring_pack(), GovernanceMode::Shadow, FailingIncidents);
    let result = svc
        .evaluate(EvaluatePath::Sync, &request, request.decision_time)
        .unwrap();
    assert_eq!(
        result.incident_write_error.as_deref(),
        Some("incident store down")
    );
}

fn at(days_ago: i64) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 1, 12, 0, 0).unwrap() - Duration::days(days_ago)
}

#[test]
fn batch_window_accepts_historical_rows_and_rejects_outside() {
    let now = at(0);
    let mut request = clean_request();
    request.decision_time = at(30);

    let mut svc = service(
        finance_pack(),
        GovernanceMode::Shadow,
        VecIncidentRecorder::default(),
    );
    // Default skew check rejects a 30-day-old row.
    assert!(matches!(
        svc.evaluate(EvaluatePath::Batch, &request, now),
        Err(EvaluateError::Validation(_))
    ));

    let window = DecisionTimeCheck::Window {
        from: at(31),
        to: at(29),
    };
    svc.evaluate_with_time_check(EvaluatePath::Batch, &request, now, window)
        .expect("row inside the declared window");

    let mut outside = clean_request();
    outside.correlation_id = "outside-1".into();
    outside.decision_time = at(40);
    assert!(matches!(
        svc.evaluate_with_time_check(EvaluatePath::Batch, &outside, now, window),
        Err(EvaluateError::Validation(_))
    ));
}

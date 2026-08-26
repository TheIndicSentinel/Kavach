mod common;

use common::{
    assert_valid, collect_json_files, golden_mvp_dir, golden_v0_dir, load_json,
    validator_for_schema, workspace_root, yaml_to_json,
};

#[test]
fn evaluate_request_schema_is_valid_meta_schema() {
    let _ = validator_for_schema("evaluate-request.schema.json");
}

#[test]
fn decision_event_schema_is_valid_meta_schema() {
    let _ = validator_for_schema("policy-pack.schema.json");
    let _ = validator_for_schema("model-record.schema.json");
    let _ = validator_for_schema("decision-event.schema.json");
}

#[test]
fn golden_v0_requests_match_evaluate_request_schema() {
    let validator = validator_for_schema("evaluate-request.schema.json");
    for path in collect_json_files(&golden_v0_dir()) {
        let fixture = load_json(&path);
        let request = &fixture["request"];
        assert_valid(
            &validator,
            request,
            &format!("golden v0 request in {}", path.display()),
        );
    }
}

#[test]
fn golden_mvp_requests_match_evaluate_request_schema() {
    let validator = validator_for_schema("evaluate-request.schema.json");
    for path in collect_json_files(&golden_mvp_dir()) {
        let fixture = load_json(&path);
        let request = &fixture["request"];
        assert_valid(
            &validator,
            request,
            &format!("golden mvp request in {}", path.display()),
        );
    }
}

#[test]
fn finance_policy_pack_matches_schema() {
    let validator = validator_for_schema("policy-pack.schema.json");
    let path = workspace_root().join("packs/finance/v0.yaml");
    let pack = yaml_to_json(&path);
    assert_valid(&validator, &pack, "packs/finance/v0.yaml");
}

#[test]
fn finance_model_record_matches_schema() {
    let validator = validator_for_schema("model-record.schema.json");
    let path = workspace_root().join("models/finance/credit-underwriting-v1.yaml");
    let model = yaml_to_json(&path);
    assert_valid(
        &validator,
        &model,
        "models/finance/credit-underwriting-v1.yaml",
    );
}

#[test]
fn golden_v0_fixtures_have_required_expect_fields() {
    for path in collect_json_files(&golden_v0_dir()) {
        let fixture = load_json(&path);
        assert!(
            fixture.get("name").is_some(),
            "missing name in {}",
            path.display()
        );
        assert!(
            fixture["expect"].get("policy_decision").is_some(),
            "missing expect.policy_decision in {}",
            path.display()
        );
        assert!(
            fixture["expect"].get("returned_decision_enforce").is_some(),
            "missing expect.returned_decision_enforce in {}",
            path.display()
        );
        assert!(
            fixture["expect"]
                .get("returned_decision_sync_shadow")
                .is_some(),
            "missing expect.returned_decision_sync_shadow in {}",
            path.display()
        );
    }
}

#[test]
fn proto_file_exists_and_declares_evaluate_service() {
    let proto = std::fs::read_to_string(workspace_root().join("proto/evaluate.proto"))
        .expect("read proto/evaluate.proto");
    assert!(proto.contains("service EvaluateService"));
    assert!(proto.contains("message EvaluateRequest"));
    assert!(proto.contains("message DecisionEvent"));
    assert!(proto.contains("policy_decision"));
    assert!(proto.contains("returned_decision"));
}

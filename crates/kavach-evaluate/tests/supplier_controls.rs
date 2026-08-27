use kavach_domain::{GovernanceMode, ModelOrigin, ModelRecord, ModelStatus, RiskTier};
use kavach_evaluate::validate_supplier_controls;
use serde_json::json;

fn sample_model(origin: ModelOrigin, mode: GovernanceMode, status: ModelStatus) -> ModelRecord {
    ModelRecord {
        model_id: "m".into(),
        version: "1".into(),
        sector: "finance".into(),
        owner: "o".into(),
        risk_tier: RiskTier::High,
        origin,
        governance_mode: mode,
        input_schema: json!({"type":"object"}),
        human_review_hold_policy: None,
        status,
        pack_id: "p".into(),
        purpose: "credit_decision".into(),
    }
}

#[test]
fn vendor_enforce_requires_production() {
    let model = sample_model(
        ModelOrigin::Vendor,
        GovernanceMode::Enforce,
        ModelStatus::Draft,
    );
    assert!(validate_supplier_controls(&model).is_err());
}

#[test]
fn vendor_enforce_allows_production() {
    let model = sample_model(
        ModelOrigin::Vendor,
        GovernanceMode::Enforce,
        ModelStatus::Production,
    );
    assert!(validate_supplier_controls(&model).is_ok());
}

#[test]
fn vendor_shadow_allows_draft() {
    let model = sample_model(
        ModelOrigin::Vendor,
        GovernanceMode::Shadow,
        ModelStatus::Draft,
    );
    assert!(validate_supplier_controls(&model).is_ok());
}

#[test]
fn in_house_enforce_allows_draft() {
    let model = sample_model(
        ModelOrigin::InHouse,
        GovernanceMode::Enforce,
        ModelStatus::Draft,
    );
    assert!(validate_supplier_controls(&model).is_ok());
}

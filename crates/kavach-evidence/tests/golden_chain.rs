//! End-to-end: golden fixtures → policy → evidence chain → verify.

use chrono::Utc;
use kavach_domain::{
    decision::map_returned_decision,
    golden::{canonical_input_digest, load_fixtures, workspace_golden_v0_dir},
    Decision, GovernanceMode, ModelOrigin,
};
use kavach_evidence::{verify_chain, AppendDecisionEvent, MemoryChain};
use kavach_policy::{PackLoader, PolicyEngine};

#[test]
fn golden_v0_fixtures_form_valid_evidence_chain() {
    let pack = PackLoader::load_from_path(
        &std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packs/finance/v0.yaml"),
    )
    .expect("load pack");

    let fixtures = load_fixtures(&workspace_golden_v0_dir()).expect("fixtures");
    let mut chain = MemoryChain::new();

    for fixture in fixtures {
        let Some(expected_policy) = fixture.expect.policy_decision else {
            continue;
        };

        let evaluation = PolicyEngine::evaluate(&pack, &fixture.request)
            .unwrap_or_else(|e| panic!("{}: {e}", fixture.name));

        assert_eq!(
            evaluation.policy_decision, expected_policy,
            "{}",
            fixture.name
        );

        let returned = map_returned_decision(
            evaluation.policy_decision,
            fixture.model.governance_mode,
            true,
        );

        if let Some(expected_returned) = fixture.expect.returned_decision_enforce {
            if fixture.model.governance_mode == GovernanceMode::Enforce {
                assert_eq!(returned, expected_returned, "{}", fixture.name);
            }
        }

        let event = chain
            .append(AppendDecisionEvent {
                pack_id: fixture.model.pack_id.clone(),
                pack_version: pack.pack.version.clone(),
                sector: fixture.model.sector.clone(),
                model_id: fixture.request.model_id.clone(),
                model_version: fixture.request.model_version.clone(),
                model_origin: ModelOrigin::InHouse,
                governance_mode: fixture.model.governance_mode,
                policy_decision: evaluation.policy_decision,
                returned_decision: returned,
                reason_codes: evaluation.reason_codes,
                policy_hits: evaluation.policy_hits,
                pii_tokens: vec![],
                input_digest: canonical_input_digest(&fixture.request.input),
                latency_ms: 1,
                decision_time: fixture.request.decision_time,
                evaluated_at: Utc::now(),
                service_identity_id: "svc-golden".into(),
                correlation_id: fixture.request.correlation_id.clone(),
                idempotency_key: fixture.request.idempotency_key.clone(),
            })
            .expect("append evidence");

        assert_eq!(event.policy_decision, expected_policy);
    }

    let report = verify_chain(chain.events()).expect("chain verify");
    assert_eq!(report.events_checked, 4);
}

#[test]
fn idempotency_returns_same_evidence_id() {
    let mut chain = MemoryChain::new();
    let input = AppendDecisionEvent {
        pack_id: "finance-v0".into(),
        pack_version: "0.1.0".into(),
        sector: "finance".into(),
        model_id: "m".into(),
        model_version: "1".into(),
        model_origin: ModelOrigin::InHouse,
        governance_mode: GovernanceMode::Enforce,
        policy_decision: Decision::Pass,
        returned_decision: Decision::Pass,
        reason_codes: vec![],
        policy_hits: vec![],
        pii_tokens: vec![],
        input_digest: "b".repeat(64),
        latency_ms: 1,
        decision_time: Utc::now(),
        evaluated_at: Utc::now(),
        service_identity_id: "svc".into(),
        correlation_id: "corr-1".into(),
        idempotency_key: None,
    };

    let first = chain.append(input.clone()).expect("first");
    let second = chain.append(input).expect("second");
    assert_eq!(first.evidence_id, second.evidence_id);
    assert_eq!(chain.events().len(), 1);
}

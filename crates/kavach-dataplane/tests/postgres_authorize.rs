//! The authorization core on Postgres, as the least-privilege runtime role:
//! mandates, replay guard and agent evidence all in the database.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use common::*;
use kavach_authz::AgentState;
use kavach_dataplane::{
    AgentIdentity, AuthorizeConfig, AuthorizeCore, CommitStatus, Mode, ToolCall,
};
use kavach_domain::Decision;
use kavach_keys::SubjectKeys;
use kavach_mandate::memory::{InMemoryConsentSource, InMemoryEventBus};
use kavach_mandate::{MandateDeps, MandateService};
use kavach_ports::agent_evidence::{verify_chain, AgentEvidenceStore};
use kavach_ports_testkit::agent_evidence::TestSigner;
use kavach_ports_testkit::FakeClock;
use kavach_storage::testing::isolated_database_urls;
use kavach_storage::StoragePool;

#[tokio::test(flavor = "multi_thread")]
async fn reminders_on_postgres_as_the_runtime_role() {
    let Some((owner, runtime)) = isolated_database_urls().await else {
        return;
    };
    let pool = StoragePool::connect_with_roles(
        &runtime,
        Some(&owner),
        &kavach_storage::DatabaseTls::development(),
    )
    .await
    .unwrap();
    let clock = Arc::new(FakeClock::synced_at(ist(11, 0, 0)));
    let Setup {
        kavach,
        sor,
        consents,
        config,
    } = setup();
    let mandates = Arc::new(
        MandateService::new(
            MandateDeps {
                keys: kavach,
                replay: pool.replay_guard(),
                consents: InMemoryConsentSource::new(consents),
                store: pool.mandate_store(),
                events: InMemoryEventBus::new(),
                clock: Clock(Arc::clone(&clock)),
            },
            config,
        )
        .unwrap(),
    );
    let signer = TestSigner::new("evidence-test", 9);
    let keys = signer.keys();
    let core = AuthorizeCore::new(
        Arc::clone(&mandates),
        Arc::new(pool.agent_evidence_store()),
        common::tools(),
        SubjectKeys::from_secret([6u8; 32]),
        Box::new(signer),
        Box::new(Clock(Arc::clone(&clock))),
        AuthorizeConfig::default(),
    )
    .unwrap();

    let token = event_token(&sor, "B-9382", ist(11, 0, 0)).await;
    let mandate = mandates.issue_from_event(&token).await.unwrap().mandate.id;
    // The same event again is a replay (guard and unique index).
    assert!(mandates.issue_from_event(&token).await.is_err());

    let agent = AgentIdentity {
        agent_id: "collections-agent".into(),
        identity_key: "oidc:https://idp#collections-agent".into(),
        state: AgentState::Active,
    };
    let call = |request_id: &str| ToolCall {
        mandate_id: mandate.clone(),
        action: "send_reminder".into(),
        request_id: request_id.into(),
        subject_ref: SUBJECT.into(),
        channel: Some("whatsapp".into()),
        waiver_bps: None,
        requested_fields: BTreeSet::new(),
        extra: BTreeMap::from([("template_id".to_string(), "emi_reminder_v1".to_string())]),
        violations: Vec::new(),
    };
    let first = core
        .authorize(&agent, &call("r-1"), Mode::Commit)
        .await
        .unwrap();
    assert_eq!(
        (first.decision, first.status),
        (Decision::Pass, CommitStatus::Committed)
    );
    let retry = core
        .authorize(&agent, &call("r-1"), Mode::Commit)
        .await
        .unwrap();
    assert_eq!(retry.status, CommitStatus::Replayed);
    assert_eq!(
        retry.grant.unwrap().credential_id,
        first.grant.unwrap().credential_id
    );
    for i in 2..=3 {
        let d = core
            .authorize(&agent, &call(&format!("r-{i}")), Mode::Commit)
            .await
            .unwrap();
        assert_eq!(d.decision, Decision::Pass);
    }
    let fourth = core
        .authorize(&agent, &call("r-4"), Mode::Commit)
        .await
        .unwrap();
    assert_eq!(fourth.decision, Decision::Block);

    let records = core.store().records(TENANT, 0).await.unwrap();
    assert_eq!(records.len(), 4, "three allows and the refused fourth");
    verify_chain(&records, &keys, None, &[], ist(12, 0, 0)).expect("signed chain");
}

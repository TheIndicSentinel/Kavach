use chrono::Utc;
use kavach_domain::{Decision, GovernanceMode, ModelOrigin};
use kavach_evaluate::EvidenceStore;
use kavach_evidence::AppendDecisionEvent;
use kavach_ports::agent_evidence::{EvidenceSigner, TimeSync};
use kavach_ports::checkpoint::{
    sign_checkpoint, Appended, CheckpointStore, Head, Scope, CHAIN_AGENT_DECISIONS,
    CHAIN_DECISION_EVENTS,
};
use kavach_ports::PortError;
use kavach_storage::testing::isolated_database_url;
use kavach_storage::{DatabaseTls, StoragePool};

struct TestSigner;

impl EvidenceSigner for TestSigner {
    fn key_id(&self) -> &str {
        "checkpoint-test"
    }

    fn sign(&self, _message: &[u8]) -> Result<Vec<u8>, PortError> {
        Ok(vec![0; 64])
    }
}

fn event(correlation_id: &str) -> AppendDecisionEvent {
    let now = Utc::now();
    AppendDecisionEvent {
        pack_id: "credit-test".into(),
        pack_version: "1".into(),
        sector: "finance".into(),
        model_id: "credit-test".into(),
        model_version: "1".into(),
        model_origin: ModelOrigin::InHouse,
        governance_mode: GovernanceMode::Enforce,
        policy_decision: Decision::Pass,
        returned_decision: Decision::Pass,
        reason_codes: vec![],
        policy_hits: vec![],
        pii_tokens: vec![],
        input_digest: format!("sha256:{}", "a".repeat(64)),
        latency_ms: 1,
        decision_time: now,
        evaluated_at: now,
        service_identity_id: "test".into(),
        correlation_id: correlation_id.into(),
        idempotency_key: None,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn postgres_credit_store_keeps_signed_checkpoints_scoped_and_linear() {
    let Some(database_url) = isolated_database_url().await else {
        return;
    };
    let storage = StoragePool::connect(&database_url, &DatabaseTls::development())
        .await
        .expect("migrate isolated schema");
    let tenant = "checkpoint-tenant";
    let store = storage.evidence_store_for_tenant(tenant);
    let mut writer = store.clone();
    let first = EvidenceStore::append(&mut writer, event("credit-cp-1")).expect("append first");
    let second = EvidenceStore::append(&mut writer, event("credit-cp-2")).expect("append second");
    let scope = Scope {
        tenant_id: tenant,
        partition_id: 0,
        chain: CHAIN_DECISION_EVENTS,
    };
    let signer = TestSigner;
    let first_checkpoint = sign_checkpoint(
        Head {
            scope,
            seq: 1,
            hash: &first.hash,
        },
        None,
        Utc::now(),
        TimeSync {
            status: "synced".into(),
            max_error_ms: Some(1),
        },
        &signer,
    )
    .expect("sign first checkpoint");
    assert_eq!(
        store.append(&first_checkpoint).await.unwrap(),
        Appended::Written
    );
    let second_checkpoint = sign_checkpoint(
        Head {
            scope,
            seq: 2,
            hash: &second.hash,
        },
        Some(&first_checkpoint),
        Utc::now(),
        TimeSync {
            status: "synced".into(),
            max_error_ms: Some(1),
        },
        &signer,
    )
    .expect("sign second checkpoint");
    assert_eq!(
        store.append(&second_checkpoint).await.unwrap(),
        Appended::Written
    );
    assert_eq!(store.head(scope).await.unwrap(), Some((2, second.hash)));
    assert_eq!(store.latest(scope).await.unwrap(), Some(second_checkpoint));
    assert_eq!(store.list(scope, 0, 10).await.unwrap().len(), 2);

    let agent_scope = Scope {
        chain: CHAIN_AGENT_DECISIONS,
        ..scope
    };
    let foreign_chain = sign_checkpoint(
        Head {
            scope: agent_scope,
            seq: 1,
            hash: &first.hash,
        },
        None,
        Utc::now(),
        TimeSync {
            status: "synced".into(),
            max_error_ms: Some(1),
        },
        &signer,
    )
    .expect("sign agent checkpoint");
    assert!(store.append(&foreign_chain).await.is_err());
}

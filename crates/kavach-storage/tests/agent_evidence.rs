//! Agent evidence stores against the shared contract (H5a-3b).

use std::sync::Arc;

use kavach_ports::agent_evidence::{AgentEvidenceStore, CommitResult};
use kavach_ports_testkit::agent_evidence::{conformance, request, TestSigner};
use kavach_ports_testkit::checkpoint_store;
use kavach_ports_testkit::FakeClock;
use kavach_storage::testing::isolated_database_urls;
use kavach_storage::{MemoryAgentEvidenceStore, StoragePool};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn memory_store_meets_the_contract() {
    conformance(Arc::new(MemoryAgentEvidenceStore::default())).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_store_meets_the_contract_as_the_runtime_role() {
    let Some((owner, runtime)) = isolated_database_urls().await else {
        return;
    };
    let pool = StoragePool::connect_with_roles(
        &runtime,
        Some(&owner),
        &kavach_storage::DatabaseTls::development(),
    )
    .await
    .expect("connect");
    conformance(Arc::new(pool.agent_evidence_store())).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn memory_checkpoint_store_meets_the_contract() {
    checkpoint_store::conformance(Arc::new(MemoryAgentEvidenceStore::default())).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_checkpoint_store_meets_the_contract_as_the_runtime_role() {
    let Some((owner, runtime)) = isolated_database_urls().await else {
        return;
    };
    let pool = StoragePool::connect_with_roles(
        &runtime,
        Some(&owner),
        &kavach_storage::DatabaseTls::development(),
    )
    .await
    .expect("connect");
    checkpoint_store::conformance(Arc::new(pool.agent_evidence_store())).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn checkpoints_are_append_only_even_for_their_owner() {
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
    // The conformance run leaves checkpoints behind to try to alter.
    checkpoint_store::conformance(Arc::new(pool.agent_evidence_store())).await;

    let statements = [
        "UPDATE evidence_checkpoints SET sig = 'x'",
        "DELETE FROM evidence_checkpoints",
        "TRUNCATE evidence_checkpoints",
    ];
    for statement in statements {
        let err = sqlx::query(statement)
            .execute(&pool.pool)
            .await
            .expect_err(statement);
        assert!(
            err.to_string().contains("permission denied"),
            "{statement}: {err}"
        );
    }
    let owner_pool = sqlx::PgPool::connect(&owner).await.unwrap();
    for statement in statements {
        let err = sqlx::query(statement)
            .execute(&owner_pool)
            .await
            .expect_err(statement);
        assert!(
            err.to_string().contains("append-only"),
            "{statement}: {err}"
        );
    }
    // The database itself refuses a second successor of the same checkpoint.
    let err = sqlx::query(
        "INSERT INTO evidence_checkpoints (tenant_id, partition_id, chain, seq, head_hash, \
            prev_checkpoint_hash, key_id, ts, hash, sig, payload) \
        SELECT tenant_id, partition_id, chain, seq + 1000, head_hash, prev_checkpoint_hash, \
            key_id, ts, hash || 'x', sig, payload FROM evidence_checkpoints LIMIT 1",
    )
    .execute(&owner_pool)
    .await
    .expect_err("fork");
    assert!(err.to_string().contains("duplicate key"), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn evidence_is_append_only_even_for_its_owner() {
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
    let store = pool.agent_evidence_store();
    let signer = TestSigner::new("evidence-test", 9);
    let clock = FakeClock::synced_at(chrono::Utc::now());
    let mut req = request("immutable", "r-1", 3);
    req.draft.send_by = None;
    assert!(matches!(
        store.commit(req, &clock, &signer).await.unwrap(),
        CommitResult::Committed(_)
    ));

    let statements = [
        "UPDATE agent_decisions SET sig = 'x'",
        "DELETE FROM agent_decisions",
        "TRUNCATE agent_decisions",
        "UPDATE agent_outcomes SET outcome = 'failed'",
        "DELETE FROM agent_outcomes",
        "TRUNCATE agent_outcomes",
    ];
    // The runtime role has no privilege for any of them.
    for statement in statements {
        let err = sqlx::query(statement)
            .execute(&pool.pool)
            .await
            .expect_err(statement);
        assert!(
            err.to_string().contains("permission denied"),
            "{statement}: {err}"
        );
    }
    // Even the owner is stopped by the append-only triggers (UPDATE, DELETE
    // and TRUNCATE on records; outcomes are empty, so check records).
    let owner_pool = sqlx::PgPool::connect(&owner).await.unwrap();
    for statement in &statements[..3] {
        let err = sqlx::query(statement)
            .execute(&owner_pool)
            .await
            .expect_err(statement);
        assert!(
            err.to_string().contains("append-only"),
            "{statement}: {err}"
        );
    }
}

/// A request refused for a raw phone number in a reference-only field is
/// recorded without the number or anything that reverses to it.
#[tokio::test]
async fn blocked_raw_identifier_leaves_no_trace_of_it() {
    use sha2::{Digest, Sha256};
    let phone = "9876543210";
    let keys = kavach_keys::SubjectKeys::from_secret([5u8; 32]);
    let store = MemoryAgentEvidenceStore::default();
    let signer = TestSigner::new("evidence-test", 9);
    let clock = FakeClock::synced_at(chrono::Utc::now());

    let mut req = request("privacy", "r-1", 3);
    req.draft.pre_commit_decision = kavach_domain::Decision::Block;
    // Reference-only violation: only the reason and field are recorded.
    req.draft.params_mac = None;
    req.binding.params_mac = None;
    req.draft.signals = vec!["reference_only_violation:recipient_ref".into()];
    req.draft.subject_pseudonym = keys.pseudonym("privacy", "ref:borrower:B-9382");
    req.binding.subject_pseudonym = req.draft.subject_pseudonym.clone();
    let CommitResult::Committed(record) = store.commit(req, &clock, &signer).await.unwrap() else {
        panic!("committed");
    };
    let text = serde_json::to_string(&*record).unwrap();
    assert!(!text.contains(phone), "raw number");
    assert!(
        !text.contains(&format!("{:x}", Sha256::digest(phone))),
        "unsalted hash"
    );
    assert!(
        !text.contains(&keys.params_mac("privacy", phone.as_bytes())),
        "MAC of the number"
    );
    assert!(!text.contains("B-9382"), "raw subject reference");
}

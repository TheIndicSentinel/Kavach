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
        "UPDATE agent_decisions SET kind = 'mandate_revocation'",
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
    // and TRUNCATE on records, the kind too; outcomes are empty, so check
    // records).
    let owner_pool = sqlx::PgPool::connect(&owner).await.unwrap();
    for statement in &statements[..4] {
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

/// A commit stopped by a unique key other than the request's (here: a
/// `credential_id` already used by a different request) is an error, never
/// treated as a retry of a stored record.
#[tokio::test(flavor = "multi_thread")]
async fn a_clash_on_another_key_is_an_error_not_a_retry() {
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
    let mut first = request("clash", "r-1", 3);
    first.draft.send_by = None;
    assert!(matches!(
        store.commit(first, &clock, &signer).await.unwrap(),
        CommitResult::Committed(_)
    ));
    // A different request that reuses r-1's credential id.
    let mut second = request("clash", "r-2", 3);
    second.draft.send_by = None;
    second.credential_id = "cred-r-1".into();
    let err = store
        .commit(second, &clock, &signer)
        .await
        .expect_err("a different request must not be answered with r-1's record");
    assert_eq!(err.class, kavach_ports::ErrorClass::Unavailable, "{err:?}");
    // Nothing of it was kept: no record, no reserved slot.
    assert_eq!(store.records("clash", 0).await.unwrap().len(), 1);
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

/// One row of the chain written directly by the owner, to probe the table's
/// constraints (R1b-1). `kind` is the column; `signed_kind` the payload's.
#[allow(clippy::too_many_arguments)]
async fn insert_row(
    pool: &sqlx::PgPool,
    seq: i64,
    kind: &str,
    signed_kind: &str,
    request_id: Option<&str>,
    source_system: Option<&str>,
    event_id: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO agent_decisions (tenant_id, partition_id, seq, record_id, prev_hash, \
            hash, sig, key_id, payload, kind, agent_id, request_id, binding, \
            returned_decision, source_system, event_id) \
        VALUES ('kinds', 0, $1, $2, 'p', 'h', 's', 'k', $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(seq)
    .bind(format!("kinds-{seq}-{kind}-{}", event_id.unwrap_or("none")))
    .bind(serde_json::json!({ "kind": signed_kind }))
    .bind(kind)
    .bind(request_id.map(|_| "agent-1"))
    .bind(request_id)
    .bind(request_id.map(|_| serde_json::json!({})))
    .bind(request_id.map(|_| "PASS"))
    .bind(source_system)
    .bind(event_id)
    .execute(pool)
    .await
    .map(|_| ())
}

/// R1b-1: the chain holds more than one kind of record in one table. The
/// kinds change no grant and no trigger, every record still takes one
/// position, and each kind's required fields are enforced by the database.
#[tokio::test(flavor = "multi_thread")]
async fn record_kinds_keep_grants_triggers_and_one_record_per_position() {
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
    let owner_pool = sqlx::PgPool::connect(&owner).await.unwrap();

    grants_and_triggers_are_unchanged(&owner_pool).await;

    // A decision is written exactly as before, and is of kind agent_decision.
    let store = pool.agent_evidence_store();
    let signer = TestSigner::new("evidence-test", 9);
    let clock = FakeClock::synced_at(chrono::Utc::now());
    let mut req = request("kinds", "r-1", 3);
    req.draft.send_by = None;
    assert!(matches!(
        store.commit(req, &clock, &signer).await.unwrap(),
        CommitResult::Committed(_)
    ));
    let kinds: Vec<String> = sqlx::query_scalar("SELECT kind FROM agent_decisions")
        .fetch_all(&owner_pool)
        .await
        .unwrap();
    assert_eq!(kinds, ["agent_decision"]);

    each_kind_is_enforced(&owner_pool).await;

    // A revocation record is append-only too, for the runtime role and owner.
    for statement in [
        "UPDATE agent_decisions SET event_id = 'x' WHERE kind = 'mandate_revocation'",
        "DELETE FROM agent_decisions WHERE kind = 'mandate_revocation'",
    ] {
        let err = sqlx::query(statement)
            .execute(&pool.pool)
            .await
            .expect_err(statement);
        assert!(
            err.to_string().contains("permission denied"),
            "{statement}: {err}"
        );
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

/// The kinds changed no grant and no trigger: the runtime role may read and
/// append, nothing more, and both append-only triggers are in place.
async fn grants_and_triggers_are_unchanged(owner_pool: &sqlx::PgPool) {
    // The runtime role may read and append, nothing more.
    for (privilege, granted) in [
        ("SELECT", true),
        ("INSERT", true),
        ("UPDATE", false),
        ("DELETE", false),
        ("TRUNCATE", false),
    ] {
        let has: bool = sqlx::query_scalar(
            "SELECT has_table_privilege('kavach_runtime', 'agent_decisions', $1)",
        )
        .bind(privilege)
        .fetch_one(owner_pool)
        .await
        .unwrap();
        assert_eq!(has, granted, "runtime {privilege}");
    }
    let mut triggers: Vec<String> = sqlx::query_scalar(
        "SELECT tgname::text FROM pg_trigger \
        WHERE tgrelid = 'agent_decisions'::regclass AND NOT tgisinternal",
    )
    .fetch_all(owner_pool)
    .await
    .unwrap();
    triggers.sort();
    assert_eq!(
        triggers,
        ["agent_decisions_append_only", "agent_decisions_no_truncate"]
    );
}

/// Each kind's required fields, the signed kind, one record per position and
/// one revocation record per event, enforced by the database.
async fn each_kind_is_enforced(owner_pool: &sqlx::PgPool) {
    let refused = |result: Result<(), sqlx::Error>, why: &str, expected: &str| {
        let err = result.expect_err(why).to_string();
        assert!(err.contains(expected), "{why}: {err}");
    };
    let rev = "mandate_revocation";
    refused(
        insert_row(
            owner_pool,
            2,
            "agent_decision",
            "agent_decision",
            None,
            None,
            None,
        )
        .await,
        "a decision without its request",
        "agent_records_decision_fields",
    );
    refused(
        insert_row(
            owner_pool,
            2,
            rev,
            rev,
            Some("r-2"),
            Some("lms"),
            Some("e-1"),
        )
        .await,
        "a revocation carrying decision fields",
        "agent_records_revocation_fields",
    );
    refused(
        insert_row(owner_pool, 2, rev, rev, None, None, None).await,
        "a revocation without its event",
        "agent_records_revocation_fields",
    );
    refused(
        insert_row(
            owner_pool,
            2,
            rev,
            "agent_decision",
            None,
            Some("lms"),
            Some("e-1"),
        )
        .await,
        "a column kind other than the signed kind",
        "agent_records_kind_is_signed",
    );
    refused(
        insert_row(
            owner_pool,
            2,
            "agent_state",
            "agent_state",
            None,
            Some("lms"),
            Some("e-1"),
        )
        .await,
        "a kind this schema does not know",
        "agent_records_kind_known",
    );
    refused(
        insert_row(owner_pool, 1, rev, rev, None, Some("lms"), Some("e-1")).await,
        "a second record at a taken position",
        "duplicate key",
    );
    insert_row(owner_pool, 2, rev, rev, None, Some("lms"), Some("e-1"))
        .await
        .expect("a revocation record");
    refused(
        insert_row(owner_pool, 3, rev, rev, None, Some("lms"), Some("e-1")).await,
        "a second record for one event",
        "agent_records_one_per_revocation_event",
    );
    insert_row(owner_pool, 3, rev, rev, None, Some("lms"), Some("e-2"))
        .await
        .expect("another event, another record");
}

//! Postgres adapters against a real database (`KAVACH_TEST_DATABASE_URL`).
//! Each test runs in its own schema; CI fails if the database is missing.

use chrono::{Duration, Utc};
use kavach_domain::{Decision, GovernanceMode, ModelOrigin};
use kavach_evaluate::{EvaluateIncident, EvidenceStore, IncidentRecorder};
use kavach_evidence::{AppendDecisionEvent, EvidenceError};
use kavach_storage::testing::isolated_database_url;
use kavach_storage::{
    AuditInsert, BatchJobCreate, BatchJobStore, RetentionStoreError, RuntimePointers, StoragePool,
    TombstoneReason,
};

async fn pool() -> Option<StoragePool> {
    let url = isolated_database_url().await?;
    Some(StoragePool::connect(&url).await.expect("connect + migrate"))
}

fn event(correlation_id: &str, input_digest: &str, age_days: i64) -> AppendDecisionEvent {
    let at = Utc::now() - Duration::days(age_days);
    AppendDecisionEvent {
        pack_id: "finance-v0".into(),
        pack_version: "0.1.0".into(),
        sector: "finance".into(),
        model_id: "credit-underwriting-v1".into(),
        model_version: "1.0.0".into(),
        model_origin: ModelOrigin::InHouse,
        governance_mode: GovernanceMode::Shadow,
        policy_decision: Decision::Pass,
        returned_decision: Decision::Pass,
        reason_codes: vec![],
        policy_hits: vec![],
        pii_tokens: vec![],
        input_digest: input_digest.into(),
        latency_ms: 1,
        decision_time: at,
        evaluated_at: at,
        service_identity_id: "test".into(),
        correlation_id: correlation_id.into(),
        idempotency_key: None,
    }
}

async fn chain(pool: &StoragePool) -> Vec<(String, String)> {
    sqlx::query_as::<_, (String, String)>(
        "SELECT prev_hash, hash FROM decision_events ORDER BY created_at, prev_hash",
    )
    .fetch_all(&pool.pool)
    .await
    .unwrap()
}

/// Every event links to exactly one predecessor and the meta head is the tip.
async fn assert_linear_chain(pool: &StoragePool, expected_len: usize) {
    let links = chain(pool).await;
    assert_eq!(links.len(), expected_len);
    let mut next = std::collections::HashMap::new();
    for (prev, hash) in &links {
        assert!(
            next.insert(prev.clone(), hash.clone()).is_none(),
            "fork at {prev}"
        );
    }
    let mut cursor = "0".repeat(64);
    for _ in 0..expected_len {
        cursor = next.get(&cursor).expect("broken chain").clone();
    }
    let head: String = sqlx::query_scalar("SELECT head_hash FROM evidence_chain_meta WHERE id = 1")
        .fetch_one(&pool.pool)
        .await
        .unwrap();
    assert_eq!(head, cursor);
}

#[tokio::test(flavor = "multi_thread")]
async fn evidence_appends_form_a_chain_and_replay_idempotently() {
    let Some(pool) = pool().await else { return };
    let mut store = pool.evidence_store();
    let first = store.append(event("c-1", "d-1", 0)).unwrap();
    let second = store.append(event("c-2", "d-2", 0)).unwrap();
    assert_eq!(first.prev_hash, "0".repeat(64));
    assert_eq!(second.prev_hash, first.hash);

    let replay = store.append(event("c-1", "d-1", 0)).unwrap();
    assert_eq!(replay.evidence_id, first.evidence_id);
    assert!(matches!(
        store.append(event("c-1", "different-input", 0)),
        Err(EvidenceError::IdempotencyConflict { .. })
    ));
    assert_linear_chain(&pool, 2).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_appends_stay_linear() {
    let Some(pool) = pool().await else { return };
    let tasks: Vec<_> = (0..16)
        .map(|i| {
            let mut store = pool.evidence_store();
            tokio::spawn(async move { store.append(event(&format!("c-{i}"), "d", 0)) })
        })
        .collect();
    for task in tasks {
        task.await.unwrap().expect("append");
    }
    assert_linear_chain(&pool, 16).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_retries_of_one_request_return_the_same_decision() {
    let Some(pool) = pool().await else { return };
    let tasks: Vec<_> = (0..8)
        .map(|_| {
            let mut store = pool.evidence_store();
            tokio::spawn(async move { store.append(event("same", "d", 0)) })
        })
        .collect();
    let mut ids = std::collections::HashSet::new();
    for task in tasks {
        ids.insert(task.await.unwrap().expect("retry replays").evidence_id);
    }
    assert_eq!(ids.len(), 1);
    assert_linear_chain(&pool, 1).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn runtime_pointers_and_audit_round_trip() {
    let Some(pool) = pool().await else { return };
    let admin = pool.admin_store();
    assert!(admin.get_runtime_pointers().await.unwrap().is_none());

    let pointers = RuntimePointers {
        pack_path: "packs/a.yaml".into(),
        model_path: "models/m.yaml".into(),
        previous_pack_path: Some("packs/old.yaml".into()),
        pack_sha256: Some("sha256:aa".into()),
        previous_pack_sha256: Some("sha256:bb".into()),
        updated_at: Utc::now(),
        updated_by: "admin-1".into(),
        approved_by: "admin-2".into(),
        version: 0,
    };
    admin.set_runtime_pointers(pointers.clone()).await.unwrap();
    let stored = admin.get_runtime_pointers().await.unwrap().unwrap();
    assert_eq!(stored.pack_path, pointers.pack_path);
    assert_eq!(stored.pack_sha256, pointers.pack_sha256);
    assert_eq!(stored.previous_pack_sha256, pointers.previous_pack_sha256);
    assert_eq!(stored.approved_by, "admin-2");

    // A second write replaces the singleton row.
    admin
        .set_runtime_pointers(RuntimePointers {
            pack_path: "packs/b.yaml".into(),
            ..pointers
        })
        .await
        .unwrap();
    assert_eq!(
        admin
            .get_runtime_pointers()
            .await
            .unwrap()
            .unwrap()
            .pack_path,
        "packs/b.yaml"
    );

    for action in ["first", "second", "third"] {
        admin
            .append_audit(AuditInsert {
                action: action.into(),
                resource_type: "policy_pack".into(),
                resource_id: "p".into(),
                actor_principal: "admin-1".into(),
                approver_principal: "admin-2".into(),
                payload: serde_json::json!({ "n": action }),
            })
            .await
            .unwrap();
    }
    let listed = admin.list_audit(2).await.unwrap();
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].payload["n"], "third");
}

#[tokio::test(flavor = "multi_thread")]
async fn retention_tombstones_only_expired_untombstoned_evidence() {
    let Some(pool) = pool().await else { return };
    let mut evidence = pool.evidence_store();
    let old = evidence.append(event("old", "d", 400)).unwrap();
    let erased = evidence.append(event("erased", "d", 400)).unwrap();
    let fresh = evidence.append(event("fresh", "d", 1)).unwrap();

    let retention = pool.retention_store();
    assert_eq!(
        retention
            .get_settings()
            .await
            .unwrap()
            .evidence_retention_days,
        365
    );
    let updated = retention
        .set_settings(30, "admin-1", "admin-2")
        .await
        .unwrap();
    assert_eq!(updated.evidence_retention_days, 30);
    assert_eq!(updated.approved_by.as_deref(), Some("admin-2"));
    retention
        .set_settings(365, "admin-1", "admin-2")
        .await
        .unwrap();

    assert!(matches!(
        retention
            .tombstone("missing", TombstoneReason::DpdpErasure, "a", "b")
            .await,
        Err(RetentionStoreError::NotFound(_))
    ));
    retention
        .tombstone(&erased.evidence_id, TombstoneReason::DpdpErasure, "a", "b")
        .await
        .unwrap();
    assert!(matches!(
        retention
            .tombstone(&erased.evidence_id, TombstoneReason::DpdpErasure, "a", "b")
            .await,
        Err(RetentionStoreError::AlreadyTombstoned(_))
    ));

    let report = retention.apply_retention("a", "b").await.unwrap();
    assert_eq!(report.evidence_ids, vec![old.evidence_id.clone()]);
    assert!(retention.is_tombstoned(&old.evidence_id).await.unwrap());
    assert!(!retention.is_tombstoned(&fresh.evidence_id).await.unwrap());
    // Running again finds nothing new.
    assert_eq!(
        retention
            .apply_retention("a", "b")
            .await
            .unwrap()
            .tombstoned_count,
        0
    );
    assert_eq!(retention.list_tombstones(10).await.unwrap().len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn incidents_and_batch_jobs_round_trip() {
    let Some(pool) = pool().await else { return };
    let mut incidents = pool.incident_store();
    incidents
        .record(EvaluateIncident {
            correlation_id: "c-1".into(),
            model_id: "credit-underwriting-v1".into(),
            reason: "evidence_write_failed".into(),
        })
        .unwrap();
    let listed = incidents.list(10).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].reason, "evidence_write_failed");

    let mut jobs = pool.batch_job_store();
    let job_id = jobs
        .create_pending(&BatchJobCreate {
            input_path: "/data/in.ndjson".into(),
            output_path: "/data/out.ndjson".into(),
            model_id: "credit-underwriting-v1".into(),
            governance_mode: GovernanceMode::Shadow,
        })
        .unwrap();
    jobs.mark_running(&job_id, 3).unwrap();
    jobs.mark_completed(&job_id, 3, 2, 1, 0).unwrap();
    let job = jobs.get(&job_id).await.unwrap();
    assert_eq!(job.status, "completed");
    assert_eq!((job.succeeded_rows, job.failed_rows), (2, 1));
    assert_eq!(jobs.list(10).await.unwrap().len(), 1);
}

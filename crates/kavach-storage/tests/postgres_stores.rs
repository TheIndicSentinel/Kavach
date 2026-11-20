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
    Some(
        StoragePool::connect(&url, &kavach_storage::DatabaseTls::development())
            .await
            .expect("connect + migrate"),
    )
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

#[tokio::test(flavor = "multi_thread")]
async fn evidence_and_retention_are_scoped_to_tenant() {
    let Some(pool) = pool().await else { return };
    let mut tenant_a = pool.evidence_store_for_tenant("retention-a");
    let mut tenant_b = pool.evidence_store_for_tenant("retention-b");
    let a = tenant_a
        .append(event("shared-correlation", "digest-a", 0))
        .unwrap();
    let b = tenant_b
        .append(event("shared-correlation", "digest-b", 0))
        .unwrap();
    assert_eq!(a.prev_hash, "0".repeat(64));
    assert_eq!(b.prev_hash, "0".repeat(64));
    assert!(tenant_a.event(&b.evidence_id).await.unwrap().is_none());
    assert!(tenant_b.event(&a.evidence_id).await.unwrap().is_none());

    let retention_a = pool.retention_store_for_tenant("retention-a");
    let retention_b = pool.retention_store_for_tenant("retention-b");
    retention_a.set_settings(30, "a", "b").await.unwrap();
    assert_eq!(
        retention_a
            .get_settings()
            .await
            .unwrap()
            .evidence_retention_days,
        30
    );
    assert_eq!(
        retention_b
            .get_settings()
            .await
            .unwrap()
            .evidence_retention_days,
        365
    );

    retention_a
        .tombstone(&a.evidence_id, TombstoneReason::DpdpErasure, "a", "b")
        .await
        .unwrap();
    assert!(retention_a.is_tombstoned(&a.evidence_id).await.unwrap());
    assert!(!retention_b.is_tombstoned(&a.evidence_id).await.unwrap());
    assert!(retention_b
        .candidates(Utc::now())
        .await
        .unwrap()
        .contains(&b.evidence_id));
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
async fn admin_audit_reads_are_scoped_to_the_requested_tenant() {
    let Some(pool) = pool().await else { return };
    let admin = pool.admin_store();
    for tenant_id in ["audit-tenant-a", "audit-tenant-b"] {
        let entry = admin
            .append_audit(AuditInsert {
                tenant_id: tenant_id.into(),
                acting_as_superadmin: false,
                action: "tenant_scope_probe".into(),
                resource_type: "test".into(),
                resource_id: "shared-resource".into(),
                actor_principal: "actor".into(),
                approver_principal: "approver".into(),
                payload: serde_json::json!({}),
            })
            .await
            .expect("append audit row");
        assert_eq!(entry.tenant_id, tenant_id);
    }

    for tenant_id in ["audit-tenant-a", "audit-tenant-b"] {
        let rows = admin
            .list_audit(tenant_id, 10)
            .await
            .expect("scoped audit list");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].tenant_id, tenant_id);
        let last = admin
            .last_audit(tenant_id, "tenant_scope_probe", "shared-resource")
            .await
            .expect("scoped last audit")
            .expect("tenant's audit row");
        assert_eq!(last.tenant_id, tenant_id);
    }
    assert!(admin
        .list_audit("audit-tenant-other", 10)
        .await
        .expect("unrelated tenant list")
        .is_empty());
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
        model_sha256: None,
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
                tenant_id: "default".into(),
                acting_as_superadmin: false,
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
    let listed = admin.list_audit("default", 2).await.unwrap();
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].payload["n"], "third");
}

#[tokio::test(flavor = "multi_thread")]
async fn runtime_pointers_are_scoped_to_tenant() {
    let Some(pool) = pool().await else { return };
    let pointer = |pack_path: &str| RuntimePointers {
        pack_path: pack_path.into(),
        model_path: "models/model.yaml".into(),
        previous_pack_path: None,
        pack_sha256: None,
        previous_pack_sha256: None,
        model_sha256: None,
        updated_at: Utc::now(),
        updated_by: "operator".into(),
        approved_by: "approver".into(),
        version: 0,
    };
    let tenant_a = pool.admin_store_for_tenant("runtime-a");
    let tenant_b = pool.admin_store_for_tenant("runtime-b");
    tenant_a
        .set_runtime_pointers(pointer("packs/a.yaml"))
        .await
        .unwrap();
    tenant_b
        .set_runtime_pointers(pointer("packs/b.yaml"))
        .await
        .unwrap();
    let a = tenant_a.get_runtime_pointers().await.unwrap().unwrap();
    let b = tenant_b.get_runtime_pointers().await.unwrap().unwrap();
    assert_eq!(a.pack_path, "packs/a.yaml");
    assert_eq!(b.pack_path, "packs/b.yaml");
    assert_eq!((a.version, b.version), (1, 1));
    assert!(pool
        .admin_store_for_tenant("runtime-c")
        .get_runtime_pointers()
        .await
        .unwrap()
        .is_none());
}

/// S3: an entry derived from stored state is written once per key; entries
/// without a key are unaffected (NULLs are distinct in the unique index).
#[tokio::test(flavor = "multi_thread")]
async fn an_audit_entry_with_a_key_is_written_once() {
    let Some(pool) = pool().await else { return };
    let admin = pool.admin_store();
    let entry = |n: &str| AuditInsert {
        tenant_id: "default".into(),
        acting_as_superadmin: false,
        action: "mandates_revoked_by_event".into(),
        resource_type: "loan".into(),
        resource_id: "lms:loan/L-1".into(),
        actor_principal: "system-of-record".into(),
        approver_principal: String::new(),
        payload: serde_json::json!({ "n": n }),
    };
    assert!(admin
        .append_audit_once("revocation:t:lms:e-1", entry("first"))
        .await
        .unwrap());
    assert!(!admin
        .append_audit_once("revocation:t:lms:e-1", entry("again"))
        .await
        .unwrap());
    assert!(admin
        .append_audit_once("revocation:t:lms:e-2", entry("other"))
        .await
        .unwrap());
    // Plain entries have no key and are never merged.
    admin.append_audit(entry("plain-1")).await.unwrap();
    admin.append_audit(entry("plain-2")).await.unwrap();
    let listed = admin.list_audit("default", 10).await.unwrap();
    let ns: Vec<&str> = listed
        .iter()
        .filter_map(|e| e.payload["n"].as_str())
        .collect();
    assert_eq!(ns.iter().filter(|n| **n == "first").count(), 1);
    assert_eq!(ns.iter().filter(|n| **n == "again").count(), 0);
    assert_eq!(ns.len(), 4);
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

#[tokio::test(flavor = "multi_thread")]
async fn batch_never_baselines_and_refuses_a_changed_model_file() {
    use kavach_storage::{govern_model, AdminBackend, ModelStartupError, ModelStartupRole};

    let Some(pool) = pool().await else { return };
    let admin = AdminBackend::Postgres(pool.admin_store());
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../models/finance/credit-underwriting-v1.yaml");
    let bytes = std::fs::read(&path).unwrap();
    let yaml: kavach_domain::ModelRecord = serde_yaml::from_slice(&bytes).unwrap();
    let digest = kavach_policy::pack_digest(&bytes);

    // Nothing governed yet: batch refuses and writes nothing.
    let err = govern_model(
        &admin,
        "default",
        &path,
        yaml.clone(),
        &digest,
        ModelStartupRole::Batch,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, ModelStartupError::NotGoverned(_)), "{err}");
    assert!(admin.get_runtime_pointers().await.unwrap().is_none());

    // The API records the baseline.
    assert!(admin
        .insert_pointers_if_absent(RuntimePointers {
            pack_path: "packs/finance/v0.yaml".into(),
            model_path: path.display().to_string(),
            previous_pack_path: None,
            pack_sha256: None,
            previous_pack_sha256: None,
            model_sha256: Some(digest.clone()),
            updated_at: Utc::now(),
            updated_by: "system:startup".into(),
            approved_by: "system:startup".into(),
            version: 0,
        })
        .await
        .unwrap());
    let api = ModelStartupRole::Api {
        bootstrap_model: false,
    };
    govern_model(&admin, "default", &path, yaml.clone(), &digest, api)
        .await
        .unwrap();

    // Governed mode reaches batch even though the YAML says shadow.
    sqlx::query("UPDATE model_state SET governance_mode = 'enforce'")
        .execute(&pool.pool)
        .await
        .unwrap();
    let governed = govern_model(
        &admin,
        "default",
        &path,
        yaml.clone(),
        &digest,
        ModelStartupRole::Batch,
    )
    .await
    .unwrap();
    assert_eq!(governed.model.governance_mode, GovernanceMode::Enforce);
    assert!(governed.yaml_divergence.is_some());

    // A changed file is refused; batch has no override.
    let err = govern_model(
        &admin,
        "default",
        &path,
        yaml,
        "sha256:changed",
        ModelStartupRole::Batch,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, ModelStartupError::DigestMismatch { .. }),
        "{err}"
    );
}

/// An event read back from Postgres (which keeps microseconds) still
/// hashes to its stored hash, even if it was evaluated with nanoseconds.
#[tokio::test(flavor = "multi_thread")]
async fn events_read_back_from_postgres_verify() {
    use chrono::Timelike;
    let Some(pool) = pool().await else { return };
    let mut store = pool.evidence_store();
    let mut input = event("precision-1", &"b".repeat(64), 0);
    input.decision_time +=
        Duration::nanoseconds(123_456_789 - i64::from(input.decision_time.nanosecond()));
    input.evaluated_at = input.decision_time;
    let appended = store.append(input).expect("append");
    let read = store
        .event(&appended.evidence_id)
        .await
        .expect("read")
        .expect("stored");
    assert_eq!(read, appended, "the stored event is the hashed event");
    kavach_evidence::verify_event_hash(&read).expect("hash matches the stored content");
    assert!(store
        .event("00000000-0000-4000-8000-000000000000")
        .await
        .unwrap()
        .is_none());
}

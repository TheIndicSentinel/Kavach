//! Migration tracking and role separation (H5a-3a, ADR-005 §1).

use chrono::Utc;
use kavach_storage::testing::{auditor_url, isolated_database_url, isolated_database_urls};
use kavach_storage::{AuditInsert, RuntimePointers, StoragePool};

#[tokio::test(flavor = "multi_thread")]
async fn runtime_role_cannot_alter_evidence_or_governance_history() {
    let Some((owner, runtime)) = isolated_database_urls().await else {
        return;
    };
    let pool = StoragePool::connect_with_roles(&runtime, Some(&owner))
        .await
        .expect("migrate as owner, connect as runtime");

    // What the application does still works.
    let admin = pool.admin_store();
    admin
        .append_audit(AuditInsert {
            action: "probe".into(),
            resource_type: "test".into(),
            resource_id: "r".into(),
            actor_principal: "a".into(),
            approver_principal: "b".into(),
            payload: serde_json::json!({}),
        })
        .await
        .expect("audit insert");
    admin
        .set_runtime_pointers(RuntimePointers {
            pack_path: "p".into(),
            model_path: "m".into(),
            previous_pack_path: None,
            pack_sha256: None,
            previous_pack_sha256: None,
            model_sha256: None,
            updated_at: Utc::now(),
            updated_by: "a".into(),
            approved_by: "b".into(),
            version: 0,
        })
        .await
        .expect("pointer upsert");

    // What it must not do is refused by the database itself.
    for statement in [
        "UPDATE admin_audit_log SET action = 'x'",
        "DELETE FROM admin_audit_log",
        "TRUNCATE admin_audit_log",
        "UPDATE decision_events SET hash = 'x'",
        "DELETE FROM decision_events",
        "TRUNCATE decision_events",
        "DELETE FROM change_requests",
        "TRUNCATE change_requests",
        "DELETE FROM mandates",
        "DROP TRIGGER change_requests_guard ON change_requests",
        "ALTER TABLE admin_audit_log DISABLE TRIGGER ALL",
        "DROP TABLE admin_audit_log",
        "CREATE TABLE intruder (id INT)",
    ] {
        let err = sqlx::query(statement)
            .execute(&pool.pool)
            .await
            .expect_err(statement);
        let message = err.to_string();
        assert!(
            message.contains("permission denied") || message.contains("must be owner"),
            "{statement}: {message}"
        );
    }
}

/// The export role reads the agent evidence and nothing else, and writes
/// nothing (ADR-005 §13).
#[tokio::test(flavor = "multi_thread")]
async fn auditor_role_reads_agent_evidence_and_nothing_else() {
    let Some((owner, runtime)) = isolated_database_urls().await else {
        return;
    };
    StoragePool::connect_with_roles(&runtime, Some(&owner))
        .await
        .expect("migrate as owner");
    let auditor = sqlx::PgPool::connect(&auditor_url(&owner))
        .await
        .expect("connect as kavach_auditor");

    for table in [
        "agent_decisions",
        "agent_outcomes",
        "evidence_checkpoints",
        "agent_evidence_chains",
    ] {
        sqlx::query(&format!("SELECT * FROM {table} LIMIT 1"))
            .fetch_optional(&auditor)
            .await
            .unwrap_or_else(|e| panic!("auditor reads {table}: {e}"));
    }
    for statement in [
        // No writes to what it reads.
        "INSERT INTO agent_evidence_chains (tenant_id, partition_id, head_seq, head_hash) \
            VALUES ('t', 0, 0, 'x')",
        "UPDATE agent_evidence_chains SET head_seq = 0",
        "DELETE FROM agent_decisions",
        "DELETE FROM agent_outcomes",
        "DELETE FROM evidence_checkpoints",
        "TRUNCATE evidence_checkpoints",
        // No access to anything else.
        "SELECT * FROM mandates",
        "SELECT * FROM contact_counters",
        "SELECT * FROM decision_events",
        "SELECT * FROM admin_audit_log",
        "SELECT * FROM replay_guard",
        "CREATE TABLE intruder (id INT)",
    ] {
        let err = sqlx::query(statement)
            .execute(&auditor)
            .await
            .expect_err(statement);
        assert!(
            err.to_string().contains("permission denied"),
            "{statement}: {err}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn migrations_apply_once_on_fresh_and_upgraded_databases() {
    // Fresh: migrate twice; the second run is a no-op.
    let Some(url) = isolated_database_url().await else {
        return;
    };
    kavach_storage::migrate(&url).await.expect("fresh");
    kavach_storage::migrate(&url).await.expect("idempotent");
    let pool = StoragePool::connect_with_roles(&url, None).await.unwrap();
    let applied: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations WHERE success")
        .fetch_one(&pool.pool)
        .await
        .unwrap();
    assert!(applied >= 9, "{applied}");

    // Upgraded: a database built by the pre-tracking runner (each file run
    // whole, untracked) adopts tracking without errors.
    let Some(url) = isolated_database_url().await else {
        return;
    };
    let legacy = sqlx::PgPool::connect(&url).await.unwrap();
    for sql in [
        include_str!("../migrations/001_evidence.sql"),
        include_str!("../migrations/002_batch_jobs.sql"),
        include_str!("../migrations/003_admin_governance.sql"),
        include_str!("../migrations/004_retention_erasure.sql"),
        include_str!("../migrations/005_pack_digest.sql"),
        include_str!("../migrations/006_change_requests.sql"),
        include_str!("../migrations/007_model_state.sql"),
        include_str!("../migrations/008_mandates.sql"),
    ] {
        sqlx::raw_sql(sql)
            .execute(&legacy)
            .await
            .expect("legacy runner");
    }
    sqlx::query("INSERT INTO admin_audit_log (action, resource_type, resource_id, actor_principal, approver_principal) VALUES ('kept', 't', 'r', 'a', 'b')")
        .execute(&legacy)
        .await
        .unwrap();
    legacy.close().await;
    kavach_storage::migrate(&url).await.expect("adopt tracking");
    let pool = StoragePool::connect_with_roles(&url, None).await.unwrap();
    let kept: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM admin_audit_log WHERE action = 'kept'")
            .fetch_one(&pool.pool)
            .await
            .unwrap();
    assert_eq!(kept, 1, "existing data survives");
}

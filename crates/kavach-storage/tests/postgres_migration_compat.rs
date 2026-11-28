//! The expand half of an expand-then-contract upgrade (rollout rehearsal):
//! a database at migration 019 holds rows written by the previous version;
//! after migrations 020–022 (additive, nullable) those rows read back with
//! the new columns unknown, the previous version's INSERT statements still
//! work, and the new code scopes and revokes the old rows as it did.
//!
//! What this does **not** show: an old binary starting against the new
//! schema. `sqlx` refuses a database whose applied migrations it does not
//! know, so rollback needs the migrations reverted first (they are additive
//! and nullable; dropping the three columns and two indexes is safe once no
//! new binary runs).

use std::borrow::Cow;
use std::path::Path;

use chrono::{Duration, TimeZone, Utc};
use kavach_ports::{MandateStore, RevocationApply};
use kavach_storage::testing::isolated_database_url;
use kavach_storage::StoragePool;
use sqlx::migrate::Migrator;
use sqlx::postgres::PgPoolOptions;

const LAST_OLD_MIGRATION: i64 = 19;

/// Rows written by the previous version, with its statements (no
/// `source_occurred_at`, `clock_synced` or `idempotency_key`).
async fn insert_previous_version_rows(
    raw: &sqlx::PgPool,
    root: &kavach_ports::StoredMandate,
    issued_at: chrono::DateTime<Utc>,
) {
    sqlx::query(
        "INSERT INTO mandates (tenant_id, id, parent_id, depth, status, revoked_reason, token, \
            mandate, source_system, source_event_id) \
        VALUES ($1, $2, NULL, 0, 'active', NULL, $3, $4, $5, $6)",
    )
    .bind(&root.mandate.tenant_id)
    .bind(&root.mandate.id)
    .bind(&root.token)
    .bind(serde_json::to_value(&root.mandate).unwrap())
    .bind(&root.mandate.source.system)
    .bind(&root.mandate.source.event_id)
    .execute(raw)
    .await
    .expect("old mandate insert");
    sqlx::query(
        "INSERT INTO admin_audit_log (action, resource_type, resource_id, actor_principal, \
            approver_principal, payload) VALUES ('old', 'loan', 'l', 'a', '', '{}')",
    )
    .execute(raw)
    .await
    .expect("old audit insert");
    sqlx::query(
        "INSERT INTO mandate_revocations (tenant_id, source_system, event_id, content_sha256, \
            event_type, record_ref, occurred_at, revoked, created_at) \
        VALUES ('compat', 'lms', 'pay-old', $1, 'loan.paid', 'other-loan', $2, '[]', $2)",
    )
    .bind("ab".repeat(32))
    .bind(issued_at)
    .execute(raw)
    .await
    .expect("old revocation insert");
}

#[tokio::test(flavor = "multi_thread")]
async fn rows_and_statements_from_the_previous_version_survive_migrations_020_to_022() {
    let Some(url) = isolated_database_url().await else {
        return;
    };
    let raw = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("connect");

    // The database as the previous version left it: migrations up to 019.
    let full = Migrator::new(Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/migrations"
    )))
    .await
    .expect("migrations");
    let old = Migrator {
        migrations: Cow::Owned(
            full.migrations
                .iter()
                .filter(|m| m.version <= LAST_OLD_MIGRATION)
                .cloned()
                .collect(),
        ),
        ..Migrator::DEFAULT
    };
    old.run(&raw).await.expect("migrate to 019");

    let issued_at = Utc.with_ymd_and_hms(2026, 10, 1, 5, 30, 0).unwrap();
    let mut root = kavach_ports_testkit::mandate_store::sample("old-root", None, 0);
    root.mandate.tenant_id = "compat".into();
    root.mandate.nbf = issued_at;
    root.mandate.exp = issued_at + Duration::days(1);
    root.mandate.source.record_ref = "compat-loan".into();
    root.mandate.source.event_id = "evt-old".into();
    insert_previous_version_rows(&raw, &root, issued_at).await;

    // Expand: the new migrations on top, through the real pool.
    let pool = StoragePool::connect(&url, &kavach_storage::DatabaseTls::development())
        .await
        .expect("migrate to the current version");
    let store = pool.mandate_store();

    // The old revocation reads back with the new fields unknown.
    let old_revocation = store
        .revocation_for_event("compat", "lms", "pay-old")
        .await
        .expect("read")
        .expect("kept");
    assert_eq!(old_revocation.clock_synced, None);

    // The old statements still work against the new schema (what a
    // not-yet-upgraded replica does while the upgrade rolls).
    let mut second = kavach_ports_testkit::mandate_store::sample("old-root-2", None, 0);
    second.mandate.tenant_id = "compat".into();
    second.mandate.source.record_ref = "compat-loan".into();
    second.mandate.source.event_id = "evt-old-2".into();
    store
        .insert(second)
        .await
        .expect("plain insert still works");

    // The new code scopes an old root (no source time) by `nbf`, as before.
    let applied = store
        .apply_revocation(RevocationApply {
            tenant_id: "compat".into(),
            system: "lms".into(),
            event_id: "pay-new".into(),
            event_digest: format!("sha256-jcs-v1:{}", "cd".repeat(32)),
            legacy_digest: "ef".repeat(32),
            event_type: "loan.paid".into(),
            record_ref: "compat-loan".into(),
            occurred_at: issued_at + Duration::seconds(60),
            reason: kavach_domain::mandate::RevocationReason::Payment,
            revoked_at: issued_at + Duration::seconds(90),
            clock_synced: true,
            reach_until: issued_at + Duration::seconds(90),
        })
        .await
        .expect("applied");
    assert!(
        applied.stored.revoked.contains(&"old-root".to_string()),
        "an old root is reached through nbf: {:?}",
        applied.stored.revoked
    );
}

/// Migration 030 adds `idempotency_key` to `agent_decisions`, which is
/// append-only (`kavach_append_only()`, migration 010). A database that
/// already holds agent evidence must still upgrade, and a request recorded
/// before the upgrade keeps its one-record-per-request key.
#[tokio::test(flavor = "multi_thread")]
async fn agent_evidence_recorded_before_migration_030_survives_the_upgrade() {
    let Some(url) = isolated_database_url().await else {
        return;
    };
    let raw = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("connect");
    let full = Migrator::new(Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/migrations"
    )))
    .await
    .expect("migrations");
    let old = Migrator {
        migrations: Cow::Owned(
            full.migrations
                .iter()
                .filter(|m| m.version < 30)
                .cloned()
                .collect(),
        ),
        ..Migrator::DEFAULT
    };
    old.run(&raw).await.expect("migrate to 029");

    // An agent decision as the previous version wrote it (no idempotency_key).
    sqlx::query(
        "INSERT INTO agent_decisions (tenant_id, partition_id, seq, record_id, prev_hash, hash, \
            sig, key_id, payload, agent_id, request_id, binding, credential_id, returned_decision) \
        VALUES ('compat', 0, 1, 'rec-old', 'p', 'h', 's', 'k', '{\"kind\":\"agent_decision\"}', \
            'agent-old', 'req-old', '{}', NULL, 'BLOCK')",
    )
    .execute(&raw)
    .await
    .expect("old agent decision insert");

    // Expand: the new migrations on top, through the real pool.
    let pool = StoragePool::connect(&url, &kavach_storage::DatabaseTls::development())
        .await
        .expect("an upgrade over existing agent evidence must succeed");

    let insert = |seq: i64, record_id: &'static str, request_id: &'static str, key: &'static str| {
        sqlx::query(
            "INSERT INTO agent_decisions (tenant_id, partition_id, seq, record_id, prev_hash, \
                hash, sig, key_id, payload, agent_id, request_id, idempotency_key, binding, \
                credential_id, returned_decision) \
            VALUES ('compat', 0, $1, $2, 'p', 'h', 's', 'k', '{\"kind\":\"agent_decision\"}', \
                'agent-old', $3, $4, '{}', NULL, 'BLOCK')",
        )
        .bind(seq)
        .bind(record_id)
        .bind(request_id)
        .bind(key)
    };

    // A new record with a fresh key is accepted, so the refusal below is the key's.
    insert(2, "rec-fresh", "req-fresh", "req-fresh")
        .execute(&pool.pool)
        .await
        .expect("a new agent decision with a fresh key");

    // The old record keeps its one-per-request uniqueness under the new key.
    let duplicate = insert(3, "rec-new", "req-other", "req-old")
        .execute(&pool.pool)
        .await
        .expect_err("a new record must not reuse the request key of a record from before 030");
    assert_eq!(
        duplicate
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::constraint),
        Some("agent_decisions_one_per_idempotency_key"),
        "{duplicate}"
    );
}

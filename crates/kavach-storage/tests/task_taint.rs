use chrono::{DateTime, Utc};
use kavach_ports::{TaskTaintSource, TaskTaintStore};
use kavach_storage::testing::isolated_database_urls;
use kavach_storage::{DatabaseTls, MemoryTaskTaintStore, StoragePool};

#[tokio::test]
async fn memory_task_taint_is_monotonic_and_tenant_scoped() {
    let store = MemoryTaskTaintStore::default();
    let now = Utc::now();
    let first = store
        .mark_tainted("tenant-a", "mandate-1", TaskTaintSource::UserContent, now)
        .await
        .unwrap();
    let replay = store
        .mark_tainted(
            "tenant-a",
            "mandate-1",
            TaskTaintSource::GovernedModelOutput,
            now + chrono::Duration::seconds(1),
        )
        .await
        .unwrap();

    assert_eq!(first, replay);
    assert_eq!(first.first_tainted_at, now);
    assert_eq!(first.source, TaskTaintSource::UserContent);
    assert!(store
        .get_taint("tenant-a", "mandate-1")
        .await
        .unwrap()
        .is_some());
    assert!(store
        .get_taint("tenant-b", "mandate-1")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn postgres_task_taint_is_monotonic_as_least_privilege_runtime_role() {
    let Some((owner, runtime)) = isolated_database_urls().await else {
        return;
    };
    let pool = StoragePool::connect_with_roles(&runtime, Some(&owner), &DatabaseTls::development())
        .await
        .expect("connect with migrated isolated schema");
    let store = pool.task_taint_store();
    let now: DateTime<Utc> = Utc::now();
    let first = store
        .mark_tainted(
            "taint-test-a",
            "mandate-1",
            TaskTaintSource::UserContent,
            now,
        )
        .await
        .expect("runtime can mark taint");
    let replay = store
        .mark_tainted(
            "taint-test-a",
            "mandate-1",
            TaskTaintSource::GovernedModelOutput,
            now + chrono::Duration::seconds(1),
        )
        .await
        .expect("runtime replay is idempotent");
    assert_eq!(first, replay);
    assert_eq!(
        store
            .get_taint("taint-test-a", "mandate-1")
            .await
            .expect("runtime can read taint"),
        Some(first)
    );
    assert!(store
        .get_taint("taint-test-b", "mandate-1")
        .await
        .expect("tenant-scoped miss")
        .is_none());

    let can_mutate: bool = sqlx::query_scalar(
        "SELECT has_table_privilege(current_user, 'agent_task_taint', 'UPDATE') \
         OR has_table_privilege(current_user, 'agent_task_taint', 'DELETE')",
    )
    .fetch_one(&pool.pool)
    .await
    .expect("inspect least-privilege grants");
    assert!(!can_mutate, "runtime role must not clear or replace taint");
}

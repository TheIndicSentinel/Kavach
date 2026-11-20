use kavach_storage::testing::{
    credit_auditor_url, isolated_database_urls, CREDIT_AUDITOR_TEST_PASSWORD,
};
use kavach_storage::{DatabaseTls, StoragePool};
use sqlx::postgres::PgPoolOptions;

#[tokio::test]
async fn credit_auditor_is_read_only_and_separate_from_agent_auditor() {
    let Some((owner_url, _runtime_url)) = isolated_database_urls().await else {
        return;
    };
    let _storage = StoragePool::connect(&owner_url, &DatabaseTls::development())
        .await
        .expect("migrate isolated schema");
    let credit_url = credit_auditor_url(&owner_url);
    assert!(credit_url.contains(CREDIT_AUDITOR_TEST_PASSWORD));
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&credit_url)
        .await
        .expect("connect as credit auditor");

    let allowed: (bool, bool, bool, bool, bool) = sqlx::query_as(
        "SELECT has_table_privilege(current_user, 'decision_events', 'SELECT'), \
                has_table_privilege(current_user, 'evidence_chains', 'SELECT'), \
                has_table_privilege(current_user, 'decision_events', 'INSERT'), \
                has_table_privilege(current_user, 'evidence_checkpoints', 'SELECT'), \
                has_table_privilege(current_user, 'agent_decisions', 'SELECT')",
    )
    .fetch_one(&pool)
    .await
    .expect("check role privileges");
    assert_eq!(allowed, (true, true, false, true, false));
    sqlx::query("SELECT count(*) FROM decision_events")
        .fetch_one(&pool)
        .await
        .expect("credit auditor can read credit events");
    sqlx::query("SELECT count(*) FROM evidence_checkpoints")
        .fetch_one(&pool)
        .await
        .expect("credit auditor can read checkpoint rows");
    assert!(sqlx::query("SELECT count(*) FROM agent_decisions")
        .fetch_one(&pool)
        .await
        .is_err());
    pool.close().await;
}

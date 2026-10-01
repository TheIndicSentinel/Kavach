//! Postgres mandate store and replay guard against the shared contracts
//! (ADR-011). `KAVACH_TEST_DATABASE_URL`; CI fails if it is missing.

use std::sync::Arc;

use chrono::{Duration, Utc};
use kavach_ports::{ErrorClass, MandateStore, ReplayGuard};
use kavach_storage::testing::isolated_database_url;
use kavach_storage::StoragePool;

async fn pool() -> Option<StoragePool> {
    let url = isolated_database_url().await?;
    Some(StoragePool::connect(&url).await.expect("connect + migrate"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_mandate_store_meets_the_contract() {
    let Some(pool) = pool().await else { return };
    kavach_ports_testkit::mandate_store::conformance(Arc::new(pool.mandate_store())).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn postgres_replay_guard_meets_the_contract() {
    let Some(pool) = pool().await else { return };
    kavach_ports_testkit::conformance::replay_guard(&pool.replay_guard()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replay_guard_is_shared_and_race_free() {
    let Some(pool) = pool().await else { return };
    // Two replicas (two guards on one database) racing on one event id:
    // exactly one wins.
    let (a, b) = (pool.replay_guard(), pool.replay_guard());
    let now = Utc::now();
    let exp = now + Duration::minutes(5);
    let (ra, rb) = tokio::join!(
        a.check_and_record("t", "sor:lms:evt-1", now, exp),
        b.check_and_record("t", "sor:lms:evt-1", now, exp),
    );
    assert_eq!([ra.is_ok(), rb.is_ok()].iter().filter(|ok| **ok).count(), 1);
    let loser = ra.err().or(rb.err()).unwrap();
    assert_eq!(loser.class, ErrorClass::Rejected);
    assert_eq!(
        a.purge_expired(exp + Duration::seconds(1)).await.unwrap(),
        1
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn one_root_mandate_per_system_of_record_event() {
    let Some(pool) = pool().await else { return };
    let store = pool.mandate_store();
    let first = kavach_ports_testkit::mandate_store::sample("m-1", None, 0);
    store.insert(first.clone()).await.expect("first");
    // Another mandate id, same source event: refused by the database.
    let mut again = kavach_ports_testkit::mandate_store::sample("m-2", None, 0);
    again.mandate.source = first.mandate.source.clone();
    let err = store.insert(again).await.unwrap_err();
    assert_eq!(err.class, ErrorClass::Rejected);
    assert!(err.message.contains("already issued"), "{}", err.message);
    // The stored mandate round-trips exactly (JSONB storage).
    let stored = store.get("conformance", "m-1").await.unwrap().unwrap();
    assert_eq!(stored, first);
}

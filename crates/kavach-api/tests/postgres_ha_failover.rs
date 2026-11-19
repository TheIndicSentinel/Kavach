//! Active/passive process-failure behavior against a real Postgres lease.

use kavach_api::{ha_lease, DatabaseTls};
use kavach_storage::{connect_runtime, testing::isolated_database_urls};
use tokio::sync::watch;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn standby_promotes_after_active_stops_and_old_pool_is_fenced() {
    let Some((owner_url, runtime_url)) = isolated_database_urls().await else {
        return;
    };
    let tls = DatabaseTls::development();
    let _owner = kavach_storage::StoragePool::connect(&owner_url, &tls)
        .await
        .expect("migrate isolated schema");
    let former_active_pool = connect_runtime(&runtime_url, &tls)
        .await
        .expect("connect former active");
    let standby_pool = connect_runtime(&runtime_url, &tls)
        .await
        .expect("connect standby");

    let (_active_stop_tx, active_stop_rx) = watch::channel(false);
    let (active_fence, active_task) = ha_lease::start(
        former_active_pool.active_lease_store(),
        "tenant-ha-test".into(),
        active_stop_rx,
    )
    .await
    .expect("start active lease lifecycle");
    assert_eq!(active_fence.status(), "active");

    let (standby_stop_tx, standby_stop_rx) = watch::channel(false);
    let (standby_fence, standby_task) = ha_lease::start(
        standby_pool.active_lease_store(),
        "tenant-ha-test".into(),
        standby_stop_rx,
    )
    .await
    .expect("start standby lease lifecycle");
    assert_eq!(standby_fence.status(), "standby");

    // Simulate abrupt process loss: its lease expires naturally, and no
    // shutdown hook clears or releases the lease on its behalf.
    active_task.abort();
    let promoted = tokio::time::timeout(std::time::Duration::from_secs(15), async {
        while standby_fence.status() != "active" {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await;
    assert!(
        promoted.is_ok(),
        "standby did not promote after lease expiry"
    );

    let stale_write = sqlx::query(
        "INSERT INTO replay_guard (tenant_id, key, expires_at) \
         VALUES ('tenant-ha-test', 'former-active-write', clock_timestamp() + interval '1 minute')",
    )
    .execute(&former_active_pool.pool)
    .await
    .expect_err("the former active pool must remain fenced after promotion");
    assert_eq!(
        stale_write
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .as_deref(),
        Some("55000")
    );

    let _ = standby_stop_tx.send(true);
    let _ = standby_task.await;
}

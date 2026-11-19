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
    let owner = kavach_storage::StoragePool::connect(&owner_url, &tls)
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

    let (_standby_stop_tx, standby_stop_rx) = watch::channel(false);
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
    let first_promoted_epoch: i64 =
        sqlx::query_scalar("SELECT epoch FROM active_api_leases WHERE tenant_id = $1")
            .bind("tenant-ha-test")
            .fetch_one(&owner.pool)
            .await
            .expect("read first promoted epoch");

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

    // A restarted API rejoins as standby while the promoted process owns the
    // lease. If that active then fails, the rejoined process can take over.
    let rejoined_pool = connect_runtime(&runtime_url, &tls)
        .await
        .expect("connect rejoined API");
    let (rejoined_stop_tx, rejoined_stop_rx) = watch::channel(false);
    let (rejoined_fence, rejoined_task) = ha_lease::start(
        rejoined_pool.active_lease_store(),
        "tenant-ha-test".into(),
        rejoined_stop_rx,
    )
    .await
    .expect("start rejoined API");
    assert_eq!(rejoined_fence.status(), "standby");

    standby_task.abort();
    let recovered = tokio::time::timeout(std::time::Duration::from_secs(15), async {
        while rejoined_fence.status() != "active" {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await;
    assert!(
        recovered.is_ok(),
        "rejoined API did not take over after active process loss"
    );

    let rejoined_write = sqlx::query(
        "INSERT INTO replay_guard (tenant_id, key, expires_at) \
         VALUES ('tenant-ha-test', 'rejoined-active-write', clock_timestamp() + interval '1 minute')",
    )
    .execute(&rejoined_pool.pool)
    .await
    .expect("rejoined API may write after promotion");
    assert_eq!(rejoined_write.rows_affected(), 1);
    let current_epoch: i64 =
        sqlx::query_scalar("SELECT epoch FROM active_api_leases WHERE tenant_id = $1")
            .bind("tenant-ha-test")
            .fetch_one(&owner.pool)
            .await
            .expect("read recovered epoch");
    assert_eq!(current_epoch, first_promoted_epoch + 1);

    let _ = active_task.await;
    let _ = rejoined_stop_tx.send(true);
    let _ = rejoined_task.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn active_self_fences_when_its_database_pool_is_lost() {
    let Some((owner_url, runtime_url)) = isolated_database_urls().await else {
        return;
    };
    let tls = DatabaseTls::development();
    let _owner = kavach_storage::StoragePool::connect(&owner_url, &tls)
        .await
        .expect("migrate isolated schema");
    let active_pool = connect_runtime(&runtime_url, &tls)
        .await
        .expect("connect active");
    let standby_pool = connect_runtime(&runtime_url, &tls)
        .await
        .expect("connect standby");

    let (_active_stop_tx, active_stop_rx) = watch::channel(false);
    let (active_fence, active_task) = ha_lease::start(
        active_pool.active_lease_store(),
        "tenant-ha-db-loss-test".into(),
        active_stop_rx,
    )
    .await
    .expect("start active lease lifecycle");
    assert_eq!(active_fence.status(), "active");

    let (standby_stop_tx, standby_stop_rx) = watch::channel(false);
    let (standby_fence, standby_task) = ha_lease::start(
        standby_pool.active_lease_store(),
        "tenant-ha-db-loss-test".into(),
        standby_stop_rx,
    )
    .await
    .expect("start standby lease lifecycle");
    assert_eq!(standby_fence.status(), "standby");

    // Model an asymmetric database connectivity failure: the active API's
    // pool is lost while the standby can still reach the shared Postgres.
    active_pool.pool.close().await;
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while active_fence.status() != "fenced" {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("active must self-fence after renewal fails");
    assert_eq!(
        standby_fence.status(),
        "standby",
        "standby must wait for database lease expiry"
    );

    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        while standby_fence.status() != "active" {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("reachable standby should promote after the old lease expires");

    let _ = active_task.await;
    let _ = standby_stop_tx.send(true);
    let _ = standby_task.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn neither_process_serves_or_promotes_when_both_database_pools_are_lost() {
    let Some((owner_url, runtime_url)) = isolated_database_urls().await else {
        return;
    };
    let tls = DatabaseTls::development();
    let owner = kavach_storage::StoragePool::connect(&owner_url, &tls)
        .await
        .expect("migrate isolated schema");
    let active_pool = connect_runtime(&runtime_url, &tls)
        .await
        .expect("connect active");
    let standby_pool = connect_runtime(&runtime_url, &tls)
        .await
        .expect("connect standby");

    let (_active_stop_tx, active_stop_rx) = watch::channel(false);
    let (active_fence, active_task) = ha_lease::start(
        active_pool.active_lease_store(),
        "tenant-ha-total-db-path-test".into(),
        active_stop_rx,
    )
    .await
    .expect("start active lease lifecycle");
    assert_eq!(active_fence.status(), "active");

    let (standby_stop_tx, standby_stop_rx) = watch::channel(false);
    let (standby_fence, standby_task) = ha_lease::start(
        standby_pool.active_lease_store(),
        "tenant-ha-total-db-path-test".into(),
        standby_stop_rx,
    )
    .await
    .expect("start standby lease lifecycle");
    assert_eq!(standby_fence.status(), "standby");

    let (holder, epoch): (String, i64) =
        sqlx::query_as("SELECT holder_id, epoch FROM active_api_leases WHERE tenant_id = $1")
            .bind("tenant-ha-total-db-path-test")
            .fetch_one(&owner.pool)
            .await
            .expect("read initial lease");

    // Both API instances lose their database path. Keep the owner connection
    // only to observe that the standby did not create a new lease epoch.
    active_pool.pool.close().await;
    standby_pool.pool.close().await;
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while active_fence.status() != "fenced" {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("active must self-fence after lease renewal fails");

    // More than the ten-second lease TTL elapses without either API being
    // able to reach Postgres. The standby must fail closed, not self-promote.
    tokio::time::sleep(std::time::Duration::from_secs(11)).await;
    assert_eq!(active_fence.status(), "fenced");
    assert_eq!(standby_fence.status(), "standby");
    let (current_holder, current_epoch): (String, i64) =
        sqlx::query_as("SELECT holder_id, epoch FROM active_api_leases WHERE tenant_id = $1")
            .bind("tenant-ha-total-db-path-test")
            .fetch_one(&owner.pool)
            .await
            .expect("lease remains inspectable by owner");
    assert_eq!(current_holder, holder);
    assert_eq!(current_epoch, epoch);

    let _ = active_task.await;
    let _ = standby_stop_tx.send(true);
    let _ = standby_task.await;
}

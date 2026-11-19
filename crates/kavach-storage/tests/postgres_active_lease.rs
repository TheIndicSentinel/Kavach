//! Shared Postgres active/passive lease primitives.

use chrono::Duration;
use kavach_storage::{connect_runtime, testing::isolated_database_urls, DatabaseTls, StoragePool};
use tokio::time::{sleep, Duration as TokioDuration};

async fn pools() -> Option<(StoragePool, StoragePool)> {
    let (owner_url, runtime_url) = isolated_database_urls().await?;
    let tls = DatabaseTls::development();
    let owner = StoragePool::connect(&owner_url, &tls)
        .await
        .expect("migrate and connect as owner");
    let runtime = connect_runtime(&runtime_url, &tls)
        .await
        .expect("connect as runtime");
    Some((owner, runtime))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lease_claim_renewal_and_takeover_are_atomic() {
    let Some((_owner, runtime)) = pools().await else {
        return;
    };
    let first = runtime.active_lease_store();
    let second = runtime.active_lease_store();
    let token_a = [0x11; 32];
    let token_b = [0x22; 32];

    let (a, b) = tokio::join!(
        first.claim("tenant", "api-a", &token_a, Duration::seconds(2)),
        second.claim("tenant", "api-b", &token_b, Duration::seconds(2)),
    );
    let (winner, winner_id, winner_token, loser) = match (a.unwrap(), b.unwrap()) {
        (Some(lease), None) => (first, "api-a", token_a, lease),
        (None, Some(lease)) => (second, "api-b", token_b, lease),
        other => panic!("exactly one claimant must win: {other:?}"),
    };
    assert_eq!(loser.epoch, 1);
    let denied_token = if winner_id == "api-a" {
        &token_b
    } else {
        &token_a
    };
    assert!(!winner
        .renew(
            "tenant",
            winner_id,
            loser.epoch,
            denied_token,
            Duration::seconds(2)
        )
        .await
        .unwrap());
    assert!(winner
        .renew(
            "tenant",
            winner_id,
            loser.epoch,
            &winner_token,
            Duration::seconds(2)
        )
        .await
        .unwrap());

    let unconfigured: Option<String> =
        sqlx::query_scalar("SELECT current_setting('kavach.fencing_enabled', true)")
            .fetch_one(&runtime.pool)
            .await
            .unwrap();
    assert_eq!(unconfigured, None);
    sqlx::query(
        "INSERT INTO replay_guard (tenant_id, key, expires_at) \
         VALUES ('tenant', 'single-instance-write', clock_timestamp() + interval '1 minute')",
    )
    .execute(&runtime.pool)
    .await
    .expect("unconfigured single-instance writes remain unchanged");

    winner.enable_write_fencing().await;
    winner
        .bind_write_identity("tenant", winner_id, loser.epoch, &winner_token)
        .await;
    let (a, b, c) = tokio::join!(
        write_settings(&runtime.pool),
        write_settings(&runtime.pool),
        write_settings(&runtime.pool)
    );
    for settings in [a, b, c] {
        assert_eq!(settings.0, "on");
        assert_eq!(settings.1, "tenant");
        assert_eq!(settings.2, winner_id);
        assert_eq!(settings.3, loser.epoch.to_string());
        assert_eq!(settings.4, hex::encode(winner_token));
    }
    winner.clear_write_identity().await;
    let cleared = write_settings(&runtime.pool).await;
    assert_eq!(cleared.0, "on");
    assert!(cleared.1.is_empty());
    assert!(cleared.2.is_empty());
    assert!(cleared.3.is_empty());
    assert!(cleared.4.is_empty());
    let blank_identity_write = sqlx::query(
        "INSERT INTO replay_guard (tenant_id, key, expires_at) \
         VALUES ('tenant', 'blank-identity-write', clock_timestamp() + interval '1 minute')",
    )
    .execute(&runtime.pool)
    .await
    .expect_err("standby/fenced identity must fail closed");
    assert_eq!(
        blank_identity_write
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .as_deref(),
        Some("55000")
    );

    // Runtime credentials can execute the narrow lease API but cannot inspect
    // or edit its underlying owner-controlled row.
    let access = sqlx::query_scalar::<_, bool>(
        "SELECT has_table_privilege(current_user, 'active_api_leases', 'SELECT')",
    )
    .fetch_one(&runtime.pool)
    .await
    .unwrap();
    assert!(!access);
}

async fn write_settings(pool: &sqlx::PgPool) -> (String, String, String, String, String) {
    sqlx::query_as(
        "SELECT current_setting('kavach.fencing_enabled', true), \
                current_setting('kavach.tenant_id', true), \
                current_setting('kavach.holder_id', true), \
                current_setting('kavach.lease_epoch', true), \
                current_setting('kavach.token_hash', true)",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn expired_lease_takeover_advances_epoch_and_old_holder_cannot_renew() {
    let Some((_owner, runtime)) = pools().await else {
        return;
    };
    let store = runtime.active_lease_store();
    let old_token = [0x31; 32];
    let new_token = [0x42; 32];
    let old = store
        .claim("tenant", "old-api", &old_token, Duration::milliseconds(40))
        .await
        .unwrap()
        .expect("initial owner");
    sleep(TokioDuration::from_millis(80)).await;
    let next = store
        .claim("tenant", "new-api", &new_token, Duration::seconds(2))
        .await
        .unwrap()
        .expect("expired lease can be taken over");
    assert_eq!(next.epoch, old.epoch + 1);
    assert!(!store
        .renew(
            "tenant",
            "old-api",
            old.epoch,
            &old_token,
            Duration::seconds(2)
        )
        .await
        .unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn promotion_waits_for_guarded_writes_and_rejects_the_old_holder() {
    let Some((owner, runtime)) = pools().await else {
        return;
    };
    let lease_store = runtime.active_lease_store();
    let old_token = [0x51; 32];
    let new_token = [0x62; 32];
    lease_store.enable_write_fencing().await;
    let old_lease = lease_store
        .claim("tenant", "old-holder", &old_token, Duration::seconds(2))
        .await
        .unwrap()
        .expect("initial owner");
    lease_store
        .bind_write_identity("tenant", "old-holder", old_lease.epoch, &old_token)
        .await;

    let mut transaction = runtime.pool.begin().await.unwrap();
    sqlx::query(
        "INSERT INTO replay_guard (tenant_id, key, expires_at) \
         VALUES ('tenant', 'held-write', clock_timestamp() + interval '1 minute')",
    )
    .execute(&mut *transaction)
    .await
    .expect("current active may write");
    tokio::time::sleep(std::time::Duration::from_millis(2100)).await;

    let promotion_store = lease_store.clone();
    let mut promotion = tokio::spawn(async move {
        promotion_store
            .claim("tenant", "new-holder", &new_token, Duration::seconds(5))
            .await
    });
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), &mut promotion)
            .await
            .is_err()
    );

    transaction.commit().await.unwrap();
    let promoted = promotion
        .await
        .expect("promotion task")
        .unwrap()
        .expect("expired lease takeover");
    assert_eq!(promoted.epoch, old_lease.epoch + 1);

    let stale_write = sqlx::query(
        "INSERT INTO replay_guard (tenant_id, key, expires_at) \
         VALUES ('tenant', 'stale-write', clock_timestamp() + interval '1 minute')",
    )
    .execute(&runtime.pool)
    .await
    .expect_err("former holder must be fenced by the trigger");
    assert_eq!(
        stale_write
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .as_deref(),
        Some("55000")
    );

    let owner_epoch: i64 =
        sqlx::query_scalar("SELECT epoch FROM active_api_leases WHERE tenant_id = 'tenant'")
            .fetch_one(&owner.pool)
            .await
            .unwrap();
    assert_eq!(owner_epoch, promoted.epoch);
}

#[tokio::test(flavor = "multi_thread")]
async fn every_runtime_writable_table_has_a_complete_fencing_trigger() {
    let Some((owner, _runtime)) = pools().await else {
        return;
    };
    sqlx::query("SELECT kavach_assert_active_write_guards()")
        .execute(&owner.pool)
        .await
        .expect("migration guard inventory assertion");
}

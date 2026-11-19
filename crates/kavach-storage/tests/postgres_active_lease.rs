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

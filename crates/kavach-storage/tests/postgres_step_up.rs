//! Durable, one-use state for reviewer step-up ceremonies.

use chrono::{Duration, Utc};
use kavach_ports::{StepUpChallengeState, StepUpChallengeStore};
use kavach_storage::testing::isolated_database_urls;
use kavach_storage::{DatabaseTls, StoragePool};

fn state(id: &str, digest: char, issued_at: chrono::DateTime<Utc>) -> StepUpChallengeState {
    StepUpChallengeState {
        challenge_id: id.into(),
        state_hash: format!("sha256:{}", digest.to_string().repeat(64)),
        nonce_hash: format!("sha256:{}", "b".repeat(64)),
        tenant_id: "tenant-1".into(),
        principal_key: "oidc:https://idp.example#reviewer-1".into(),
        action_hash: format!("sha256-action-v1:{}", "a".repeat(64)),
        issued_at,
        expires_at: issued_at + Duration::minutes(2),
    }
}

async fn pool() -> Option<StoragePool> {
    let (owner_url, runtime_url) = isolated_database_urls().await?;
    Some(
        StoragePool::connect_with_roles(
            &runtime_url,
            Some(&owner_url),
            &DatabaseTls::development(),
        )
        .await
        .expect("migrate as owner and connect as runtime"),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn runtime_role_reads_and_consumes_step_up_challenge_once() {
    let Some(pool) = pool().await else { return };
    let store = pool.step_up_challenge_store();
    let now = Utc::now();
    let state = state("challenge-pg-1", 'c', now);
    let state_hash = state.state_hash.clone();
    store.insert(state.clone()).await.unwrap();

    assert_eq!(
        store.get_live(&state_hash, now).await.unwrap(),
        Some(state.clone())
    );
    assert!(store
        .get_live(
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            now
        )
        .await
        .unwrap()
        .is_none());
    assert_eq!(store.consume(&state_hash, now).await.unwrap(), Some(state));
    assert!(store.consume(&state_hash, now).await.unwrap().is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_runtime_consumers_cannot_replay_step_up_challenge() {
    let Some(pool) = pool().await else { return };
    let store = pool.step_up_challenge_store();
    let now = Utc::now();
    let state = state("challenge-pg-race", 'd', now);
    let state_hash = state.state_hash.clone();
    store.insert(state).await.unwrap();

    let (left, right) = tokio::join!(
        store.consume(&state_hash, now),
        store.consume(&state_hash, now),
    );
    assert_ne!(left.unwrap().is_some(), right.unwrap().is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn expired_step_up_state_is_purged_and_live_state_is_protected() {
    let Some(pool) = pool().await else { return };
    let store = pool.step_up_challenge_store();
    let now = Utc::now();
    let expired = state("challenge-pg-expired", 'e', now - Duration::hours(1));
    let live = state("challenge-pg-live", 'f', now);
    let expired_hash = expired.state_hash.clone();
    let live_hash = live.state_hash.clone();
    store.insert(expired).await.unwrap();
    store.insert(live.clone()).await.unwrap();

    assert!(store.get_live(&expired_hash, now).await.unwrap().is_none());
    assert_eq!(store.purge_expired(now).await.unwrap(), 1);
    assert!(store.get_live(&expired_hash, now).await.unwrap().is_none());
    assert_eq!(store.get_live(&live_hash, now).await.unwrap(), Some(live));
}

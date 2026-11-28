//! Periodic deletion of expired D17 encrypted review snapshots.

use std::time::Duration;

use chrono::Utc;
use kavach_ports::ReviewSnapshotStore;

use crate::state::ReviewSnapshotBackend;

const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

/// Runs an expiry-only cleanup at startup and once a minute until shutdown.
pub fn start(
    store: ReviewSnapshotBackend,
    stop: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    start_with_interval(store, stop, CLEANUP_INTERVAL)
}

fn start_with_interval(
    store: ReviewSnapshotBackend,
    mut stop: tokio::sync::watch::Receiver<bool>,
    cadence: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(cadence);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = interval.tick() => match store.purge_expired(Utc::now()).await {
                    Ok(0) => {}
                    Ok(deleted) => tracing::info!(deleted, "expired D17 review snapshots purged"),
                    Err(error) => tracing::error!(%error, "D17 review snapshot cleanup failed"),
                },
                result = stop.changed() => {
                    if result.is_err() || *stop.borrow() {
                        return;
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cleanup_purges_expired_rows_and_stops_with_server() {
        use chrono::Duration as ChronoDuration;
        use kavach_ports::EncryptedReviewSnapshot;

        let memory = std::sync::Arc::new(kavach_storage::MemoryReviewSnapshotStore::default());
        let backend = ReviewSnapshotBackend::Memory(memory.clone());
        let now = Utc::now();
        let expired = EncryptedReviewSnapshot {
            version: 1,
            key_id: "review-v1".into(),
            tenant_id: "tenant-1".into(),
            record_id: "expired-record".into(),
            action_hash: format!("sha256-action-v1:{}", "a".repeat(64)),
            nonce: [7; 12],
            ciphertext: vec![9; 32],
            expires_at: now - ChronoDuration::seconds(1),
        };
        memory
            .insert(expired.clone(), now - ChronoDuration::seconds(2))
            .await
            .expect("insert expired snapshot");
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let task = start_with_interval(backend, stop_rx, Duration::from_millis(1));
        let replacement = EncryptedReviewSnapshot {
            expires_at: now + ChronoDuration::minutes(1),
            ..expired
        };
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if memory.insert(replacement.clone(), Utc::now()).await.is_ok() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("scheduled cleanup removed the expired row");
        stop_tx.send(true).expect("signal shutdown");
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("cleanup task stopped")
            .expect("cleanup task joined");
    }
}

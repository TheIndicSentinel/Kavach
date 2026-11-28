//! In-memory D17 encrypted review-snapshot adapter.

use std::{collections::HashMap, future::Future, sync::Mutex};

use chrono::{DateTime, Utc};
use kavach_ports::{EncryptedReviewSnapshot, PortError, ReviewSnapshotStore};

#[derive(Default)]
pub struct MemoryReviewSnapshotStore {
    snapshots: Mutex<HashMap<(String, String), EncryptedReviewSnapshot>>,
}

impl ReviewSnapshotStore for MemoryReviewSnapshotStore {
    fn insert(
        &self,
        snapshot: EncryptedReviewSnapshot,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<(), PortError>> + Send {
        std::future::ready((|| {
            snapshot.validate(now)?;
            let key = (snapshot.tenant_id.clone(), snapshot.record_id.clone());
            let mut entries = self.snapshots.lock().map_err(|_| {
                PortError::unavailable("review snapshot storage lock is unavailable")
            })?;
            if entries.contains_key(&key) {
                return Err(PortError::rejected("review snapshot already exists"));
            }
            entries.insert(key, snapshot);
            Ok(())
        })())
    }

    fn get_live(
        &self,
        tenant_id: &str,
        record_id: &str,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<Option<EncryptedReviewSnapshot>, PortError>> + Send {
        std::future::ready((|| {
            let entries = self.snapshots.lock().map_err(|_| {
                PortError::unavailable("review snapshot storage lock is unavailable")
            })?;
            Ok(entries
                .get(&(tenant_id.to_owned(), record_id.to_owned()))
                .filter(|snapshot| snapshot.expires_at > now)
                .cloned())
        })())
    }

    fn purge_expired(
        &self,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<u64, PortError>> + Send {
        std::future::ready((|| {
            let mut entries = self.snapshots.lock().map_err(|_| {
                PortError::unavailable("review snapshot storage lock is unavailable")
            })?;
            let before = entries.len();
            entries.retain(|_, snapshot| snapshot.expires_at > now);
            Ok((before - entries.len()) as u64)
        })())
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use kavach_ports::ReviewSnapshotStore;

    use super::*;

    fn sample(now: DateTime<Utc>) -> EncryptedReviewSnapshot {
        EncryptedReviewSnapshot {
            version: 1,
            key_id: "review-v1".into(),
            tenant_id: "tenant-1".into(),
            record_id: "record-1".into(),
            action_hash: format!("sha256-action-v1:{}", "a".repeat(64)),
            nonce: [7; 12],
            ciphertext: vec![9; 32],
            expires_at: now + Duration::minutes(30),
        }
    }

    #[tokio::test]
    async fn scopes_reads_rejects_duplicates_and_purges_expired_ciphertext() {
        let now = Utc::now();
        let store = MemoryReviewSnapshotStore::default();
        let snapshot = sample(now);
        store.insert(snapshot.clone(), now).await.expect("insert");
        assert!(store.insert(snapshot, now).await.is_err());
        assert!(store
            .get_live("tenant-2", "record-1", now)
            .await
            .unwrap()
            .is_none());
        assert!(store
            .get_live("tenant-1", "record-1", now)
            .await
            .unwrap()
            .is_some());
        assert!(store
            .get_live("tenant-1", "record-1", now + Duration::minutes(30))
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            store
                .purge_expired(now + Duration::minutes(30))
                .await
                .unwrap(),
            1
        );
    }
}

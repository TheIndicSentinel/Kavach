//! In-memory adapter for server-side step-up challenge state.
//!
//! Production runtime storage is PostgreSQL. Raw OIDC state and nonce values
//! are never stored; the rows contain only their SHA-256 digests.

use std::collections::HashMap;
use std::future::{ready, Future};
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use kavach_ports::{PortError, StepUpChallengeState, StepUpChallengeStore};

struct StoredChallenge {
    state: StepUpChallengeState,
    consumed: bool,
}

#[derive(Default)]
pub struct MemoryStepUpChallengeStore {
    rows: Mutex<HashMap<String, StoredChallenge>>,
}

impl StepUpChallengeStore for MemoryStepUpChallengeStore {
    fn insert(
        &self,
        state: StepUpChallengeState,
    ) -> impl Future<Output = Result<(), PortError>> + Send {
        let result = (|| {
            state.validate(state.issued_at)?;
            let mut rows = self
                .rows
                .lock()
                .map_err(|_| PortError::unavailable("step-up challenge lock poisoned"))?;
            if rows.contains_key(&state.state_hash)
                || rows
                    .values()
                    .any(|stored| stored.state.challenge_id == state.challenge_id)
            {
                return Err(PortError::rejected("step-up challenge already exists"));
            }
            rows.insert(
                state.state_hash.clone(),
                StoredChallenge {
                    state,
                    consumed: false,
                },
            );
            Ok(())
        })();
        ready(result)
    }

    fn get_live(
        &self,
        state_hash: &str,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<Option<StepUpChallengeState>, PortError>> + Send {
        let result = (|| {
            let rows = self
                .rows
                .lock()
                .map_err(|_| PortError::unavailable("step-up challenge lock poisoned"))?;
            let Some(stored) = rows.get(state_hash) else {
                return Ok(None);
            };
            if stored.consumed || stored.state.validate(now).is_err() {
                return Ok(None);
            }
            Ok(Some(stored.state.clone()))
        })();
        ready(result)
    }

    fn consume(
        &self,
        state_hash: &str,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<Option<StepUpChallengeState>, PortError>> + Send {
        let result = (|| {
            let mut rows = self
                .rows
                .lock()
                .map_err(|_| PortError::unavailable("step-up challenge lock poisoned"))?;
            let Some(stored) = rows.get_mut(state_hash) else {
                return Ok(None);
            };
            if stored.consumed || stored.state.validate(now).is_err() {
                return Ok(None);
            }
            stored.consumed = true;
            Ok(Some(stored.state.clone()))
        })();
        ready(result)
    }

    fn purge_expired(
        &self,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<u64, PortError>> + Send {
        let result = (|| {
            let mut rows = self
                .rows
                .lock()
                .map_err(|_| PortError::unavailable("step-up challenge lock poisoned"))?;
            let before = rows.len();
            rows.retain(|_, stored| stored.state.expires_at > now);
            Ok(u64::try_from(before - rows.len()).unwrap_or(u64::MAX))
        })();
        ready(result)
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone};
    use kavach_ports::StepUpChallengeStore;

    use super::*;

    fn state(id: &str, state_hash: &str, now: DateTime<Utc>) -> StepUpChallengeState {
        StepUpChallengeState {
            challenge_id: id.into(),
            state_hash: format!("sha256:{}", state_hash.repeat(64)),
            nonce_hash: format!("sha256:{}", "b".repeat(64)),
            tenant_id: "tenant-1".into(),
            principal_key: "oidc:https://idp.example#reviewer-1".into(),
            action_hash: format!("sha256-action-v1:{}", "a".repeat(64)),
            issued_at: now,
            expires_at: now + Duration::minutes(2),
        }
    }

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, 17, 12, 0, 0).unwrap()
    }

    #[tokio::test]
    async fn challenge_lookup_and_consumption_are_live_and_one_use() {
        let store = MemoryStepUpChallengeStore::default();
        let record = state("challenge-1", "c", now());
        let lookup = record.state_hash.clone();
        store.insert(record.clone()).await.unwrap();

        assert_eq!(
            store.get_live(&lookup, now()).await.unwrap(),
            Some(record.clone())
        );
        assert_eq!(store.consume(&lookup, now()).await.unwrap(), Some(record));
        assert!(store.get_live(&lookup, now()).await.unwrap().is_none());
        assert!(store.consume(&lookup, now()).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn expired_challenges_are_not_read_or_consumed_and_can_be_purged() {
        let store = MemoryStepUpChallengeStore::default();
        let record = state("challenge-expired", "d", now());
        let lookup = record.state_hash.clone();
        store.insert(record.clone()).await.unwrap();
        let expired_at = record.expires_at;

        assert!(store.get_live(&lookup, expired_at).await.unwrap().is_none());
        assert!(store.consume(&lookup, expired_at).await.unwrap().is_none());
        assert_eq!(store.purge_expired(expired_at).await.unwrap(), 1);
        assert_eq!(store.purge_expired(expired_at).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn challenge_state_requires_digest_fields_and_unique_identifiers() {
        let store = MemoryStepUpChallengeStore::default();
        let mut bad = state("challenge-bad", "e", now());
        bad.nonce_hash = "raw-nonce-must-not-be-stored".into();
        assert!(store.insert(bad).await.is_err());

        let record = state("challenge-unique", "f", now());
        store.insert(record.clone()).await.unwrap();
        assert!(store.insert(record).await.is_err());
    }
}

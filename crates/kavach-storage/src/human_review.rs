//! In-memory adapter for completed human-review approvals.
//!
//! This adapter is used by tests and local workflows; production runtime
//! storage is PostgreSQL.

use std::collections::HashMap;
use std::future::{ready, Future};
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use kavach_ports::{PortError, ReviewApprovalRecord, ReviewApprovalStore};

type ApprovalKey = (String, String);
type StoredApproval = (ReviewApprovalRecord, Option<DateTime<Utc>>);
type ApprovalRows = HashMap<ApprovalKey, StoredApproval>;

#[derive(Default)]
pub struct MemoryReviewApprovalStore {
    records: Mutex<ApprovalRows>,
}

impl ReviewApprovalStore for MemoryReviewApprovalStore {
    fn insert(
        &self,
        record: ReviewApprovalRecord,
    ) -> impl Future<Output = Result<(), PortError>> + Send {
        let result = (|| {
            record.validate()?;
            let key = (record.tenant_id.clone(), record.approval_id.clone());
            let mut records = self
                .records
                .lock()
                .map_err(|_| PortError::unavailable("review approval store lock poisoned"))?;
            if records.contains_key(&key) {
                return Err(PortError::rejected("review approval id already exists"));
            }
            if record.single_use_credential_id.as_ref().is_some_and(|id| {
                records
                    .values()
                    .any(|(stored, _)| stored.single_use_credential_id.as_ref() == Some(id))
            }) {
                return Err(PortError::rejected(
                    "single-use credential id already exists",
                ));
            }
            records.insert(key, (record, None));
            Ok(())
        })();
        ready(result)
    }

    fn consume(
        &self,
        tenant_id: &str,
        approval_id: &str,
        action_hash: &str,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<Option<ReviewApprovalRecord>, PortError>> + Send {
        let result = (|| {
            let mut records = self
                .records
                .lock()
                .map_err(|_| PortError::unavailable("review approval store lock poisoned"))?;
            let Some((record, consumed_at)) =
                records.get_mut(&(tenant_id.to_string(), approval_id.to_string()))
            else {
                return Ok(None);
            };
            if consumed_at.is_some()
                || record
                    .validate_scope_and_lifetime(tenant_id, action_hash, now)
                    .is_err()
            {
                return Ok(None);
            }
            *consumed_at = Some(now);
            Ok(Some(record.clone()))
        })();
        ready(result)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chrono::TimeZone;
    use kavach_ports::{ReviewApprovalStore, ReviewDecision};

    use super::*;

    fn record(id: &str, decision: ReviewDecision) -> ReviewApprovalRecord {
        ReviewApprovalRecord {
            tenant_id: "tenant-1".into(),
            approval_id: id.into(),
            action_hash: format!("sha256-action-v1:{}", "a".repeat(64)),
            rendered_action: "Propose a 35% waiver for borrower ref:B-9382".into(),
            approver: "oidc:https://idp.example#user-1".into(),
            step_up_ref: "webauthn:assertion-1".into(),
            decision,
            single_use_credential_id: (decision == ReviewDecision::Approve)
                .then(|| format!("credential-{id}")),
            expires: Utc.with_ymd_and_hms(2026, 11, 17, 12, 5, 0).unwrap(),
        }
    }

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, 17, 12, 0, 0).unwrap()
    }

    #[tokio::test]
    async fn consume_is_bound_to_tenant_action_and_expiry_then_succeeds_once() {
        let store = MemoryReviewApprovalStore::default();
        let approval = record("approval-1", ReviewDecision::Approve);
        let hash = approval.action_hash.clone();
        store.insert(approval.clone()).await.unwrap();

        assert!(store
            .consume("tenant-2", "approval-1", &hash, now())
            .await
            .unwrap()
            .is_none());
        assert!(store
            .consume("tenant-1", "approval-1", "sha256-action-v1:other", now())
            .await
            .unwrap()
            .is_none());
        assert!(store
            .consume("tenant-1", "approval-1", &hash, approval.expires)
            .await
            .unwrap()
            .is_none());

        assert_eq!(
            store
                .consume("tenant-1", "approval-1", &hash, now())
                .await
                .unwrap(),
            Some(approval)
        );
        assert!(store
            .consume("tenant-1", "approval-1", &hash, now())
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn rejected_records_never_consume_as_approvals() {
        let store = MemoryReviewApprovalStore::default();
        let rejected = record("approval-reject", ReviewDecision::Reject);
        store.insert(rejected.clone()).await.unwrap();
        assert!(store
            .consume("tenant-1", "approval-reject", &rejected.action_hash, now())
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn credential_ids_cannot_be_bound_to_two_approval_records() {
        let store = MemoryReviewApprovalStore::default();
        let first = record("approval-1", ReviewDecision::Approve);
        let mut second = record("approval-2", ReviewDecision::Approve);
        second.single_use_credential_id = first.single_use_credential_id.clone();
        store.insert(first).await.unwrap();
        assert!(store.insert(second).await.is_err());
    }

    #[tokio::test]
    async fn concurrent_consumers_can_win_only_once() {
        let store = Arc::new(MemoryReviewApprovalStore::default());
        let approval = record("approval-race", ReviewDecision::Approve);
        let hash = approval.action_hash.clone();
        store.insert(approval).await.unwrap();
        let mut tasks = Vec::new();
        for _ in 0..16 {
            let store = Arc::clone(&store);
            let hash = hash.clone();
            tasks.push(tokio::spawn(async move {
                store
                    .consume("tenant-1", "approval-race", &hash, now())
                    .await
                    .unwrap()
                    .is_some()
            }));
        }
        let mut winners = 0;
        for task in tasks {
            winners += usize::from(task.await.unwrap());
        }
        assert_eq!(winners, 1);
    }
}

//! In-memory adapter for completed human-review approvals.
//!
//! This adapter is used by tests and local workflows; production runtime
//! storage is PostgreSQL.

use std::collections::HashMap;
use std::future::{ready, Future};
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use kavach_ports::{PortError, ReviewApprovalRecord, ReviewApprovalStore, ReviewReleaseRecord};

type ApprovalKey = (String, String);
type StoredApproval = (ReviewApprovalRecord, Option<DateTime<Utc>>);

#[derive(Default)]
struct ApprovalState {
    records: HashMap<ApprovalKey, StoredApproval>,
    releases: HashMap<(String, String), ReviewReleaseRecord>,
}

#[derive(Default)]
pub struct MemoryReviewApprovalStore {
    state: Mutex<ApprovalState>,
}

impl ReviewApprovalStore for MemoryReviewApprovalStore {
    fn insert(
        &self,
        record: ReviewApprovalRecord,
    ) -> impl Future<Output = Result<(), PortError>> + Send {
        let result = (|| {
            record.validate()?;
            let key = (record.tenant_id.clone(), record.approval_id.clone());
            let mut state = self
                .state
                .lock()
                .map_err(|_| PortError::unavailable("review approval store lock poisoned"))?;
            if state.records.contains_key(&key) {
                return Err(PortError::rejected("review approval id already exists"));
            }
            if record.single_use_credential_id.as_ref().is_some_and(|id| {
                state
                    .records
                    .values()
                    .any(|(stored, _)| stored.single_use_credential_id.as_ref() == Some(id))
            }) {
                return Err(PortError::rejected(
                    "single-use credential id already exists",
                ));
            }
            state.records.insert(key, (record, None));
            Ok(())
        })();
        ready(result)
    }

    fn release(
        &self,
        tenant_id: &str,
        approval_id: &str,
        execution_id: &str,
        action_hash: &str,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<Option<ReviewReleaseRecord>, PortError>> + Send {
        let result = (|| {
            let mut state = self
                .state
                .lock()
                .map_err(|_| PortError::unavailable("review approval store lock poisoned"))?;
            let release_key = (tenant_id.to_string(), execution_id.to_string());
            if let Some(existing) = state.releases.get(&release_key) {
                return Ok((existing.approval_id == approval_id
                    && existing.action_hash == action_hash)
                    .then(|| existing.clone()));
            }
            let key = (tenant_id.to_string(), approval_id.to_string());
            let release = {
                let Some((record, consumed_at)) = state.records.get_mut(&key) else {
                    return Ok(None);
                };
                if consumed_at.is_some()
                    || record.execution_id.as_deref() != Some(execution_id)
                    || record
                        .validate_scope_and_lifetime(tenant_id, action_hash, now)
                        .is_err()
                {
                    return Ok(None);
                }
                let release = ReviewReleaseRecord {
                    tenant_id: tenant_id.to_string(),
                    approval_id: record.approval_id.clone(),
                    review_record_id: record.review_record_id.clone(),
                    execution_id: record
                        .execution_id
                        .clone()
                        .ok_or_else(|| PortError::invalid("approval has no execution id"))?,
                    action_hash: record.action_hash.clone(),
                    single_use_credential_id: record
                        .single_use_credential_id
                        .clone()
                        .ok_or_else(|| PortError::invalid("approval has no credential id"))?,
                    approver: record.approver.clone(),
                    released_at: now,
                };
                *consumed_at = Some(now);
                release
            };
            release.validate()?;
            state.releases.insert(release_key, release.clone());
            Ok(Some(release))
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
            review_record_id: "adr:tenant-1:0:1".into(),
            execution_id: (decision == ReviewDecision::Approve).then(|| format!("execution-{id}")),
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
    async fn release_is_bound_and_retries_only_for_the_same_execution_id() {
        let store = MemoryReviewApprovalStore::default();
        let approval = record("approval-1", ReviewDecision::Approve);
        let hash = approval.action_hash.clone();
        store.insert(approval.clone()).await.unwrap();

        assert!(store
            .release(
                "tenant-2",
                "approval-1",
                "execution-approval-1",
                &hash,
                now()
            )
            .await
            .unwrap()
            .is_none());
        assert!(store
            .release(
                "tenant-1",
                "approval-1",
                "execution-approval-1",
                "sha256-action-v1:other",
                now()
            )
            .await
            .unwrap()
            .is_none());
        assert!(store
            .release(
                "tenant-1",
                "approval-1",
                "execution-approval-1",
                &hash,
                approval.expires
            )
            .await
            .unwrap()
            .is_none());

        assert_eq!(
            store
                .release(
                    "tenant-1",
                    "approval-1",
                    "execution-approval-1",
                    &hash,
                    now()
                )
                .await
                .unwrap(),
            Some(ReviewReleaseRecord {
                tenant_id: "tenant-1".into(),
                approval_id: "approval-1".into(),
                review_record_id: "adr:tenant-1:0:1".into(),
                execution_id: "execution-approval-1".into(),
                action_hash: hash.clone(),
                single_use_credential_id: approval.single_use_credential_id.clone().unwrap(),
                approver: approval.approver.clone(),
                released_at: now(),
            })
        );
        assert!(store
            .release("tenant-1", "approval-1", "execution-other", &hash, now())
            .await
            .unwrap()
            .is_none());
        assert!(store
            .release(
                "tenant-1",
                "approval-1",
                "execution-approval-1",
                &hash,
                now()
            )
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn rejected_records_never_consume_as_approvals() {
        let store = MemoryReviewApprovalStore::default();
        let rejected = record("approval-reject", ReviewDecision::Reject);
        store.insert(rejected.clone()).await.unwrap();
        assert!(store
            .release(
                "tenant-1",
                "approval-reject",
                "execution-approval-reject",
                &rejected.action_hash,
                now()
            )
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
    async fn concurrent_retries_return_one_release_for_the_same_execution() {
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
                    .release(
                        "tenant-1",
                        "approval-race",
                        "execution-approval-race",
                        &hash,
                        now(),
                    )
                    .await
                    .unwrap()
            }));
        }
        let mut releases = Vec::new();
        for task in tasks {
            releases.push(task.await.unwrap());
        }
        assert!(releases.iter().all(Option::is_some));
        assert!(releases.windows(2).all(|pair| pair[0] == pair[1]));
    }
}

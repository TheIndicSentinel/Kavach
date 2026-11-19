//! Durable human-review records and atomic exact-action consumption.

use chrono::{DateTime, TimeZone, Utc};
use kavach_ports::{ReviewApprovalRecord, ReviewApprovalStore, ReviewDecision};
use kavach_storage::testing::isolated_database_urls;
use kavach_storage::{DatabaseTls, StoragePool};

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

fn record_for_tenant(tenant_id: &str, credential_id: &str) -> ReviewApprovalRecord {
    let mut approval = record("shared-approval", ReviewDecision::Approve);
    approval.tenant_id = tenant_id.into();
    approval.review_record_id = format!("adr:{tenant_id}:0:1");
    approval.single_use_credential_id = Some(credential_id.into());
    approval
}

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 11, 17, 12, 0, 0).unwrap()
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
async fn runtime_role_releases_an_approval_once_for_its_exact_execution() {
    let Some(pool) = pool().await else { return };
    let store = pool.review_approval_store();
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
        Some(kavach_ports::ReviewReleaseRecord {
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
    assert!(store.insert(approval).await.is_err());

    let mut reused_credential = record("approval-reused-credential", ReviewDecision::Approve);
    reused_credential.single_use_credential_id = Some("credential-approval-1".into());
    assert!(store.insert(reused_credential).await.is_err());

    let rejected = record("approval-rejected", ReviewDecision::Reject);
    store.insert(rejected.clone()).await.unwrap();
    assert!(store
        .release(
            "tenant-1",
            "approval-rejected",
            "execution-approval-rejected",
            &rejected.action_hash,
            now()
        )
        .await
        .unwrap()
        .is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_postgres_release_retries_return_the_same_execution_record() {
    let Some(pool) = pool().await else { return };
    let store = pool.review_approval_store();
    let approval = record("approval-race", ReviewDecision::Approve);
    let hash = approval.action_hash.clone();
    store.insert(approval).await.unwrap();

    let (left, right) = tokio::join!(
        store.release(
            "tenant-1",
            "approval-race",
            "execution-approval-race",
            &hash,
            now()
        ),
        store.release(
            "tenant-1",
            "approval-race",
            "execution-approval-race",
            &hash,
            now()
        ),
    );
    let left = left.unwrap();
    let right = right.unwrap();
    assert!(left.is_some() && right.is_some());
    assert_eq!(left.unwrap(), right.unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn identical_approval_ids_are_isolated_between_tenants() {
    let Some(pool) = pool().await else { return };
    let store = pool.review_approval_store();
    let tenant_1 = record_for_tenant("tenant-1", "credential-tenant-1");
    let tenant_2 = record_for_tenant("tenant-2", "credential-tenant-2");
    let hash = tenant_1.action_hash.clone();
    store.insert(tenant_1).await.expect("tenant 1 approval");
    store.insert(tenant_2).await.expect("tenant 2 approval");

    let tenant_1_release = store
        .release(
            "tenant-1",
            "shared-approval",
            "execution-shared-approval",
            &hash,
            now(),
        )
        .await
        .unwrap()
        .expect("tenant 1 release");
    assert_eq!(tenant_1_release.tenant_id, "tenant-1");
    assert_eq!(
        tenant_1_release.single_use_credential_id,
        "credential-tenant-1"
    );

    let tenant_2_release = store
        .release(
            "tenant-2",
            "shared-approval",
            "execution-shared-approval",
            &hash,
            now(),
        )
        .await
        .unwrap()
        .expect("tenant 1 release did not consume tenant 2 approval");
    assert_eq!(tenant_2_release.tenant_id, "tenant-2");
    assert_eq!(
        tenant_2_release.single_use_credential_id,
        "credential-tenant-2"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn approval_and_release_history_cannot_be_forged_edited_deleted_or_truncated() {
    let Some((owner_url, runtime_url)) = isolated_database_urls().await else {
        return;
    };
    let tls = DatabaseTls::development();
    let owner = StoragePool::connect(&owner_url, &tls)
        .await
        .expect("migrate as owner");
    let runtime = StoragePool::connect_with_roles(&runtime_url, Some(&owner_url), &tls)
        .await
        .expect("connect as runtime");
    let approval = record("approval-immutable", ReviewDecision::Approve);
    runtime
        .review_approval_store()
        .insert(approval.clone())
        .await
        .unwrap();
    let release = runtime
        .review_approval_store()
        .release(
            &approval.tenant_id,
            &approval.approval_id,
            approval.execution_id.as_deref().unwrap(),
            &approval.action_hash,
            now(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        release.single_use_credential_id,
        approval.single_use_credential_id.clone().unwrap()
    );

    assert!(sqlx::query(
        "UPDATE human_review_approvals SET rendered_action = 'tampered' \
         WHERE tenant_id = $1 AND approval_id = $2",
    )
    .bind(&approval.tenant_id)
    .bind(&approval.approval_id)
    .execute(&owner.pool)
    .await
    .is_err());
    assert!(sqlx::query(
        "DELETE FROM human_review_approvals WHERE tenant_id = $1 AND approval_id = $2",
    )
    .bind(&approval.tenant_id)
    .bind(&approval.approval_id)
    .execute(&owner.pool)
    .await
    .is_err());
    assert!(sqlx::query("TRUNCATE human_review_approvals")
        .execute(&owner.pool)
        .await
        .is_err());
    assert!(sqlx::query(
        "INSERT INTO human_review_releases \
            (tenant_id, execution_id, approval_id, review_record_id, action_hash, \
             single_use_credential_id, approver, released_at) \
         VALUES ($1, 'forged-execution', $2, $3, $4, 'credential-forged', $5, $6)",
    )
    .bind(&release.tenant_id)
    .bind(&release.approval_id)
    .bind(&release.review_record_id)
    .bind(&release.action_hash)
    .bind(&release.approver)
    .bind(release.released_at)
    .execute(&owner.pool)
    .await
    .is_err());
    assert!(sqlx::query(
        "UPDATE human_review_releases SET single_use_credential_id = 'tampered' \
         WHERE tenant_id = $1 AND execution_id = $2",
    )
    .bind(&release.tenant_id)
    .bind(&release.execution_id)
    .execute(&owner.pool)
    .await
    .is_err());
    assert!(sqlx::query(
        "DELETE FROM human_review_releases WHERE tenant_id = $1 AND execution_id = $2",
    )
    .bind(&release.tenant_id)
    .bind(&release.execution_id)
    .execute(&owner.pool)
    .await
    .is_err());
    assert!(sqlx::query("TRUNCATE human_review_releases")
        .execute(&owner.pool)
        .await
        .is_err());
}

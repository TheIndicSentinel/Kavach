//! Review snapshot tenant boundaries on PostgreSQL.

use chrono::{Duration, Utc};
use kavach_ports::{EncryptedReviewSnapshot, ReviewSnapshotStore};
use kavach_storage::testing::isolated_database_urls;
use kavach_storage::{DatabaseTls, StoragePool};

fn snapshot(tenant_id: &str, marker: u8, now: chrono::DateTime<Utc>) -> EncryptedReviewSnapshot {
    EncryptedReviewSnapshot {
        version: 1,
        key_id: "review-v1".into(),
        tenant_id: tenant_id.into(),
        record_id: "shared-record".into(),
        action_hash: format!(
            "sha256-action-v1:{}",
            char::from(b'a' + marker).to_string().repeat(64)
        ),
        nonce: [marker; 12],
        ciphertext: vec![marker; 32],
        expires_at: now + Duration::minutes(30),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn same_snapshot_id_is_isolated_between_tenants() {
    let Some((owner_url, runtime_url)) = isolated_database_urls().await else {
        return;
    };
    let pool = StoragePool::connect_with_roles(
        &runtime_url,
        Some(&owner_url),
        &DatabaseTls::development(),
    )
    .await
    .expect("migrate as owner and connect as runtime");
    let store = pool.review_snapshot_store();
    let now = Utc::now();
    let tenant_a = snapshot("snapshot-tenant-a", 1, now);
    let tenant_b = snapshot("snapshot-tenant-b", 2, now);

    store
        .insert(tenant_a.clone(), now)
        .await
        .expect("insert tenant A snapshot");
    store
        .insert(tenant_b.clone(), now)
        .await
        .expect("same record ID is distinct in tenant B");
    assert!(store
        .insert(tenant_a.clone(), now)
        .await
        .is_err_and(|error| error.class == kavach_ports::ErrorClass::Rejected));

    let actual_a = store
        .get_live("snapshot-tenant-a", "shared-record", now)
        .await
        .expect("tenant A read");
    assert!(actual_a.as_ref().is_some_and(|actual| {
        actual.tenant_id == tenant_a.tenant_id && actual.ciphertext == tenant_a.ciphertext
    }));
    let actual_b = store
        .get_live("snapshot-tenant-b", "shared-record", now)
        .await
        .expect("tenant B read");
    assert!(actual_b.as_ref().is_some_and(|actual| {
        actual.tenant_id == tenant_b.tenant_id && actual.ciphertext == tenant_b.ciphertext
    }));
    assert!(store
        .get_live("snapshot-tenant-other", "shared-record", now)
        .await
        .expect("unrelated tenant read")
        .is_none());
}

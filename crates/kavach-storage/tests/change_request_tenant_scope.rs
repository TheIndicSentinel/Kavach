//! Maker-checker request reads remain scoped when a database contains rows
//! for more than one tenant (ADR-014 §2.3).

use chrono::{Duration, Utc};
use kavach_storage::testing::isolated_database_url;
use kavach_storage::{
    AuditInsert, ChangeKind, ChangeRequest, ChangeRequestBackend, ChangeStatus, CloseRequest,
    MemoryAdminStore, MemoryChangeStore, MemoryRetentionStore, MemoryRoleStore,
    PostgresChangeStore, StoragePool,
};
use serde_json::json;
use std::sync::Arc;

fn request(id: &str, tenant_id: &str) -> ChangeRequest {
    let now = Utc::now();
    ChangeRequest {
        id: id.into(),
        tenant_id: tenant_id.into(),
        kind: ChangeKind::ActivatePack,
        params: json!({}),
        binding: json!({}),
        change_digest: format!("digest-{id}"),
        reason: None,
        proposer: format!("proposer-{tenant_id}"),
        proposer_key: format!("oidc:{tenant_id}"),
        status: ChangeStatus::Pending,
        decided_by: None,
        decided_by_key: None,
        outcome: None,
        created_at: now,
        expires_at: now + Duration::hours(1),
        decided_at: None,
    }
}

fn audit(tenant_id: &str, id: &str) -> AuditInsert {
    AuditInsert {
        tenant_id: tenant_id.into(),
        acting_as_superadmin: false,
        action: "change_request_proposed".into(),
        resource_type: "change_request".into(),
        resource_id: id.into(),
        actor_principal: format!("proposer-{tenant_id}"),
        approver_principal: String::new(),
        payload: json!({}),
    }
}

fn close_request(tenant_id: &str, id: &str) -> CloseRequest {
    CloseRequest {
        request_id: id.into(),
        status: ChangeStatus::Rejected,
        by: format!("checker-{tenant_id}"),
        by_key: format!("oidc:checker-{tenant_id}"),
        outcome: json!({"reason": "test"}),
        audit: audit(tenant_id, id),
        now: Utc::now(),
    }
}

#[tokio::test]
async fn memory_change_request_reads_are_tenant_scoped() {
    let memory = Arc::new(MemoryChangeStore::new(
        Arc::new(MemoryAdminStore::default()),
        Arc::new(MemoryRetentionStore::default()),
        Arc::new(MemoryRoleStore::default()),
    ));
    let store = ChangeRequestBackend::Memory(memory);
    for (tenant, id) in [("tenant-a", "request-a"), ("tenant-b", "request-b")] {
        store
            .create(&request(id, tenant), audit(tenant, id))
            .await
            .unwrap();
    }

    for (tenant, own_id, other_id) in [
        ("tenant-a", "request-a", "request-b"),
        ("tenant-b", "request-b", "request-a"),
    ] {
        assert_eq!(store.list(tenant, None, 10).await.unwrap().len(), 1);
        assert_eq!(store.get(tenant, own_id).await.unwrap().tenant_id, tenant);
        assert!(store.get(tenant, other_id).await.is_err());
        assert!(store.close(close_request(tenant, other_id)).await.is_err());
        assert_eq!(
            store.get("tenant-b", "request-b").await.unwrap().status,
            ChangeStatus::Pending
        );
    }
    assert!(store.list("tenant-c", None, 10).await.unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn postgres_change_request_reads_are_tenant_scoped() {
    let Some(url) = isolated_database_url().await else {
        return;
    };
    let pool = StoragePool::connect(&url, &kavach_storage::DatabaseTls::development())
        .await
        .expect("connect and migrate");
    let store: PostgresChangeStore = pool.change_request_store();
    for (tenant, id) in [("tenant-a", "request-a"), ("tenant-b", "request-b")] {
        store
            .create(&request(id, tenant), &audit(tenant, id))
            .await
            .unwrap();
    }

    for (tenant, own_id, other_id) in [
        ("tenant-a", "request-a", "request-b"),
        ("tenant-b", "request-b", "request-a"),
    ] {
        assert_eq!(store.list(tenant, None, 10).await.unwrap().len(), 1);
        assert_eq!(store.get(tenant, own_id).await.unwrap().tenant_id, tenant);
        assert!(store.get(tenant, other_id).await.is_err());
        assert!(store.close(&close_request(tenant, other_id)).await.is_err());
        assert_eq!(
            store.get("tenant-b", "request-b").await.unwrap().status,
            ChangeStatus::Pending
        );
    }
    assert!(store.list("tenant-c", None, 10).await.unwrap().is_empty());
}

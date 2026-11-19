//! Incident reads and writes stay within the process tenant (ADR-014 §2.3).

use kavach_evaluate::{EvaluateIncident, IncidentRecorder};
use kavach_storage::testing::isolated_database_url;
use kavach_storage::{DatabaseTls, IncidentBackend, MemoryIncidentStore, StoragePool};
use std::sync::Arc;

fn incident(correlation_id: &str) -> EvaluateIncident {
    EvaluateIncident {
        correlation_id: correlation_id.into(),
        model_id: "credit-underwriting-v1".into(),
        reason: "evidence append failed".into(),
    }
}

#[tokio::test]
async fn memory_incidents_are_tenant_scoped() {
    let store = Arc::new(MemoryIncidentStore::default());
    let mut backend_a = IncidentBackend::Memory(Arc::clone(&store), "tenant-a".into());
    let mut backend_b = IncidentBackend::Memory(Arc::clone(&store), "tenant-b".into());
    backend_a.record(incident("shared-correlation")).unwrap();
    backend_b.record(incident("shared-correlation")).unwrap();

    let a = backend_a.list(10).await.unwrap();
    let b = backend_b.list(10).await.unwrap();
    assert_eq!(a.len(), 1);
    assert_eq!(b.len(), 1);
    assert_eq!(a[0].tenant_id, "tenant-a");
    assert_eq!(b[0].tenant_id, "tenant-b");
    let backend_c = IncidentBackend::Memory(store, "tenant-c".into());
    assert!(backend_c.list(10).await.unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn postgres_incidents_are_tenant_scoped() {
    let Some(url) = isolated_database_url().await else {
        return;
    };
    let pool = StoragePool::connect(&url, &DatabaseTls::development())
        .await
        .expect("connect and migrate");
    let mut a = pool.incident_store_for_tenant("tenant-a");
    let mut b = pool.incident_store_for_tenant("tenant-b");
    a.record(incident("shared-correlation")).unwrap();
    b.record(incident("shared-correlation")).unwrap();

    let a_rows = a.list(10).await.unwrap();
    let b_rows = b.list(10).await.unwrap();
    assert_eq!(a_rows.len(), 1);
    assert_eq!(b_rows.len(), 1);
    assert_eq!(a_rows[0].tenant_id, "tenant-a");
    assert_eq!(b_rows[0].tenant_id, "tenant-b");
    assert!(pool
        .incident_store_for_tenant("tenant-c")
        .list(10)
        .await
        .unwrap()
        .is_empty());
}

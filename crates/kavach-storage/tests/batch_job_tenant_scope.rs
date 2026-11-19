//! Batch-job status writes and reads remain scoped to one tenant (ADR-014 §2.3).

use chrono::Utc;
use kavach_domain::GovernanceMode;
use kavach_storage::testing::isolated_database_url;
use kavach_storage::{
    BatchJobBackend, BatchJobRecord, BatchJobStore, DatabaseTls, MemoryBatchJobStore, StoragePool,
};
use std::sync::Arc;

fn record(tenant_id: &str, job_id: &str) -> BatchJobRecord {
    BatchJobRecord {
        tenant_id: tenant_id.into(),
        job_id: job_id.into(),
        status: "completed".into(),
        input_path: "/tmp/in.ndjson".into(),
        output_path: Some("/tmp/out.ndjson".into()),
        model_id: "credit-underwriting-v1".into(),
        governance_mode: "shadow".into(),
        total_rows: 1,
        processed_rows: 1,
        succeeded_rows: 1,
        failed_rows: 0,
        skipped_rows: 0,
        error_summary: None,
        created_at: Utc::now(),
        started_at: Some(Utc::now()),
        completed_at: Some(Utc::now()),
    }
}

#[tokio::test]
async fn memory_batch_job_reads_are_tenant_scoped() {
    let store = Arc::new(MemoryBatchJobStore::default());
    store.insert(record("tenant-a", "job-a")).unwrap();
    store.insert(record("tenant-b", "job-b")).unwrap();
    let tenant_a = BatchJobBackend::Memory(Arc::clone(&store), "tenant-a".into());
    let tenant_b = BatchJobBackend::Memory(Arc::clone(&store), "tenant-b".into());
    let tenant_c = BatchJobBackend::Memory(store, "tenant-c".into());

    assert_eq!(tenant_a.list(10).await.unwrap()[0].job_id, "job-a");
    assert_eq!(tenant_b.list(10).await.unwrap()[0].job_id, "job-b");
    assert!(tenant_a.get("job-b").await.is_err());
    assert!(tenant_b.get("job-a").await.is_err());
    assert!(tenant_c.list(10).await.unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn postgres_batch_job_reads_and_updates_are_tenant_scoped() {
    let Some(url) = isolated_database_url().await else {
        return;
    };
    let pool = StoragePool::connect(&url, &DatabaseTls::development())
        .await
        .expect("connect and migrate");
    let mut tenant_a = pool.batch_job_store_for_tenant("tenant-a");
    let mut tenant_b = pool.batch_job_store_for_tenant("tenant-b");
    let create = kavach_storage::BatchJobCreate {
        input_path: "/tmp/in.ndjson".into(),
        output_path: "/tmp/out.ndjson".into(),
        model_id: "credit-underwriting-v1".into(),
        governance_mode: GovernanceMode::Shadow,
    };
    let job_a = tenant_a.create_pending(&create).unwrap();
    let job_b = tenant_b.create_pending(&create).unwrap();
    tenant_a.mark_running(&job_a, 1).unwrap();
    tenant_a.mark_completed(&job_a, 1, 1, 0, 0).unwrap();
    tenant_b.mark_running(&job_b, 2).unwrap();

    assert_eq!(tenant_a.list(10).await.unwrap().len(), 1);
    assert_eq!(tenant_b.list(10).await.unwrap().len(), 1);
    assert_eq!(tenant_a.get(&job_a).await.unwrap().tenant_id, "tenant-a");
    assert!(tenant_a.get(&job_b).await.is_err());
    assert!(tenant_b.get(&job_a).await.is_err());

    // A job identifier from another tenant cannot update that row.
    tenant_a.mark_completed(&job_b, 2, 0, 0, 2).unwrap();
    assert_eq!(tenant_b.get(&job_b).await.unwrap().status, "running");
}

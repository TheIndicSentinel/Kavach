use chrono::Utc;
use kavach_storage::{BatchJobBackend, BatchJobRecord, MemoryBatchJobStore};
use std::sync::Arc;

#[tokio::test]
async fn batch_job_backend_lists_memory_records() {
    let store = Arc::new(MemoryBatchJobStore::default());
    store
        .insert(BatchJobRecord {
            job_id: "job-1".into(),
            status: "completed".into(),
            input_path: "/tmp/in.ndjson".into(),
            output_path: Some("/tmp/out.ndjson".into()),
            model_id: "credit-underwriting-v1".into(),
            governance_mode: "shadow".into(),
            total_rows: 5,
            processed_rows: 5,
            succeeded_rows: 5,
            failed_rows: 0,
            skipped_rows: 0,
            error_summary: None,
            created_at: Utc::now(),
            started_at: Some(Utc::now()),
            completed_at: Some(Utc::now()),
        })
        .expect("insert");
    let backend = BatchJobBackend::Memory(store);
    let listed = backend.list(10).await.expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].input_path, "in.ndjson");
}

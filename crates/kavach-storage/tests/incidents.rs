use kavach_evaluate::IncidentRecorder;
use kavach_storage::{IncidentBackend, MemoryIncidentStore};
use std::sync::Arc;

#[tokio::test]
async fn incident_backend_lists_memory_records() {
    let store = Arc::new(MemoryIncidentStore::default());
    let mut backend = IncidentBackend::Memory(Arc::clone(&store));
    backend.record(kavach_evaluate::EvaluateIncident {
        correlation_id: "corr-1".into(),
        model_id: "credit-underwriting-v1".into(),
        reason: "evidence append failed".into(),
    });
    let listed = backend.list(10).await.expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].correlation_id, "corr-1");
}

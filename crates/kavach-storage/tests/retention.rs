use kavach_storage::{MemoryRetentionStore, TombstoneReason};

#[test]
fn memory_tombstone_and_list() {
    let store = MemoryRetentionStore::default();
    let record = store
        .tombstone("ev-1", TombstoneReason::DpdpErasure, "admin-1", "admin-2")
        .expect("tombstone");
    assert_eq!(record.evidence_id, "ev-1");
    assert!(store.is_tombstoned("ev-1").unwrap());
    let listed = store.list_tombstones(10).expect("list");
    assert_eq!(listed.len(), 1);
}

#[test]
fn memory_apply_retention_skips_existing_tombstones() {
    let store = MemoryRetentionStore::default();
    store
        .tombstone("ev-1", TombstoneReason::DpdpErasure, "a", "b")
        .expect("tombstone");
    let report = store
        .apply_retention(&["ev-1".into(), "ev-2".into()], "a", "b")
        .expect("apply");
    assert_eq!(report.tombstoned_count, 1);
    assert_eq!(report.evidence_ids, vec!["ev-2".to_string()]);
}

#[test]
fn memory_retention_settings_round_trip() {
    let store = MemoryRetentionStore::default();
    let updated = store.set_settings(180, "admin-1", "admin-2").expect("set");
    assert_eq!(updated.evidence_retention_days, 180);
    let loaded = store.get_settings().expect("get");
    assert_eq!(loaded.evidence_retention_days, 180);
}

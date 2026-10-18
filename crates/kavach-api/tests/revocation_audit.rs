//! S3 (ADR-012 addendum): the audit entry of a revocation is derived from
//! its stored row and written once per event, so an entry the request could
//! not write is written by the reconciler, and never twice.

mod agent_fixture;
mod contract;

use chrono::{TimeZone, Utc};
use kavach_api::revocation_audit;
use kavach_ports::{MandateStore as _, StoredRevocation};

use agent_fixture::*;

fn row(event_id: &str, clock_synced: Option<bool>) -> StoredRevocation {
    StoredRevocation {
        tenant_id: "default".into(),
        system: "lms".into(),
        event_id: event_id.into(),
        event_digest: format!("sha256-jcs-v1:{}", "ab".repeat(32)),
        event_type: "loan.paid".into(),
        record_ref: "lms:loan/L-1".into(),
        occurred_at: Utc.with_ymd_and_hms(2026, 10, 1, 6, 0, 0).unwrap(),
        revoked: vec!["m-1".into()],
        revoked_at: Utc.with_ymd_and_hms(2026, 10, 1, 6, 0, 1).unwrap(),
        clock_synced,
    }
}

async fn entries_for(state: &kavach_api::AppState, event_id: &str) -> Vec<serde_json::Value> {
    state
        .admin()
        .list_audit(1000)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.action == "mandates_revoked_by_event" && e.payload["event_id"] == event_id)
        .map(|e| e.payload)
        .collect()
}

/// A revocation stored without its audit entry (the process died between
/// the commit and the write) gets exactly one, from the row.
#[tokio::test]
async fn a_missing_audit_entry_is_written_once_from_the_stored_row() {
    let state = state(50).await;
    let store = state
        .dataplane()
        .expect("agent surfaces")
        .mandates()
        .store();
    store
        .record_revocation(row("pay-lost", Some(false)))
        .await
        .expect("stored");
    assert!(entries_for(&state, "pay-lost").await.is_empty());

    let (cursor, written) = revocation_audit::pass(&state, None).await;
    assert_eq!(written, 1);
    let entries = entries_for(&state, "pay-lost").await;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["revoked"], serde_json::json!(["m-1"]));
    assert_eq!(
        entries[0]["clock_synced"], false,
        "the flag as stored, not the clock now"
    );

    // The pass is visible: one entry repaired, none missing, and when it ran.
    let metrics = state.metrics().gather_text().unwrap();
    assert!(
        metrics.contains("kavach_revocation_audit_entries_written_total 1"),
        "{metrics}"
    );
    assert!(
        metrics.contains("kavach_revocation_audit_entries_missing 0"),
        "{metrics}"
    );
    assert!(
        !metrics.contains("kavach_revocation_audit_last_pass_timestamp_seconds 0\n"),
        "{metrics}"
    );

    // A second pass, and a restart from the beginning, write nothing more.
    let (_, again) = revocation_audit::pass(&state, cursor).await;
    assert_eq!(again, 0);
    let (_, rescan) = revocation_audit::pass(&state, None).await;
    assert_eq!(rescan, 0);
    assert_eq!(entries_for(&state, "pay-lost").await.len(), 1);
}

/// The entry the request writes and the one the reconciler would derive are
/// the same, and only one of them exists.
#[tokio::test]
async fn the_request_and_the_reconciler_write_one_entry_between_them() {
    let state = state(50).await;
    let stored = row("pay-both", None);
    let wrote = state
        .admin()
        .append_audit_once(
            &revocation_audit::key(&stored),
            revocation_audit::entry(&stored),
        )
        .await
        .unwrap();
    assert!(wrote);
    state
        .dataplane()
        .unwrap()
        .mandates()
        .store()
        .record_revocation(stored)
        .await
        .unwrap();
    let (_, written) = revocation_audit::pass(&state, None).await;
    assert_eq!(written, 0, "already there");
    let entries = entries_for(&state, "pay-both").await;
    assert_eq!(entries.len(), 1);
    assert!(entries[0]["clock_synced"].is_null(), "unknown for old rows");
}

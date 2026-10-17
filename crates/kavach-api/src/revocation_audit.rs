//! The audit entry of a revocation by a system-of-record event, derived from
//! its stored row (S3, ADR-012 addendum).
//!
//! The request that revokes writes the entry after the commit; if that write
//! fails (or the process dies between), nothing used to repair it. The entry
//! is now a pure function of the stored revocation, written once per event
//! (`append_audit_once`, keyed by tenant, system and event id), so a
//! reconciler pages through the stored rows and writes any entry that is
//! missing. Whichever of the request and the reconciler writes first wins;
//! the content is identical.

use std::sync::Arc;
use std::time::Duration;

use kavach_ports::{MandateStore, RevocationCursor, StoredRevocation};
use kavach_storage::AuditInsert;

use crate::state::AppState;

const TICK: Duration = Duration::from_secs(30);
const RESTART_DELAY: Duration = Duration::from_secs(5);
const PAGE: u32 = 200;

/// The idempotency key of a revocation's audit entry.
#[must_use]
pub fn key(stored: &StoredRevocation) -> String {
    format!(
        "revocation:{}:{}:{}",
        stored.tenant_id, stored.system, stored.event_id
    )
}

/// The audit entry, from the row alone: the same whether the request or the
/// reconciler writes it. `clock_synced` is the value stored when the
/// revocation was applied (`null` for a row written before it was kept).
#[must_use]
pub fn entry(stored: &StoredRevocation) -> AuditInsert {
    AuditInsert {
        action: "mandates_revoked_by_event".into(),
        resource_type: "loan".into(),
        resource_id: stored.record_ref.clone(),
        actor_principal: "system-of-record".into(),
        approver_principal: String::new(),
        payload: serde_json::json!({
            "event_id": stored.event_id,
            "event_type": stored.event_type,
            "revoked": stored.revoked,
            "clock_synced": stored.clock_synced,
        }),
    }
}

/// What one scan found.
struct Scan {
    /// Where the next pass starts: after the last row, or before the first
    /// row that could not be written, so it is tried again.
    resume: Option<RevocationCursor>,
    written: usize,
    failed: usize,
    /// Every revocation could be read.
    complete: bool,
}

async fn scan(state: &AppState, from: Option<RevocationCursor>) -> Scan {
    let Some(dataplane) = state.dataplane() else {
        return Scan {
            resume: from,
            written: 0,
            failed: 0,
            complete: true,
        };
    };
    let mut cursor = from;
    // The cursor before the first row that could not be written.
    let mut retry_from: Option<Option<RevocationCursor>> = None;
    let (mut written, mut failed) = (0, 0);
    loop {
        let page = match dataplane
            .mandates()
            .store()
            .revocations_after(cursor.clone(), PAGE)
            .await
        {
            Ok(page) => page,
            Err(e) => {
                tracing::error!(error = %e, "revocation audit pass could not read the revocations");
                return Scan {
                    resume: retry_from.unwrap_or(cursor),
                    written,
                    failed,
                    complete: false,
                };
            }
        };
        for stored in &page {
            match state
                .admin()
                .append_audit_once(&key(stored), entry(stored))
                .await
            {
                Ok(true) => {
                    written += 1;
                    tracing::warn!(
                        event_id = %stored.event_id,
                        "revocation audit entry written by the reconciler"
                    );
                }
                Ok(false) => {}
                Err(e) => {
                    // Keep scanning (to count them all) but retry from here.
                    failed += 1;
                    retry_from.get_or_insert_with(|| cursor.clone());
                    tracing::error!(
                        event_id = %stored.event_id, error = %e,
                        "ALERT revocation audit entry missing: could not be written"
                    );
                }
            }
            cursor = Some(stored.cursor());
        }
        if page.len() < PAGE as usize {
            return Scan {
                resume: retry_from.unwrap_or(cursor),
                written,
                failed,
                complete: true,
            };
        }
    }
}

/// One pass over the revocations after `cursor`: writes each missing entry
/// and reports what it found. Returns where the next pass starts, and how
/// many entries this pass wrote.
pub async fn pass(
    state: &AppState,
    cursor: Option<RevocationCursor>,
) -> (Option<RevocationCursor>, usize) {
    let scan = scan(state, cursor).await;
    state
        .metrics()
        .observe_revocation_audit_pass(scan.written, scan.failed, scan.complete);
    (scan.resume, scan.written)
}

async fn run(state: Arc<AppState>) {
    // A restart scans from the start once: nothing is assumed written, and
    // writing is idempotent.
    let mut cursor = None;
    let mut interval = tokio::time::interval(TICK);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        (cursor, _) = pass(&state, cursor).await;
    }
}

/// Starts the reconciler when the agent surfaces are on.
pub fn start(state: &Arc<AppState>) {
    if state.dataplane().is_some() {
        let state = Arc::clone(state);
        crate::checkpoints::supervise("revocation audit reconciler", RESTART_DELAY, move || {
            run(Arc::clone(&state))
        });
    }
}

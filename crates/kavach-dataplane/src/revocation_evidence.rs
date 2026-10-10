//! Every revocation by a system-of-record event gets its evidence-chain
//! record (ADR-012 §7).
//!
//! The API revokes first and records second, so contact stops even when the
//! evidence store cannot be written. This pass closes that gap without
//! relying on the system of record to retry: it pages through the stored
//! revocations in time order and writes any record that is missing,
//! idempotently by event id. A background task runs it (the API's
//! `revocation_evidence` module), like the checkpoint writer.

use chrono::{DateTime, Duration, Utc};
use kavach_ports::agent_evidence::AgentEvidenceStore;
use kavach_ports::{MandateStore, RevocationCursor};

use crate::authorize::{AuthorizeCore, MandateVerifier};

#[derive(Debug, Clone, Copy)]
pub struct ReconcileConfig {
    /// Revocations younger than this are left to the request that made
    /// them, which writes its record at once.
    pub grace: Duration,
    /// Each pass starts this far before the watermark, so a revocation
    /// stamped slightly earlier by another replica's clock is still seen.
    pub overlap: Duration,
    /// Revocations read per page.
    pub page: u32,
}

impl Default for ReconcileConfig {
    fn default() -> Self {
        Self {
            grace: Duration::seconds(30),
            overlap: Duration::minutes(10),
            page: 500,
        }
    }
}

/// What one pass found and did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReconcileReport {
    /// Revocations old enough to be checked.
    pub checked: usize,
    /// Event ids whose missing record this pass wrote.
    pub reconciled: Vec<String>,
    /// Revocations still without their record after this pass, by event
    /// id, with why: a failed write, or a stored record that differs from
    /// the revocation.
    pub missing: Vec<(String, String)>,
    /// Where the next pass starts: everything at or before it has its
    /// record. It never moves past a revocation still missing one.
    pub watermark: Option<DateTime<Utc>>,
    /// The revocations or the evidence could not be read: the pass stopped.
    pub error: Option<String>,
}

/// One reconcile pass at `now`, from `watermark` (`None`: from the start).
pub async fn reconcile_revocations<M, V, S>(
    revocations: &M,
    core: &AuthorizeCore<V, S>,
    watermark: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    config: ReconcileConfig,
) -> ReconcileReport
where
    M: MandateStore,
    V: MandateVerifier,
    S: AgentEvidenceStore,
{
    let mut report = ReconcileReport {
        watermark,
        ..ReconcileReport::default()
    };
    let settled = now - config.grace;
    let mut cursor = watermark.map(|w| RevocationCursor::at(w - config.overlap));
    let mut blocked = false;
    loop {
        let page = match revocations
            .revocations_after(cursor.clone(), config.page)
            .await
        {
            Ok(page) => page,
            Err(err) => {
                report.error = Some(format!("revocations: {}", err.message));
                return report;
            }
        };
        let full = u32::try_from(page.len()).unwrap_or(u32::MAX) >= config.page;
        for revocation in &page {
            if revocation.revoked_at > settled {
                return report;
            }
            report.checked += 1;
            let stored = core
                .store()
                .revocation_record(
                    &revocation.tenant_id,
                    &revocation.system,
                    &revocation.event_id,
                )
                .await;
            let recorded = match stored {
                Ok(Some(_)) => true,
                Ok(None) => match core.record_revocation(revocation).await {
                    Ok(_) => {
                        report.reconciled.push(revocation.event_id.clone());
                        true
                    }
                    Err(err) => {
                        report
                            .missing
                            .push((revocation.event_id.clone(), err.message));
                        false
                    }
                },
                Err(err) => {
                    report.error = Some(format!("evidence: {}", err.message));
                    return report;
                }
            };
            if recorded {
                if !blocked {
                    report.watermark = Some(
                        report
                            .watermark
                            .map_or(revocation.revoked_at, |w| w.max(revocation.revoked_at)),
                    );
                }
            } else {
                blocked = true;
            }
        }
        match page.last() {
            Some(last) if full => cursor = Some(last.cursor()),
            _ => return report,
        }
    }
}

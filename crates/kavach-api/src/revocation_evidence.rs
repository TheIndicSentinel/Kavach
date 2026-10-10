//! The revocation evidence reconciler (ADR-012 §7): a background task that
//! writes any missing evidence-chain record of a revocation by a
//! system-of-record event, so the record never depends on the system of
//! record retrying. It runs for the life of the process, like the
//! checkpoint writer, and raises an alert while records are missing.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use kavach_dataplane::{reconcile_revocations, ReconcileConfig, ReconcileReport};

use crate::dataplane::Dataplane;
use crate::metrics::Metrics;

const TICK: Duration = Duration::from_secs(30);
const RESTART_DELAY: Duration = Duration::from_secs(5);

type Core = kavach_dataplane::AuthorizeCore<
    Arc<crate::dataplane::Mandates>,
    crate::dataplane::EvidenceBackend,
>;

/// One pass: runs it, reports it, and returns where the next one starts.
pub async fn pass(
    mandates: &crate::dataplane::Mandates,
    core: &Core,
    watermark: Option<DateTime<Utc>>,
    metrics: &Metrics,
) -> Option<DateTime<Utc>> {
    let report = reconcile_revocations(
        mandates.store(),
        core,
        watermark,
        core.clock_now(),
        ReconcileConfig::default(),
    )
    .await;
    observe(&report, metrics);
    report.watermark
}

fn observe(report: &ReconcileReport, metrics: &Metrics) {
    metrics.observe_revocation_reconcile(report);
    for event_id in &report.reconciled {
        tracing::warn!(
            event_id = %event_id,
            "revocation evidence record written by the reconciler"
        );
    }
    if !report.missing.is_empty() {
        let events: Vec<&str> = report.missing.iter().map(|(id, _)| id.as_str()).collect();
        let reasons: Vec<&str> = report.missing.iter().map(|(_, why)| why.as_str()).collect();
        tracing::error!(
            missing = report.missing.len(),
            events = ?events,
            reasons = ?reasons,
            "ALERT revocation evidence missing: revocations without their evidence-chain record"
        );
    }
    if let Some(error) = &report.error {
        tracing::error!(error = %error, "revocation evidence reconcile pass stopped");
    }
}

async fn run(mandates: Arc<crate::dataplane::Mandates>, core: Arc<Core>, metrics: Metrics) {
    // A restart scans from the start once: nothing is assumed recorded.
    let mut watermark = None;
    let mut interval = tokio::time::interval(TICK);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        watermark = pass(&mandates, &core, watermark, &metrics).await;
    }
}

/// Starts the reconciler when the agent surfaces are on.
pub fn start(dataplane: Option<&Dataplane>, metrics: &Metrics) {
    if let Some(dataplane) = dataplane {
        let mandates = Arc::clone(dataplane.mandates());
        let core = Arc::clone(dataplane.core());
        let metrics = metrics.clone();
        crate::checkpoints::supervise("revocation evidence reconciler", RESTART_DELAY, move || {
            run(Arc::clone(&mandates), Arc::clone(&core), metrics.clone())
        });
    }
}

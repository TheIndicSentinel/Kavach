//! The agent-state evidence reconciler (ADR-013 §4): a background task that
//! writes any missing evidence-chain record of a change of an agent's state,
//! so a stop never depends on the evidence chain being writable at that
//! moment and its record still always follows. Runs for the life of the
//! process, like the checkpoint writer and the revocation reconciler, and
//! raises an alert while records are missing.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use kavach_dataplane::{reconcile_agent_states, ReconcileConfig, StateReconcileReport};

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
    core: &Core,
    watermark: Option<DateTime<Utc>>,
    metrics: &Metrics,
) -> Option<DateTime<Utc>> {
    let report = reconcile_agent_states(
        core,
        watermark,
        core.clock_now(),
        ReconcileConfig::default(),
    )
    .await;
    observe(&report, metrics);
    report.watermark
}

fn observe(report: &StateReconcileReport, metrics: &Metrics) {
    metrics.observe_agent_state_reconcile(report);
    for change in &report.reconciled {
        tracing::warn!(
            change = %change,
            "agent state evidence record written by the reconciler"
        );
    }
    if !report.missing.is_empty() {
        let changes: Vec<&str> = report.missing.iter().map(|(id, _)| id.as_str()).collect();
        let reasons: Vec<&str> = report.missing.iter().map(|(_, why)| why.as_str()).collect();
        tracing::error!(
            missing = report.missing.len(),
            changes = ?changes,
            reasons = ?reasons,
            "ALERT agent state evidence missing: changes without their evidence-chain record"
        );
    }
    if let Some(error) = &report.error {
        tracing::error!(error = %error, "agent state evidence reconcile pass stopped");
    }
}

async fn run(core: Arc<Core>, metrics: Metrics) {
    // A restart scans from the start once: nothing is assumed recorded.
    let mut watermark = None;
    let mut interval = tokio::time::interval(TICK);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        watermark = pass(&core, watermark, &metrics).await;
    }
}

/// Starts the reconciler when the agent surfaces are on.
pub fn start(dataplane: Option<&Dataplane>, metrics: &Metrics) {
    if let Some(dataplane) = dataplane {
        let core = Arc::clone(dataplane.core());
        let metrics = metrics.clone();
        crate::checkpoints::supervise(
            "agent state evidence reconciler",
            RESTART_DELAY,
            move || run(Arc::clone(&core), metrics.clone()),
        );
    }
}

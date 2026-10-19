//! The outcome reconciler task (ADR-017 R2): a background pass that asks a
//! provider what became of each send whose outcome is `unknown`, and writes
//! its confirmed answer, or `ambiguous` after 24 hours. It runs for the life
//! of the process, like the revocation reconciler.
//!
//! It is given the broker only as a minter of status questions
//! ([`kavach_ports::StatusQuestions`]) and the forwarder only as an asker
//! ([`kavach_dataplane::StatusAsker`]): neither trait can send.

use std::sync::Arc;
use std::time::Duration;

use kavach_dataplane::{reconcile_outcomes, OutcomeReconcileReport, PollState};

use crate::dataplane::{Broker, Dataplane, EvidenceBackend, Mandates};
use crate::forward::HttpForwarder;

const TICK: Duration = Duration::from_secs(15);
const RESTART_DELAY: Duration = Duration::from_secs(5);

type Core = kavach_dataplane::AuthorizeCore<Arc<Mandates>, EvidenceBackend>;

/// One pass, reported to the log (counts only; a credential id only for a
/// problem).
pub async fn pass(
    core: &Core,
    broker: &Broker,
    forwarder: &HttpForwarder,
    polls: &mut PollState,
) -> OutcomeReconcileReport {
    let report = reconcile_outcomes(core, forwarder, broker, polls).await;
    observe(&report);
    report
}

fn observe(report: &OutcomeReconcileReport) {
    let resolved = report.confirmed_delivered + report.confirmed_not_delivered + report.ambiguous;
    if resolved > 0 {
        tracing::info!(
            confirmed_delivered = report.confirmed_delivered,
            confirmed_not_delivered = report.confirmed_not_delivered,
            ambiguous = report.ambiguous,
            "unknown outcomes resolved by the reconciler"
        );
    }
    for problem in &report.problems {
        tracing::error!(problem = %problem, "outcome reconcile problem");
    }
    if let Some(error) = &report.error {
        tracing::error!(error = %error, "outcome reconcile pass stopped");
    }
}

async fn run(core: Arc<Core>, broker: Arc<Broker>, forwarder: Arc<HttpForwarder>) {
    let mut polls = PollState::default();
    let mut interval = tokio::time::interval(TICK);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        pass(&core, &broker, &forwarder, &mut polls).await;
    }
}

/// Starts the reconciler when the agent surfaces are on.
pub fn start(dataplane: Option<&Dataplane>) {
    if let Some(dataplane) = dataplane {
        let core = Arc::clone(dataplane.core());
        let (broker, forwarder) = dataplane.status_handles();
        crate::checkpoints::supervise("outcome reconciler", RESTART_DELAY, move || {
            run(
                Arc::clone(&core),
                Arc::clone(&broker),
                Arc::clone(&forwarder),
            )
        });
    }
}

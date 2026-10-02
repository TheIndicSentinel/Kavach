//! The background task that writes evidence checkpoints (ADR-005 §13).
//!
//! It ticks the [`Checkpointer`] once a second, exports what each tick
//! reports, and is restarted if it ever exits. It never touches the
//! decision path: a checkpoint that cannot be written is counted and
//! logged, and an alert is raised when records stay uncovered too long.

use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use kavach_dataplane::{Checkpointer, Skip, StallChange, Tick, TickReport};
use kavach_ports::checkpoint::CheckpointStore;
use serde::Serialize;

use crate::metrics::Metrics;

const TICK: Duration = Duration::from_secs(1);
const RESTART_DELAY: Duration = Duration::from_secs(1);

/// Checkpoint health, in `/v1/runtime` when the agent surfaces are on.
/// Informational: it never affects `/health` or decisions.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct CheckpointView {
    /// Seconds since every record was last covered by a checkpoint. Up to
    /// about 60 is normal while records arrive; it keeps growing if the
    /// writer cannot write or has stopped.
    pub checkpoint_lag_seconds: u64,
    /// True once the lag passes `--checkpoint-stall-seconds`.
    pub checkpoint_stalled: bool,
    /// `seq` of the newest checkpoint.
    pub checkpoint_last_seq: Option<i64>,
    /// Records newer than the newest checkpoint.
    pub checkpoint_uncovered_records: i64,
}

impl CheckpointView {
    pub fn of<S: CheckpointStore>(checkpointer: &Checkpointer<S>) -> Self {
        let status = checkpointer.status(Instant::now());
        Self {
            checkpoint_lag_seconds: status.lag_seconds,
            checkpoint_stalled: status.stalled,
            checkpoint_last_seq: status.last_seq,
            checkpoint_uncovered_records: status.uncovered_records,
        }
    }
}

/// Logs and counts one tick.
fn observe<S: CheckpointStore>(
    report: &TickReport,
    checkpointer: &Checkpointer<S>,
    metrics: &Metrics,
) {
    match &report.tick {
        Tick::Covered | Tick::Waiting => {}
        Tick::Written { seq } => {
            metrics.observe_checkpoint_written();
            tracing::info!(seq, "evidence checkpoint written");
        }
        Tick::Skipped { reason, detail } => {
            metrics.observe_checkpoint_skipped(reason.as_str());
            match reason {
                // Another replica wrote it: nothing is wrong.
                Skip::Superseded => tracing::debug!(reason = reason.as_str(), "{detail}"),
                Skip::ChainBehindCheckpoint => tracing::error!(
                    reason = reason.as_str(),
                    "ALERT evidence checkpoint: {detail}"
                ),
                _ => tracing::warn!(
                    reason = reason.as_str(),
                    "evidence checkpoint not written: {detail}"
                ),
            }
        }
    }
    match report.stall {
        Some(StallChange::Began { lag_seconds }) => tracing::error!(
            lag_seconds,
            "ALERT evidence checkpoints stalled: records have had no checkpoint for \
             {lag_seconds} seconds"
        ),
        Some(StallChange::Ended) => tracing::info!("evidence checkpoints recovered"),
        None => {}
    }
    metrics.set_checkpoint_status(&checkpointer.status(Instant::now()));
}

async fn run<S: CheckpointStore>(checkpointer: Arc<Checkpointer<S>>, metrics: Metrics) {
    let mut interval = tokio::time::interval(TICK);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        let report = checkpointer.tick(Instant::now()).await;
        observe(&report, &checkpointer, &metrics);
    }
}

/// Runs `task` for the life of the process: if it ever ends, by panic or by
/// returning, that is logged and it is started again after `delay`.
pub fn supervise<F, Fut>(
    name: &'static str,
    delay: Duration,
    task: F,
) -> tokio::task::JoinHandle<()>
where
    F: Fn() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        loop {
            match tokio::spawn(task()).await {
                Err(err) if err.is_cancelled() => return,
                Err(err) => {
                    let panic = err.into_panic();
                    let message = panic
                        .downcast_ref::<&str>()
                        .map(ToString::to_string)
                        .or_else(|| panic.downcast_ref::<String>().cloned())
                        .unwrap_or_else(|| "no message".into());
                    tracing::error!(task = name, "ALERT {name} panicked: {message}; restarting");
                }
                Ok(()) => tracing::error!(task = name, "ALERT {name} exited; restarting"),
            }
            tokio::time::sleep(delay).await;
        }
    })
}

/// Starts the checkpoint writer. Needs a Tokio runtime.
pub fn spawn_writer<S: CheckpointStore + 'static>(
    checkpointer: Arc<Checkpointer<S>>,
    metrics: Metrics,
) -> tokio::task::JoinHandle<()> {
    supervise("evidence checkpoint writer", RESTART_DELAY, move || {
        run(Arc::clone(&checkpointer), metrics.clone())
    })
}

/// Starts the writer when the agent surfaces are on. It runs for the life
/// of the process.
pub fn start(dataplane: Option<&crate::dataplane::Dataplane>, metrics: &Metrics) {
    if let Some(dataplane) = dataplane {
        spawn_writer(Arc::clone(dataplane.checkpointer()), metrics.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn a_task_that_panics_or_exits_is_restarted() {
        let runs = Arc::new(AtomicUsize::new(0));
        let (done, mut finished) = tokio::sync::mpsc::unbounded_channel();
        let counter = Arc::clone(&runs);
        let handle = supervise("test task", Duration::from_millis(1), move || {
            let (counter, done) = (Arc::clone(&counter), done.clone());
            async move {
                match counter.fetch_add(1, Ordering::SeqCst) {
                    0 => panic!("first run fails"),
                    1 => {} // second run just returns
                    _ => {
                        let _ = done.send(());
                        std::future::pending::<()>().await;
                    }
                }
            }
        });
        tokio::time::timeout(Duration::from_secs(5), finished.recv())
            .await
            .expect("restarted after a panic and after an exit");
        assert_eq!(runs.load(Ordering::SeqCst), 3);
        handle.abort();
    }
}

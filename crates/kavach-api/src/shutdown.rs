//! An orderly stop.
//!
//! On SIGTERM or Ctrl-C the API:
//! 1. stops accepting new connections;
//! 2. lets every request in flight finish, up to a deadline;
//! 3. waits for every gateway call that has started (see [`InFlight`]);
//! 4. writes a final checkpoint, so nothing recorded is left uncovered.
//!
//! A gateway call runs in a task of its own, so once its decision is
//! recorded it completes (forward, outcome) even if the client has gone:
//! a call in flight at the signal ends with an outcome, never a missing
//! one. The tracker is what makes step 3 possible for a call whose client
//! is no longer connected.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Notify;

/// The default deadline for draining, in seconds. It exceeds the
/// provider's own timeout, which bounds a gateway call.
pub const DEFAULT_GRACE_SECONDS: u64 = 30;

/// Counts gateway calls that have started and not finished.
#[derive(Debug, Default)]
pub struct InFlight {
    count: AtomicUsize,
    idle: Notify,
}

impl InFlight {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Marks one call as started; it is finished when the guard drops.
    #[must_use]
    pub fn enter(self: &Arc<Self>) -> InFlightGuard {
        self.count.fetch_add(1, Ordering::SeqCst);
        InFlightGuard(Arc::clone(self))
    }

    /// Calls started and not yet finished.
    #[must_use]
    pub fn current(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }

    /// Waits until no call is in flight, for at most `deadline`. Returns
    /// how many were still in flight (0: drained).
    pub async fn drain(&self, deadline: Duration) -> usize {
        let wait = async {
            loop {
                // Armed before the check, so a call finishing in between
                // is not missed.
                let notified = self.idle.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if self.current() == 0 {
                    return;
                }
                notified.await;
            }
        };
        let _ = tokio::time::timeout(deadline, wait).await;
        self.current()
    }
}

/// A started gateway call. Dropping it (finished, failed or panicked)
/// marks the call as done.
#[derive(Debug)]
pub struct InFlightGuard(Arc<InFlight>);

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        if self.0.count.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.0.idle.notify_waiters();
        }
    }
}

/// What the last steps of an orderly stop did.
#[derive(Debug)]
pub struct Stopped {
    /// Gateway calls still running at the deadline (0: all finished).
    pub still_in_flight: usize,
    /// The final checkpoint's result; `None` without agent surfaces.
    pub checkpoint: Option<kavach_dataplane::checkpointer::Tick>,
}

impl Stopped {
    /// Whether every call finished and the evidence is covered by a
    /// checkpoint.
    #[must_use]
    pub fn clean(&self) -> bool {
        use kavach_dataplane::checkpointer::Tick;
        self.still_in_flight == 0
            && self
                .checkpoint
                .as_ref()
                .is_none_or(|t| matches!(t, Tick::Covered | Tick::Written { .. }))
    }
}

/// Waits for the gateway calls in flight (up to `deadline`), then writes a
/// final checkpoint of everything recorded. Run it after the listeners
/// have stopped accepting.
pub async fn drain_and_checkpoint(
    dataplane: Option<&crate::dataplane::Dataplane>,
    deadline: Duration,
) -> Stopped {
    let Some(dp) = dataplane else {
        return Stopped {
            still_in_flight: 0,
            checkpoint: None,
        };
    };
    let still_in_flight = dp.in_flight().drain(deadline).await;
    let report = dp
        .checkpointer()
        .checkpoint_now(std::time::Instant::now())
        .await;
    Stopped {
        still_in_flight,
        checkpoint: Some(report.tick),
    }
}

/// The stop itself, after the signal: tells every listener to stop (via
/// `stop`), waits up to `grace` for them and for the gateway calls in
/// flight, then writes the final checkpoint. `Ok` only when every listener
/// drained, every call finished and the evidence is covered; otherwise an
/// `ALERT` is logged and the error says so (the process exits non-zero).
pub async fn stop_and_checkpoint<F, T, E>(
    mut servers: std::pin::Pin<&mut F>,
    stop: &tokio::sync::watch::Sender<bool>,
    grace: Duration,
    dataplane: Option<&crate::dataplane::Dataplane>,
) -> Result<(), String>
where
    F: std::future::Future<Output = Result<T, E>>,
{
    let began = std::time::Instant::now();
    let in_flight = dataplane.map_or(0, |dp| dp.in_flight().current());
    tracing::info!(
        "shutting down: no new connections; waiting up to {}s for requests and {in_flight} \
         gateway call(s) in flight",
        grace.as_secs()
    );
    let _ = stop.send(true);
    let drained = tokio::time::timeout(grace, servers.as_mut()).await;
    let listeners_drained = matches!(drained, Ok(Ok(_)));
    let left = grace.saturating_sub(began.elapsed());
    let stopped = drain_and_checkpoint(dataplane, left).await;
    if listeners_drained && stopped.clean() {
        tracing::info!(
            "shutdown complete in {} ms: every gateway call finished; final checkpoint {:?}",
            began.elapsed().as_millis(),
            stopped.checkpoint
        );
        return Ok(());
    }
    tracing::error!(
        "ALERT shutdown was not clean after {}s: listeners drained={listeners_drained}, {} \
         gateway call(s) still in flight, final checkpoint {:?}. A call cut off between send \
         and outcome is reported as outcome_missing",
        grace.as_secs(),
        stopped.still_in_flight,
        stopped.checkpoint
    );
    Err("shutdown was not clean (see the ALERT above)".into())
}

/// Resolves on SIGTERM (a process manager) or Ctrl-C.
pub async fn termination() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut term) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn drain_returns_at_once_when_nothing_is_in_flight() {
        let tracker = InFlight::new();
        assert_eq!(tracker.drain(Duration::from_secs(5)).await, 0);
    }

    #[tokio::test]
    async fn drain_waits_for_a_call_that_finishes() {
        let tracker = InFlight::new();
        let guard = tracker.enter();
        assert_eq!(tracker.current(), 1);
        let finishing = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            drop(guard);
        });
        assert_eq!(tracker.drain(Duration::from_secs(5)).await, 0);
        finishing.await.unwrap();
    }

    #[tokio::test]
    async fn drain_reports_what_is_left_at_the_deadline() {
        let tracker = InFlight::new();
        let _held = tracker.enter();
        let _also = tracker.enter();
        assert_eq!(tracker.drain(Duration::from_millis(50)).await, 2);
    }

    #[tokio::test]
    async fn a_panicking_call_is_not_counted_forever() {
        let tracker = InFlight::new();
        let guard = tracker.enter();
        let task = tokio::spawn(async move {
            let _guard = guard;
            panic!("a call that panics");
        });
        assert!(task.await.is_err());
        assert_eq!(tracker.drain(Duration::from_secs(1)).await, 0);
    }
}

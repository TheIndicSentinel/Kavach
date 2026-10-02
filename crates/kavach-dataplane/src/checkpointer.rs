//! Decides when the agent chain gets a signed checkpoint, and writes it
//! (ADR-005 §13).
//!
//! One [`Checkpointer::tick`] is one step: read the head (no commit lock),
//! read the newest checkpoint, and write a new one when records are
//! uncovered and due. It never blocks or fails a decision. The host calls
//! `tick` on a timer and exports what it reports; this module does no I/O
//! of its own beyond the store, and takes monotonic time as an argument.
//!
//! A checkpoint only helps once a copy has left the system (see
//! `kavach_ports::checkpoint`).

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use kavach_ports::agent_evidence::EvidenceSigner;
use kavach_ports::checkpoint::{
    sign_checkpoint, Appended, CheckpointStore, Head, Scope, CHAIN_AGENT_DECISIONS,
};
use kavach_ports::TimeSource;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointPolicy {
    /// Checkpoint once this many records are uncovered…
    pub every_records: i64,
    /// …or once records have been uncovered for this long.
    pub every: Duration,
    /// Uncovered for this long is a stall: the host raises an alert.
    pub stall_after: Duration,
    /// Largest acceptable clock error for the checkpoint's time (the same
    /// rule as decisions).
    pub max_clock_error_ms: u64,
}

impl Default for CheckpointPolicy {
    fn default() -> Self {
        Self {
            every_records: 1_000,
            every: Duration::from_secs(60),
            stall_after: Duration::from_secs(600),
            max_clock_error_ms: 500,
        }
    }
}

/// Why a due checkpoint was not written. Fixed vocabulary (metric label).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skip {
    /// Trusted time is unavailable; a checkpoint is never dated by a guess.
    Time,
    Signing,
    Store,
    /// Another writer checkpointed first; the next tick reads its result.
    Superseded,
    /// The newest checkpoint covers a record the chain no longer has:
    /// records were removed. Nothing can be written until that is resolved.
    ChainBehindCheckpoint,
}

impl Skip {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Time => "time",
            Self::Signing => "signing",
            Self::Store => "store",
            Self::Superseded => "superseded",
            Self::ChainBehindCheckpoint => "chain_behind_checkpoint",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tick {
    /// No records yet, or the newest record is covered by a checkpoint.
    Covered,
    /// Records are uncovered but not yet due.
    Waiting,
    Written {
        seq: i64,
    },
    /// Due, but not written; `detail` is for the log.
    Skipped {
        reason: Skip,
        detail: String,
    },
}

/// A change in the stall state, reported once when it happens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StallChange {
    Began { lag_seconds: u64 },
    Ended,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TickReport {
    pub tick: Tick,
    pub stall: Option<StallChange>,
}

/// What the host exports (metrics, `/v1/runtime`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointStatus {
    /// `seq` of the newest checkpoint, as of the last tick.
    pub last_seq: Option<i64>,
    /// Records newer than the newest checkpoint, as of the last tick.
    pub uncovered_records: i64,
    /// Seconds since a tick last found every record covered. It keeps
    /// growing if ticks stop, so a dead writer shows up here too.
    pub lag_seconds: u64,
    pub stalled: bool,
    /// Wall-clock time of that last fully-covered tick.
    pub last_covered_at: DateTime<Utc>,
}

struct State {
    last_covered: Instant,
    last_covered_at: DateTime<Utc>,
    uncovered_since: Option<Instant>,
    last_seq: Option<i64>,
    uncovered_records: i64,
    stalled: bool,
}

pub struct Checkpointer<S> {
    store: Arc<S>,
    signer: Box<dyn EvidenceSigner>,
    clock: Box<dyn TimeSource>,
    tenant_id: String,
    partition_id: i32,
    policy: CheckpointPolicy,
    state: Mutex<State>,
}

impl<S: CheckpointStore> Checkpointer<S> {
    /// `signer` must hold the checkpoint key, which signs nothing else.
    pub fn new(
        store: Arc<S>,
        signer: Box<dyn EvidenceSigner>,
        clock: Box<dyn TimeSource>,
        tenant_id: &str,
        partition_id: i32,
        policy: CheckpointPolicy,
        started: Instant,
    ) -> Self {
        let last_covered_at = clock.now().utc;
        Self {
            store,
            signer,
            clock,
            tenant_id: tenant_id.into(),
            partition_id,
            policy,
            state: Mutex::new(State {
                last_covered: started,
                last_covered_at,
                uncovered_since: None,
                last_seq: None,
                uncovered_records: 0,
                stalled: false,
            }),
        }
    }

    fn scope(&self) -> Scope<'_> {
        Scope {
            tenant_id: &self.tenant_id,
            partition_id: self.partition_id,
            chain: CHAIN_AGENT_DECISIONS,
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        // The state is plain data: a poisoned lock is still usable.
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[must_use]
    pub fn status(&self, now: Instant) -> CheckpointStatus {
        let state = self.state();
        let lag = now.saturating_duration_since(state.last_covered);
        CheckpointStatus {
            last_seq: state.last_seq,
            uncovered_records: state.uncovered_records,
            lag_seconds: lag.as_secs(),
            stalled: state.stalled || lag >= self.policy.stall_after,
            last_covered_at: state.last_covered_at,
        }
    }

    /// One step. `now` is monotonic time (it only measures intervals; the
    /// checkpoint itself is dated by the trusted clock).
    pub async fn tick(&self, now: Instant) -> TickReport {
        let tick = self.step(now).await;
        let mut state = self.state();
        if matches!(tick, Tick::Covered | Tick::Written { .. }) {
            state.last_covered = now;
            state.last_covered_at = self.clock.now().utc;
            state.uncovered_since = None;
            state.uncovered_records = 0;
        }
        let lag = now.saturating_duration_since(state.last_covered);
        let stalled = lag >= self.policy.stall_after;
        let stall = match (state.stalled, stalled) {
            (false, true) => Some(StallChange::Began {
                lag_seconds: lag.as_secs(),
            }),
            (true, false) => Some(StallChange::Ended),
            _ => None,
        };
        state.stalled = stalled;
        TickReport { tick, stall }
    }

    async fn step(&self, now: Instant) -> Tick {
        let skipped = |reason, detail: String| Tick::Skipped { reason, detail };
        let head = match self.store.head(self.scope()).await {
            Ok(head) => head,
            Err(e) => return skipped(Skip::Store, format!("read head: {}", e.message)),
        };
        let latest = match self.store.latest(self.scope()).await {
            Ok(latest) => latest,
            Err(e) => return skipped(Skip::Store, format!("read latest: {}", e.message)),
        };
        let last_seq = latest.as_ref().map(|c| c.payload.seq);
        let (head_seq, head_hash) = head.unwrap_or_default();
        let covered_seq = last_seq.unwrap_or(0);
        let uncovered = head_seq - covered_seq;
        let since = {
            let mut state = self.state();
            state.last_seq = last_seq;
            state.uncovered_records = uncovered.max(0);
            if uncovered > 0 {
                *state.uncovered_since.get_or_insert(now)
            } else {
                now
            }
        };
        if uncovered < 0 {
            return skipped(
                Skip::ChainBehindCheckpoint,
                format!(
                    "the newest checkpoint covers record {covered_seq} but the chain ends at \
                     record {head_seq}: records were removed"
                ),
            );
        }
        if uncovered == 0 {
            return Tick::Covered;
        }
        let due = uncovered >= self.policy.every_records
            || now.saturating_duration_since(since) >= self.policy.every;
        if !due {
            return Tick::Waiting;
        }

        let trusted = self.clock.now();
        let ts = match trusted.require_synced(self.policy.max_clock_error_ms) {
            Ok(ts) => ts,
            Err(e) => return skipped(Skip::Time, e.message),
        };
        let head = Head {
            scope: self.scope(),
            seq: head_seq,
            hash: &head_hash,
        };
        let checkpoint = match sign_checkpoint(
            head,
            latest.as_ref(),
            ts,
            trusted.sync.into(),
            &*self.signer,
        ) {
            Ok(checkpoint) => checkpoint,
            Err(e) => return skipped(Skip::Signing, e.message),
        };
        match self.store.append(&checkpoint).await {
            Ok(Appended::Written) => {
                self.state().last_seq = Some(head_seq);
                Tick::Written { seq: head_seq }
            }
            Ok(Appended::Superseded) => {
                skipped(Skip::Superseded, "another writer checkpointed first".into())
            }
            Err(e) => skipped(Skip::Store, format!("append: {}", e.message)),
        }
    }
}

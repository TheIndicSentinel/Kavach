//! The checkpoint writer's decisions (ADR-005 §13): when a checkpoint is
//! due, what stops one, and how a stall shows.

mod common;

use std::future::{ready, Future};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{TimeZone, Utc};
use kavach_dataplane::{CheckpointPolicy, Checkpointer, Skip, StallChange, Tick};
use kavach_ports::agent_evidence::{AgentEvidenceStore, CommitResult, DevKeys, SegmentStart};
use kavach_ports::checkpoint::{
    verify_checkpoints, Appended, ChainSegment, Checkpoint, CheckpointStore, Scope,
    CHAIN_AGENT_DECISIONS,
};
use kavach_ports::{PortError, SyncStatus, TimeSource};
use kavach_ports_testkit::agent_evidence::{request, TestSigner};
use kavach_ports_testkit::FakeClock;
use kavach_storage::MemoryAgentEvidenceStore;

const TENANT: &str = "default";
const SCOPE: Scope<'static> = Scope {
    tenant_id: TENANT,
    partition_id: 0,
    chain: CHAIN_AGENT_DECISIONS,
};

fn policy() -> CheckpointPolicy {
    CheckpointPolicy {
        every_records: 5,
        every: Duration::from_secs(60),
        stall_after: Duration::from_secs(600),
        max_clock_error_ms: 500,
    }
}

struct Rig {
    store: Arc<MemoryAgentEvidenceStore>,
    clock: Arc<FakeClock>,
    start: Instant,
    committed: Mutex<usize>,
}

impl Rig {
    fn new() -> Self {
        Self {
            store: Arc::new(MemoryAgentEvidenceStore::default()),
            clock: Arc::new(FakeClock::synced_at(
                Utc.with_ymd_and_hms(2026, 10, 1, 5, 30, 0).unwrap(),
            )),
            start: Instant::now(),
            committed: Mutex::new(0),
        }
    }

    fn checkpointer(&self, signer: TestSigner) -> Checkpointer<MemoryAgentEvidenceStore> {
        Checkpointer::new(
            Arc::clone(&self.store),
            Box::new(signer),
            Box::new(common::Clock(Arc::clone(&self.clock))),
            TENANT,
            0,
            policy(),
            self.start,
        )
    }

    fn at(&self, seconds: u64) -> Instant {
        self.start + Duration::from_secs(seconds)
    }

    async fn commit(&self, n: usize) {
        let signer = TestSigner::new("evidence-test", 9);
        for _ in 0..n {
            let id = {
                let mut committed = self.committed.lock().unwrap();
                *committed += 1;
                *committed
            };
            let mut req = request(TENANT, &format!("ckpt-{id}"), 1);
            req.contact = None;
            req.draft.send_by = None;
            let result = self.store.commit(req, &*self.clock, &signer).await.unwrap();
            assert!(matches!(result, CommitResult::Committed(_)));
        }
    }

    async fn stored(&self) -> Vec<Checkpoint> {
        self.store.list(SCOPE, 0, 100).await.unwrap()
    }
}

fn key() -> TestSigner {
    TestSigner::new("checkpoint-test", 11)
}

#[tokio::test]
async fn a_checkpoint_is_written_when_records_are_due_by_time_or_by_count() {
    let rig = Rig::new();
    let writer = rig.checkpointer(key());

    // Nothing to cover.
    assert_eq!(writer.tick(rig.at(0)).await.tick, Tick::Covered);
    assert!(rig.stored().await.is_empty());

    // Two records: not due until they have been uncovered for 60 seconds.
    rig.commit(2).await;
    assert_eq!(writer.tick(rig.at(10)).await.tick, Tick::Waiting);
    assert_eq!(writer.tick(rig.at(69)).await.tick, Tick::Waiting);
    let status = writer.status(rig.at(69));
    assert_eq!((status.last_seq, status.uncovered_records), (None, 2));
    assert_eq!(status.lag_seconds, 69);
    assert_eq!(writer.tick(rig.at(70)).await.tick, Tick::Written { seq: 2 });
    // The head has not moved: nothing more to write.
    assert_eq!(writer.tick(rig.at(200)).await.tick, Tick::Covered);
    assert_eq!(rig.stored().await.len(), 1);
    let status = writer.status(rig.at(201));
    assert_eq!((status.last_seq, status.uncovered_records), (Some(2), 0));
    assert_eq!((status.lag_seconds, status.stalled), (1, false));

    // Five more: due at once, by count.
    rig.commit(5).await;
    assert_eq!(
        writer.tick(rig.at(201)).await.tick,
        Tick::Written { seq: 7 }
    );

    // What was written is one linked line that verifies against the chain.
    let stored = rig.stored().await;
    assert_eq!(stored.len(), 2);
    assert_eq!(stored[1].payload.prev_checkpoint_hash, stored[0].hash);
    assert_eq!(stored[1].payload.ts, rig.clock.now().utc);
    assert_eq!(stored[1].payload.time_sync.status, "synced");
    let records = rig.store.records(TENANT, 0).await.unwrap();
    let segment = ChainSegment::of_records(SegmentStart::GENESIS, &records);
    let report = verify_checkpoints(&stored, SCOPE, &segment, &key().keys(), DevKeys::Refuse)
        .expect("checkpoints verify");
    assert_eq!(report.records_after_last, 0);
}

#[tokio::test]
async fn a_restarted_or_second_writer_continues_the_same_line() {
    let rig = Rig::new();
    rig.commit(5).await;
    let first = rig.checkpointer(key());
    assert_eq!(first.tick(rig.at(0)).await.tick, Tick::Written { seq: 5 });

    // A new process (or another replica) starts from what is stored.
    let second = rig.checkpointer(key());
    assert_eq!(second.tick(rig.at(1)).await.tick, Tick::Covered);
    assert_eq!(second.status(rig.at(1)).last_seq, Some(5));
    rig.commit(5).await;
    assert_eq!(second.tick(rig.at(2)).await.tick, Tick::Written { seq: 10 });
    // The first writer sees the other's checkpoint instead of forking.
    assert_eq!(first.tick(rig.at(3)).await.tick, Tick::Covered);

    let stored = rig.stored().await;
    assert_eq!(stored.len(), 2);
    assert_eq!(stored[1].payload.prev_checkpoint_hash, stored[0].hash);
}

#[tokio::test]
async fn without_trusted_time_nothing_is_written_and_the_stall_is_reported_once() {
    let rig = Rig::new();
    let writer = rig.checkpointer(key());
    assert_eq!(writer.tick(rig.at(0)).await.tick, Tick::Covered);
    rig.commit(5).await;
    rig.clock.set_sync(SyncStatus::Unsynced);

    let report = writer.tick(rig.at(1)).await;
    assert!(
        matches!(
            report.tick,
            Tick::Skipped {
                reason: Skip::Time,
                ..
            }
        ),
        "{report:?}"
    );
    assert_eq!(report.stall, None);
    assert!(rig.stored().await.is_empty(), "never dated by a guess");
    // A clock error above the bound is the same.
    rig.clock.set_sync(SyncStatus::Synced { max_error_ms: 501 });
    assert!(matches!(
        writer.tick(rig.at(2)).await.tick,
        Tick::Skipped {
            reason: Skip::Time,
            ..
        }
    ));

    // Still uncovered after ten minutes: the stall begins, once.
    assert_eq!(writer.tick(rig.at(599)).await.stall, None);
    assert!(!writer.status(rig.at(599)).stalled);
    assert_eq!(
        writer.tick(rig.at(600)).await.stall,
        Some(StallChange::Began { lag_seconds: 600 })
    );
    assert_eq!(writer.tick(rig.at(601)).await.stall, None);
    let status = writer.status(rig.at(601));
    assert!(status.stalled);
    assert_eq!((status.lag_seconds, status.uncovered_records), (601, 5));

    // Time comes back: the checkpoint is written and the stall ends.
    rig.clock.set_sync(SyncStatus::Synced { max_error_ms: 20 });
    let report = writer.tick(rig.at(602)).await;
    assert_eq!(report.tick, Tick::Written { seq: 5 });
    assert_eq!(report.stall, Some(StallChange::Ended));
    assert!(!writer.status(rig.at(602)).stalled);
}

#[tokio::test]
async fn a_writer_that_stops_ticking_shows_as_lag_and_then_as_stalled() {
    let rig = Rig::new();
    let writer = rig.checkpointer(key());
    assert_eq!(writer.tick(rig.at(5)).await.tick, Tick::Covered);
    // No further ticks (the task died): status alone shows it.
    assert_eq!(writer.status(rig.at(65)).lag_seconds, 60);
    assert!(!writer.status(rig.at(604)).stalled);
    assert!(writer.status(rig.at(605)).stalled);
}

#[tokio::test]
async fn a_signing_failure_writes_nothing() {
    let rig = Rig::new();
    rig.commit(5).await;
    let writer = rig.checkpointer(TestSigner::failing("checkpoint-test"));
    assert!(matches!(
        writer.tick(rig.at(0)).await.tick,
        Tick::Skipped {
            reason: Skip::Signing,
            ..
        }
    ));
    assert!(rig.stored().await.is_empty());
}

/// A store whose answers the test sets.
#[derive(Default)]
struct Scripted {
    head: Mutex<Option<(i64, String)>>,
    latest: Mutex<Option<Checkpoint>>,
    append: Mutex<Option<Result<Appended, PortError>>>,
    fail_reads: Mutex<bool>,
}

impl CheckpointStore for Scripted {
    fn head(
        &self,
        _: Scope<'_>,
    ) -> impl Future<Output = Result<Option<(i64, String)>, PortError>> + Send {
        ready(if *self.fail_reads.lock().unwrap() {
            Err(PortError::unavailable("database down"))
        } else {
            Ok(self.head.lock().unwrap().clone())
        })
    }
    fn latest(
        &self,
        _: Scope<'_>,
    ) -> impl Future<Output = Result<Option<Checkpoint>, PortError>> + Send {
        ready(Ok(self.latest.lock().unwrap().clone()))
    }
    fn append(&self, _: &Checkpoint) -> impl Future<Output = Result<Appended, PortError>> + Send {
        let scripted = self.append.lock().unwrap().clone();
        ready(scripted.unwrap_or(Ok(Appended::Written)))
    }
    fn list(
        &self,
        _: Scope<'_>,
        _: i64,
        _: u32,
    ) -> impl Future<Output = Result<Vec<Checkpoint>, PortError>> + Send {
        ready(Ok(Vec::new()))
    }
}

#[tokio::test]
async fn store_trouble_a_lost_race_and_a_shortened_chain_are_reported_as_such() {
    // A real checkpoint of record 5, to play the "latest".
    let rig = Rig::new();
    rig.commit(5).await;
    assert_eq!(
        rig.checkpointer(key()).tick(rig.at(0)).await.tick,
        Tick::Written { seq: 5 }
    );
    let fifth = rig.stored().await.remove(0);
    let hash = |i: u8| format!("{i:02x}").repeat(32);

    let store = Arc::new(Scripted::default());
    let writer = Checkpointer::new(
        Arc::clone(&store),
        Box::new(key()),
        Box::new(common::Clock(Arc::clone(&rig.clock))),
        TENANT,
        0,
        policy(),
        rig.start,
    );
    let skip = |tick: Tick| match tick {
        Tick::Skipped { reason, detail } => (reason, detail),
        other => panic!("expected a skip, got {other:?}"),
    };

    // The database is down.
    *store.fail_reads.lock().unwrap() = true;
    assert_eq!(skip(writer.tick(rig.at(0)).await.tick).0, Skip::Store);
    *store.fail_reads.lock().unwrap() = false;

    // Ten records; the append fails, then loses a race.
    *store.head.lock().unwrap() = Some((10, hash(10)));
    *store.latest.lock().unwrap() = Some(fifth.clone());
    *store.append.lock().unwrap() = Some(Err(PortError::unavailable("database down")));
    assert_eq!(skip(writer.tick(rig.at(1)).await.tick).0, Skip::Store);
    *store.append.lock().unwrap() = Some(Ok(Appended::Superseded));
    assert_eq!(skip(writer.tick(rig.at(2)).await.tick).0, Skip::Superseded);
    assert_eq!(writer.status(rig.at(2)).uncovered_records, 5);

    // The chain now ends before the newest checkpoint: records were removed.
    *store.head.lock().unwrap() = Some((3, hash(3)));
    let (reason, detail) = skip(writer.tick(rig.at(3)).await.tick);
    assert_eq!(reason, Skip::ChainBehindCheckpoint);
    assert!(
        detail.contains("record 5") && detail.contains("record 3"),
        "{detail}"
    );
    assert_eq!(reason.as_str(), "chain_behind_checkpoint");
    // It is never treated as covered, so the stall alert follows.
    assert_eq!(
        writer.tick(rig.at(600)).await.stall,
        Some(StallChange::Began { lag_seconds: 600 })
    );
}

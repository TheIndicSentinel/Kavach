//! Conformance suite for `CheckpointStore` (ADR-005 §13).
//!
//! Run against an empty store that also holds the agent chain, so the
//! checkpoints have records to cover.

use std::sync::Arc;

use chrono::{DateTime, Duration, TimeZone, Utc};
use kavach_ports::agent_evidence::{
    AgentDecisionRecord, AgentEvidenceStore, CommitResult, DevKeys, SegmentStart, TimeSync,
};
use kavach_ports::checkpoint::{
    sign_checkpoint, verify_checkpoints, Appended, ChainSegment, Checkpoint, CheckpointStore, Head,
    Scope, CHAIN_AGENT_DECISIONS,
};
use kavach_ports::ErrorClass;

use crate::agent_evidence::{request, TestSigner};
use crate::FakeClock;

const EVIDENCE_KID: &str = "evidence-test";
const CHECKPOINT_KID: &str = "checkpoint-test";

fn t0() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 1, 5, 30, 0).unwrap()
}

fn scope(tenant: &str) -> Scope<'_> {
    Scope {
        tenant_id: tenant,
        partition_id: 0,
        chain: CHAIN_AGENT_DECISIONS,
    }
}

/// Commits `n` records to `tenant` and returns them in `seq` order.
async fn records<S: AgentEvidenceStore>(
    store: &S,
    tenant: &str,
    n: usize,
) -> Vec<AgentDecisionRecord> {
    let signer = TestSigner::new(EVIDENCE_KID, 9);
    let clock = FakeClock::synced_at(t0());
    for i in 0..n {
        let mut req = request(tenant, &format!("cp-{i}"), 1);
        req.contact = None;
        req.draft.send_by = None;
        let result = store.commit(req, &clock, &signer).await.expect("commit");
        assert!(matches!(result, CommitResult::Committed(_)), "{result:?}");
    }
    let records = store.records(tenant, 0).await.expect("records");
    assert_eq!(records.len(), n);
    records
}

/// A checkpoint of record `seq`, following `previous`.
fn checkpoint(
    tenant: &str,
    records: &[AgentDecisionRecord],
    seq: usize,
    previous: Option<&Checkpoint>,
    signer: &TestSigner,
) -> Checkpoint {
    let seq_i = i64::try_from(seq).unwrap();
    sign_checkpoint(
        Head {
            scope: scope(tenant),
            seq: seq_i,
            hash: &records[seq - 1].hash,
        },
        previous,
        t0() + Duration::seconds(seq_i),
        TimeSync {
            status: "synced".into(),
            max_error_ms: Some(10),
        },
        signer,
    )
    .expect("sign checkpoint")
}

/// Runs the whole suite against an empty store.
pub async fn conformance<S: AgentEvidenceStore + CheckpointStore + 'static>(store: Arc<S>) {
    append_read_and_list(&*store).await;
    refusals_leave_nothing_behind(&*store).await;
    two_writers_never_fork(store).await;
}

async fn append_read_and_list<S: AgentEvidenceStore + CheckpointStore>(store: &S) {
    let t = "cp-basic";
    let signer = TestSigner::new(CHECKPOINT_KID, 11);
    assert_eq!(store.head(scope(t)).await.unwrap(), None);
    assert_eq!(store.latest(scope(t)).await.unwrap(), None);
    assert!(store.list(scope(t), 0, 10).await.unwrap().is_empty());

    let records = records(store, t, 6).await;
    assert_eq!(
        store.head(scope(t)).await.unwrap(),
        Some((6, records[5].hash.clone()))
    );
    // A chain the store does not hold has no head.
    let other_chain = Scope {
        chain: "decision_events",
        ..scope(t)
    };
    assert_eq!(store.head(other_chain).await.unwrap(), None);

    let second = checkpoint(t, &records, 2, None, &signer);
    assert_eq!(store.append(&second).await.unwrap(), Appended::Written);
    assert_eq!(store.latest(scope(t)).await.unwrap(), Some(second.clone()));
    let fifth = checkpoint(t, &records, 5, Some(&second), &signer);
    assert_eq!(store.append(&fifth).await.unwrap(), Appended::Written);
    assert_eq!(store.latest(scope(t)).await.unwrap(), Some(fifth.clone()));

    // Stored exactly as signed, oldest first, paged.
    let all = store.list(scope(t), 0, 10).await.unwrap();
    assert_eq!(all, vec![second.clone(), fifth.clone()]);
    assert_eq!(store.list(scope(t), 2, 10).await.unwrap(), vec![fifth]);
    assert_eq!(store.list(scope(t), 0, 1).await.unwrap(), vec![second]);
    assert!(store.list(scope(t), 5, 10).await.unwrap().is_empty());
    // Another tenant sees none of it.
    assert_eq!(store.latest(scope("cp-elsewhere")).await.unwrap(), None);
    assert!(store
        .list(scope("cp-elsewhere"), 0, 10)
        .await
        .unwrap()
        .is_empty());

    // What the store returns verifies offline against the records.
    let segment = ChainSegment::of_records(SegmentStart::GENESIS, &records);
    let report = verify_checkpoints(&all, scope(t), &segment, &signer.keys(), DevKeys::Refuse)
        .expect("stored checkpoints verify");
    assert_eq!(report.last.map(|l| l.0), Some(5));
    assert_eq!(report.records_after_last, 1);
}

async fn refusals_leave_nothing_behind<S: AgentEvidenceStore + CheckpointStore>(store: &S) {
    let t = "cp-refuse";
    let signer = TestSigner::new(CHECKPOINT_KID, 11);
    let records = records(store, t, 6).await;
    let rejected = |result: Result<Appended, kavach_ports::PortError>, what: &str| {
        assert_eq!(
            result.expect_err(what).class,
            ErrorClass::Rejected,
            "{what}"
        );
    };

    // A hash that is not the record's (here: record 4's hash for seq 3).
    let mut wrong = checkpoint(t, &records, 4, None, &signer);
    wrong.payload.seq = 3;
    wrong.hash = kavach_ports::checkpoint::checkpoint_hash(&wrong.payload).unwrap();
    rejected(store.append(&wrong).await, "wrong record hash");
    // A record that does not exist yet.
    let mut ahead = checkpoint(t, &records, 6, None, &signer);
    ahead.payload.seq = 7;
    ahead.hash = kavach_ports::checkpoint::checkpoint_hash(&ahead.payload).unwrap();
    rejected(store.append(&ahead).await, "beyond the head");
    // Content edited after hashing.
    let mut edited = checkpoint(t, &records, 2, None, &signer);
    edited.payload.key_id = "another-key".into();
    rejected(store.append(&edited).await, "hash does not match");
    // Another tenant's records.
    let foreign = checkpoint("cp-refuse-other", &records, 2, None, &signer);
    rejected(
        store.append(&foreign).await,
        "no such record in that tenant",
    );
    assert_eq!(store.latest(scope(t)).await.unwrap(), None);

    let second = checkpoint(t, &records, 2, None, &signer);
    let fifth = checkpoint(t, &records, 5, Some(&second), &signer);
    assert_eq!(store.append(&second).await.unwrap(), Appended::Written);
    assert_eq!(store.append(&fifth).await.unwrap(), Appended::Written);

    // Following the latest checkpoint without advancing past it.
    let mut back = checkpoint(t, &records, 3, Some(&second), &signer);
    back.payload.prev_checkpoint_hash.clone_from(&fifth.hash);
    back.hash = kavach_ports::checkpoint::checkpoint_hash(&back.payload).unwrap();
    rejected(store.append(&back).await, "does not advance");

    // Not following the latest: someone else got there first.
    assert_eq!(store.append(&fifth).await.unwrap(), Appended::Superseded);
    let stale = checkpoint(t, &records, 6, Some(&second), &signer);
    assert_eq!(store.append(&stale).await.unwrap(), Appended::Superseded);
    let restart = checkpoint(t, &records, 6, None, &signer);
    assert_eq!(store.append(&restart).await.unwrap(), Appended::Superseded);

    assert_eq!(
        store.list(scope(t), 0, 10).await.unwrap(),
        vec![second, fifth]
    );
}

/// Two writers that both try to follow the same checkpoint: exactly one is
/// stored each time, so the checkpoints stay in one line (no fork).
async fn two_writers_never_fork<S: AgentEvidenceStore + CheckpointStore + 'static>(store: Arc<S>) {
    const ROUNDS: usize = 20;
    let t = "cp-fork";
    let signer = TestSigner::new(CHECKPOINT_KID, 11);
    let records = records(&*store, t, 2 * ROUNDS).await;

    let mut written = 0;
    for round in 0..ROUNDS {
        let latest = store.latest(scope(t)).await.unwrap();
        // Both follow `latest`, at different records.
        let a = checkpoint(t, &records, 2 * round + 1, latest.as_ref(), &signer);
        let b = checkpoint(t, &records, 2 * round + 2, latest.as_ref(), &signer);
        let tasks: Vec<_> = [a, b]
            .into_iter()
            .map(|candidate| {
                let store = Arc::clone(&store);
                tokio::spawn(async move { store.append(&candidate).await })
            })
            .collect();
        let mut results = Vec::new();
        for task in tasks {
            results.push(task.await.expect("join").expect("append"));
        }
        results.sort_by_key(|r| *r == Appended::Superseded);
        assert_eq!(
            results,
            vec![Appended::Written, Appended::Superseded],
            "round {round}: exactly one writer wins"
        );
        written += 1;
    }

    let stored = store
        .list(scope(t), 0, u32::try_from(4 * ROUNDS).unwrap())
        .await
        .unwrap();
    assert_eq!(stored.len(), written);
    // One line from the first checkpoint: every link and every record matches.
    let segment = ChainSegment::of_records(SegmentStart::GENESIS, &records);
    let report = verify_checkpoints(&stored, scope(t), &segment, &signer.keys(), DevKeys::Refuse)
        .expect("a single linked line of checkpoints");
    assert!(report.from_first);
    assert_eq!(report.checkpoints, ROUNDS);
    let mut predecessors: Vec<&str> = stored
        .iter()
        .map(|c| c.payload.prev_checkpoint_hash.as_str())
        .collect();
    predecessors.sort_unstable();
    predecessors.dedup();
    assert_eq!(
        predecessors.len(),
        stored.len(),
        "no checkpoint has two successors"
    );
}

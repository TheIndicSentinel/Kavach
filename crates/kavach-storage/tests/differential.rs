//! One random sequence of operations, run against the in-memory store and
//! against Postgres, and everything observable compared after every step.
//!
//! The contract tests check each store against what someone thought to ask;
//! this asks the same random questions of both and lets them disagree. The
//! signer is deterministic and the credential ids are derived from the
//! request ids, so nothing needs normalising: the two stores must produce
//! the same records byte for byte (hashes and signatures included), the same
//! outcomes, resolutions, summaries and work lists, and the same class of
//! error for every refused operation.
//!
//! Needs `KAVACH_TEST_DATABASE_URL` (a skipped run says so; CI sets it).

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU32, Ordering};

use chrono::Duration;
use kavach_ports::agent_evidence::{
    sign_outcome, AgentDecisionRecord, AgentEvidenceStore, CommitResult, Outcome,
};
use kavach_ports::outcome_resolution::{
    outcome_ref, sign_resolution, ResolutionDraft, ResolutionSource, ResolutionState,
};
use kavach_ports::TimeSource;
use kavach_ports_testkit::agent_evidence::{request, revocation_draft, TestSigner};
use kavach_ports_testkit::FakeClock;
use kavach_storage::testing::isolated_database_urls;
use kavach_storage::{MemoryAgentEvidenceStore, StoragePool};
use proptest::prelude::*;
use proptest::test_runner::{Config, TestCaseError, TestRunner};

static CASES: AtomicU32 = AtomicU32::new(0);

/// What the operations came back with, so the test can show it did not run
/// on a sequence that never got anywhere.
static SEEN: std::sync::Mutex<std::collections::BTreeMap<String, u32>> =
    std::sync::Mutex::new(std::collections::BTreeMap::new());

fn tally(kind: &str, result: &str) {
    let key = format!("{kind}: {}", result.chars().take(22).collect::<String>());
    *SEEN.lock().unwrap().entry(key).or_insert(0) += 1;
}

#[derive(Debug, Clone)]
enum Op {
    /// A request (the same id twice is a replay, or a conflict with another cap).
    Commit {
        tenant: u8,
        request: u8,
        cap: u8,
        variant: u8,
    },
    /// An outcome for the `allow`-th credential of the run.
    Outcome { allow: u8, kind: u8, reason: u8 },
    /// A resolution of it: any state from any source with any people.
    Resolve {
        allow: u8,
        pick: u8,
        state: u8,
        source: u8,
        people: u8,
    },
    /// A revocation record for an event.
    Revoke { tenant: u8, event: u8 },
    /// Time passes.
    Advance { seconds: u16 },
}

fn kind_of(op: &Op) -> &'static str {
    match op {
        Op::Commit { .. } => "commit",
        Op::Outcome { .. } => "outcome",
        Op::Resolve { .. } => "resolve",
        Op::Revoke { .. } => "revoke",
        Op::Advance { .. } => "advance",
    }
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        5 => (0u8..2, 0u8..6, 0u8..4, 0u8..4)
            .prop_map(|(tenant, request, cap, variant)| Op::Commit { tenant, request, cap, variant }),
        3 => (0u8..4, 0u8..8, 0u8..3).prop_map(|(allow, kind, reason)| Op::Outcome { allow, kind, reason }),
        4 => (0u8..4, any::<u8>(), 0u8..3, 0u8..4, 0u8..4)
            .prop_map(|(allow, pick, state, source, people)| Op::Resolve { allow, pick, state, source, people }),
        1 => (0u8..2, 0u8..3).prop_map(|(tenant, event)| Op::Revoke { tenant, event }),
        2 => (0u16..900).prop_map(|seconds| Op::Advance { seconds }),
    ]
}

/// What one store holds of a run, for comparing.
struct Run<S> {
    store: S,
    clock: FakeClock,
    signer: TestSigner,
    /// The allowed records so far: (tenant, record).
    allows: Vec<(String, AgentDecisionRecord)>,
}

fn class<T>(result: Result<T, kavach_ports::PortError>) -> Result<T, kavach_ports::ErrorClass> {
    result.map_err(|e| e.class)
}

impl<S: AgentEvidenceStore> Run<S> {
    fn new(store: S) -> Self {
        Self {
            store,
            clock: FakeClock::synced_at(
                chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2026, 10, 1, 5, 30, 0).unwrap(),
            ),
            signer: TestSigner::new("evidence-test", 9),
            allows: Vec::new(),
        }
    }

    /// Does `op` and says what came back, in a form the two stores share.
    async fn apply(&mut self, case: u32, op: &Op) -> String {
        let tenant = |t: u8| format!("d{case}-t{t}");
        match op {
            Op::Commit {
                tenant: t,
                request: r,
                cap,
                variant,
            } => {
                let id = format!("d{case}-{t}-{r}");
                let mut asked = request(&tenant(*t), &id, u32::from(*cap));
                // One time in four the same request id is asked for something
                // else: a conflict, not a replay.
                if *variant == 0 {
                    asked.binding.action = "place_call".into();
                }
                let result = class(self.store.commit(asked, &self.clock, &self.signer).await);
                if let Ok(CommitResult::Committed(record)) = &result {
                    if record.is_allow() {
                        self.allows.push((tenant(*t), (**record).clone()));
                    }
                }
                format!("{result:?}")
            }
            Op::Outcome {
                allow,
                kind,
                reason,
            } => {
                let Some((t, record)) = self.pick(*allow) else {
                    return "no allow yet".into();
                };
                // Half of them unknown: only those can be resolved.
                let outcome = [
                    Outcome::Delivered,
                    Outcome::Failed,
                    Outcome::Refused,
                    Outcome::NotExecuted,
                    Outcome::Unknown,
                    Outcome::Unknown,
                    Outcome::Unknown,
                    Outcome::Unknown,
                ][usize::from(*kind) % 8];
                let reason = ["provider_202", "timeout_after_send", "outcome_not_recorded"]
                    [usize::from(*reason) % 3];
                let row = sign_outcome(
                    &t,
                    record.payload.credential_id.as_deref().unwrap(),
                    &record.hash,
                    outcome,
                    reason,
                    self.clock.now().utc,
                    &self.signer,
                )
                .unwrap();
                format!("{:?}", class(self.store.record_outcome(row).await))
            }
            Op::Resolve {
                allow,
                pick,
                state,
                source,
                people,
            } => {
                self.resolve(*allow, *pick, (*state, *source, *people))
                    .await
            }
            Op::Revoke { tenant: t, event } => {
                let draft = revocation_draft(&tenant(*t), &format!("d{case}-e{event}"));
                let result = class(
                    self.store
                        .append_revocation(draft, &self.clock, &self.signer)
                        .await,
                );
                format!("{result:?}")
            }
            Op::Advance { seconds } => {
                self.clock.advance(Duration::seconds(i64::from(*seconds)));
                "advanced".into()
            }
        }
    }

    /// A resolution of an allow's outcome: three in four the form allows, so
    /// that the stores are asked to keep, repeat and refuse them against the
    /// outcome, and one in four any combination at all.
    async fn resolve(&self, allow: u8, pick: u8, (state, source, people): (u8, u8, u8)) -> String {
        use ResolutionSource::{ConflictResolution, OperatorAttested, ProviderStatus, Reconciler};
        use ResolutionState::{Ambiguous, ConfirmedDelivered as D, ConfirmedNotDelivered as N};
        const ALICE: Option<&str> = Some("oidc:i#alice");
        const BOB: Option<&str> = Some("oidc:i#bob");
        let (allow, state, source, people) = (&allow, &state, &source, &people);
        let Some((t, record)) = self.pick(*allow) else {
            return "no allow yet".into();
        };
        let credential = record.payload.credential_id.clone().unwrap();
        let Some(stored) = self.store.outcome(&t, &credential).await.unwrap() else {
            return "no outcome yet".into();
        };
        // Three in four are resolutions the form allows (so that the
        // stores are asked to keep them, repeat them and refuse them
        // against the outcome); one in four is any combination at all.
        let valid = [
            (D, ProviderStatus, None, None),
            (N, ProviderStatus, None, None),
            (D, OperatorAttested, ALICE, None),
            (N, OperatorAttested, ALICE, BOB),
            (D, ConflictResolution, ALICE, BOB),
            (N, ConflictResolution, BOB, ALICE),
            (Ambiguous, Reconciler, None, None),
        ];
        let (state, source, resolved_by, approved_by) = if pick.is_multiple_of(4) {
            let who = [(None, None), (ALICE, None), (ALICE, BOB), (ALICE, ALICE)]
                [usize::from(*people) % 4];
            (
                [D, N, Ambiguous][usize::from(*state) % 3],
                [
                    ProviderStatus,
                    OperatorAttested,
                    ConflictResolution,
                    Reconciler,
                ][usize::from(*source) % 4],
                who.0,
                who.1,
            )
        } else {
            valid[usize::from(pick) % valid.len()]
        };
        let draft = ResolutionDraft {
            tenant_id: t.clone(),
            credential_id: credential,
            outcome_ref: outcome_ref(&stored),
            state,
            source,
            reason: "provider_status".into(),
            // The form: a reconciler's line carries no evidence.
            evidence_digest: (source != Reconciler).then(|| "ab".repeat(32)),
            resolved_by: resolved_by.map(str::to_string),
            approved_by: approved_by.map(str::to_string),
        };
        // The form check is shared code; a draft it refuses never
        // reaches a store, and that refusal is the same for both.
        match sign_resolution(draft, self.clock.now().utc, &self.signer) {
            Err(e) => format!("form: {:?}", e.class),
            Ok(row) => format!("{:?}", class(self.store.record_resolution(row).await)),
        }
    }

    fn pick(&self, n: u8) -> Option<(String, AgentDecisionRecord)> {
        (!self.allows.is_empty()).then(|| self.allows[usize::from(n) % self.allows.len()].clone())
    }

    /// Everything the store lets a caller see about the run.
    async fn observe(&self, case: u32) -> String {
        let mut seen = String::new();
        for t in 0..2u8 {
            let tenant = format!("d{case}-t{t}");
            let records = class(self.store.records(&tenant, 0).await);
            let _ = writeln!(seen, "{tenant} records {records:?}");
            let _ = writeln!(
                seen,
                "{tenant} unresolved {:?}",
                class(self.store.unresolved_outcomes(&tenant, 100).await)
            );
            let _ = writeln!(
                seen,
                "{tenant} summary {:?}",
                class(self.store.resolution_summary(&tenant).await)
            );
            // The work list of the F7 recovery: allows with no outcome. The
            // windows are narrow because one `Advance` is at most 15 minutes
            // and a run is short: a window of an hour would
            // never exclude anything and would not test the lower bound. The
            // edges are whole minutes from `now`, so they land on decision
            // times (both bounds are strict). A limit cuts the last list short.
            let now = self.clock.now().utc;
            for (name, after, before, limit) in [
                (
                    "all",
                    chrono::DateTime::UNIX_EPOCH,
                    now - Duration::minutes(5),
                    1000,
                ),
                ("recent", now - Duration::minutes(3), now, 1000),
                (
                    "band",
                    now - Duration::minutes(8),
                    now - Duration::minutes(3),
                    1000,
                ),
                ("cut", chrono::DateTime::UNIX_EPOCH, now, 2),
            ] {
                let _ = writeln!(
                    seen,
                    "{tenant} stuck {name} {:?}",
                    class(self.store.stuck_allows(&tenant, after, before, limit).await)
                );
            }
        }
        for (tenant, record) in &self.allows {
            let credential = record.payload.credential_id.as_deref().unwrap();
            let _ = writeln!(
                seen,
                "{credential} outcome {:?} resolutions {:?} by request {:?} record {:?}",
                class(self.store.outcome(tenant, credential).await),
                class(self.store.resolutions(tenant, credential).await),
                class(
                    self.store
                        .get_by_request(tenant, "collections-agent", &record.payload.request_id)
                        .await
                ),
                class(self.store.record(tenant, &record.payload.record_id).await),
            );
        }
        seen
    }
}

#[test]
fn the_memory_store_and_postgres_agree_on_every_observable() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let Some(pool) = runtime.block_on(async {
        let (owner, runtime_url) = isolated_database_urls().await?;
        Some(
            StoragePool::connect_with_roles(
                &runtime_url,
                Some(&owner),
                &kavach_storage::DatabaseTls::development(),
            )
            .await
            .expect("connect"),
        )
    }) else {
        return;
    };
    let postgres = pool.agent_evidence_store();

    let mut runner = TestRunner::new(Config {
        cases: 40,
        failure_persistence: None,
        ..Config::default()
    });
    runner
        .run(&prop::collection::vec(op(), 1..45), |ops| {
            let case = CASES.fetch_add(1, Ordering::SeqCst);
            runtime.block_on(async {
                let mut memory = Run::new(MemoryAgentEvidenceStore::default());
                let mut database = Run::new(postgres.clone());
                for (step, op) in ops.iter().enumerate() {
                    let (a, b) = (memory.apply(case, op).await, database.apply(case, op).await);
                    tally(kind_of(op), &a);
                    if a != b {
                        return Err(TestCaseError::fail(format!(
                            "step {step} {op:?}: memory said {a}, Postgres said {b}"
                        )));
                    }
                    let (a, b) = (memory.observe(case).await, database.observe(case).await);
                    if a != b {
                        return Err(TestCaseError::fail(format!(
                            "after step {step} {op:?} they differ:\n--- memory\n{a}\n--- postgres\n{b}"
                        )));
                    }
                }
                Ok(())
            })
        })
        .unwrap_or_else(|e| panic!("{e}"));

    // The sequences got somewhere: allows, replays, conflicts, outcomes both
    // recorded and refused, resolutions kept, repeated and refused, and
    // revocations all happened, and the stores agreed about each.
    let seen = SEEN.lock().unwrap();
    println!("{seen:#?}");
    let count = |prefix: &str| -> u32 {
        seen.iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .map(|(_, n)| n)
            .sum()
    };
    for (prefix, at_least) in [
        ("commit: Ok(Committed", 40),
        ("commit: Ok(Replayed", 5),
        ("commit: Ok(Conflict", 3),
        ("outcome: Ok(())", 15),
        ("outcome: Err(Rejected)", 5),
        ("resolve: Ok(true)", 15),
        ("resolve: Ok(false)", 1),
        ("resolve: Err(Rejected)", 1),
        ("resolve: form:", 10),
        ("revoke: Ok(", 5),
    ] {
        assert!(
            count(prefix) >= at_least,
            "{prefix}: {} < {at_least}\n{seen:#?}",
            count(prefix)
        );
    }
}

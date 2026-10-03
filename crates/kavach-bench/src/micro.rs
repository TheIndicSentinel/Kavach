//! Storage micro-benchmarks for the E5 decision (Postgres only, no HTTP).
//!
//! E5 would chain outcome rows: each outcome write would lock and advance
//! a per-partition head, as records already do. That adds a second
//! serialisation point on the gateway path. These runs measure the cost:
//!
//! - `commit`: the evidence commit alone (partition head lock, record
//!   insert, head update).
//! - `outcome`: the outcome write as it is today: check the record, insert
//!   the outcome. Each operation first commits an allow to write the
//!   outcome for; that commit is not timed.
//! - `outcome-locked`: the same write in one transaction that first locks
//!   a per-partition outcome head and then advances it: the shape E5 would
//!   give it. Timed the same way.
//!
//! The outcome head lives in a table the benchmark creates in its own
//! schema; nothing in Kavach uses it.

use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Duration as ChronoDuration;
use kavach_ports::agent_evidence::{
    sign_outcome, AgentDecisionRecord, AgentEvidenceStore, CommitResult, Outcome,
};
use kavach_ports::TimeSource;
use kavach_ports_testkit::agent_evidence::{request, TestSigner};
use kavach_storage::StoragePool;

use crate::load::{measure, summarise, RunResult, Scenario};
use crate::stack::{Stack, TENANT};

const EVIDENCE_KID: &str = "evidence-test";

/// The table that stands in for E5's outcome head.
async fn create_outcome_head(pool: &StoragePool) -> Result<(), String> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS bench_outcome_heads (\
            tenant_id TEXT NOT NULL, partition_id INTEGER NOT NULL, \
            head_seq BIGINT NOT NULL, head_hash TEXT NOT NULL, \
            PRIMARY KEY (tenant_id, partition_id))",
    )
    .execute(&pool.pool)
    .await
    .map_err(|e| format!("outcome head table: {e}"))?;
    sqlx::query("INSERT INTO bench_outcome_heads VALUES ($1, 0, 0, '') ON CONFLICT DO NOTHING")
        .bind(TENANT)
        .execute(&pool.pool)
        .await
        .map_err(|e| format!("outcome head row: {e}"))?;
    Ok(())
}

/// Commits one allow, as the gateway would before forwarding.
async fn commit_allow(
    stack: &Stack,
    pool: &StoragePool,
    n: u64,
    signer: &TestSigner,
) -> Result<AgentDecisionRecord, String> {
    let mut req = request(TENANT, &format!("micro-{n}"), 1);
    req.contact = None;
    req.draft.send_by = None;
    match pool
        .agent_evidence_store()
        .commit(req, &*stack.clock, signer)
        .await
        .map_err(|e| e.to_string())?
    {
        CommitResult::Committed(record) => Ok(*record),
        other => Err(format!("commit: {other:?}")),
    }
}

/// The outcome write as E5 would shape it: lock the outcome head, check
/// the record and insert the outcome as `record_outcome` does, advance the
/// head, all in one transaction.
async fn record_outcome_locked(
    pool: &StoragePool,
    outcome: &kavach_ports::agent_evidence::OutcomeRecord,
) -> Result<(), String> {
    let err = |e: sqlx::Error| e.to_string();
    let mut tx = pool.pool.begin().await.map_err(err)?;
    sqlx::query(
        "SELECT head_seq FROM bench_outcome_heads \
         WHERE tenant_id = $1 AND partition_id = 0 FOR UPDATE",
    )
    .bind(&outcome.tenant_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(err)?;
    let hash: Option<String> = sqlx::query_scalar(
        "SELECT hash FROM agent_decisions WHERE tenant_id = $1 AND credential_id = $2",
    )
    .bind(&outcome.tenant_id)
    .bind(&outcome.credential_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(err)?;
    if hash.as_deref() != Some(outcome.record_hash.as_str()) {
        return Err("no allowed record for this credential".into());
    }
    sqlx::query(
        "INSERT INTO agent_outcomes (tenant_id, credential_id, record_hash, outcome, \
            reason, ts, key_id, sig) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(&outcome.tenant_id)
    .bind(&outcome.credential_id)
    .bind(&outcome.record_hash)
    .bind(outcome.outcome.as_str())
    .bind(&outcome.reason)
    .bind(outcome.ts)
    .bind(&outcome.key_id)
    .bind(&outcome.sig)
    .execute(&mut *tx)
    .await
    .map_err(err)?;
    sqlx::query(
        "UPDATE bench_outcome_heads SET head_seq = head_seq + 1, head_hash = $2 \
         WHERE tenant_id = $1 AND partition_id = 0",
    )
    .bind(&outcome.tenant_id)
    .bind(&outcome.sig)
    .execute(&mut *tx)
    .await
    .map_err(err)?;
    tx.commit().await.map_err(err)
}

/// One micro run. `Err` when the stack has no database.
pub async fn run_micro(
    stack: &Arc<Stack>,
    scenario: Scenario,
    concurrency: usize,
    warmup: Duration,
    duration: Duration,
    sequence: &Arc<AtomicU64>,
) -> Result<RunResult, String> {
    let pool = stack
        .storage
        .clone()
        .ok_or("the micro-benchmarks need Postgres")?;
    if scenario == Scenario::OutcomeLocked {
        create_outcome_head(&pool).await?;
    }
    let signer = Arc::new(TestSigner::new(EVIDENCE_KID, 9));
    let stack_op = Arc::clone(stack);
    let measured = measure(concurrency, warmup, duration, sequence, move |n| {
        let (stack, pool, signer) = (Arc::clone(&stack_op), pool.clone(), Arc::clone(&signer));
        async move {
            if scenario == Scenario::Commit {
                let started = Instant::now();
                commit_allow(&stack, &pool, n, &signer).await?;
                return Ok(started.elapsed());
            }
            let record = commit_allow(&stack, &pool, n, &signer).await?;
            let outcome = sign_outcome(
                TENANT,
                record.payload.credential_id.as_deref().unwrap_or_default(),
                &record.hash,
                Outcome::Delivered,
                "provider_202",
                stack.clock.now().utc + ChronoDuration::seconds(1),
                &*signer,
            )
            .map_err(|e| e.to_string())?;
            let started = Instant::now();
            if scenario == Scenario::OutcomeLocked {
                record_outcome_locked(&pool, &outcome).await?;
            } else {
                pool.agent_evidence_store()
                    .record_outcome(outcome)
                    .await
                    .map_err(|e| e.to_string())?;
            }
            Ok(started.elapsed())
        }
    })
    .await;
    Ok(summarise(
        scenario,
        concurrency,
        stack.database_pool(),
        duration,
        measured,
    ))
}

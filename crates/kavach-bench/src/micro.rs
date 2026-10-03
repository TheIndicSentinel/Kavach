//! Storage micro-benchmarks for the E5 decision (Postgres only, no HTTP).
//!
//! E5 would chain outcome rows: each outcome write would lock and advance
//! a per-partition head, as records already do. That adds a second
//! serialisation point on the gateway path. These runs measure the cost:
//!
//! - `commit`: the evidence commit alone (partition head lock, record
//!   insert, head update).
//! - `seal`: hashing and signing one record, the CPU work the commit does
//!   while it holds the partition lock (no database).
//! - `authorize`: the decision alone, in process (PRD NFR-2): the tool
//!   call extracted and decided as a pre-check, with no HTTP and no token
//!   verification. Either store.
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
use kavach_dataplane::{AgentIdentity, Mode, ToolRequest};
use kavach_domain::Decision;
use kavach_ports::agent_evidence::{
    sign_outcome, AgentDecisionRecord, AgentEvidenceStore, CommitResult, Outcome,
};
use kavach_ports::TimeSource;
use kavach_ports_testkit::agent_evidence::{request, TestSigner};
use kavach_storage::StoragePool;

use crate::load::{measure, summarise, RunResult, Scenario};
use crate::stack::{Stack, AGENT, TENANT};

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
    if scenario == Scenario::Seal {
        return Ok(run_seal(stack, concurrency, warmup, duration, sequence).await);
    }
    if scenario == Scenario::Authorize {
        return run_authorize(stack, concurrency, warmup, duration, sequence).await;
    }
    let pool = stack
        .storage
        .clone()
        .ok_or("the storage micro-benchmarks need Postgres")?;
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

/// Times `seal` (JCS, SHA-256, Ed25519) on a complete record payload.
async fn run_seal(
    stack: &Arc<Stack>,
    concurrency: usize,
    warmup: Duration,
    duration: Duration,
    sequence: &Arc<AtomicU64>,
) -> RunResult {
    let signer = Arc::new(TestSigner::new(EVIDENCE_KID, 9));
    let mut template = request(TENANT, "seal", 1).draft;
    template.seq = 1;
    template.prev_hash = kavach_ports::agent_evidence::GENESIS.into();
    template.record_id = "adr:default:0:1".into();
    let template = Arc::new(template);
    let measured = measure(concurrency, warmup, duration, sequence, move |n| {
        let (signer, template) = (Arc::clone(&signer), Arc::clone(&template));
        async move {
            let mut payload = (*template).clone();
            payload.seq = i64::try_from(n).unwrap_or(i64::MAX).saturating_add(1);
            let started = Instant::now();
            kavach_ports::agent_evidence::seal(payload, &*signer).map_err(|e| e.to_string())?;
            Ok(started.elapsed())
        }
    })
    .await;
    summarise(
        Scenario::Seal,
        concurrency,
        stack.database_pool(),
        duration,
        measured,
    )
}

/// Times the decision the gateway makes before it records anything:
/// `ToolRegistry::extract` and `AuthorizeCore::authorize` in pre-check mode,
/// spread over all subjects. The agent is the one the stack's token names,
/// already authenticated: token verification and HTTP are left out (the
/// `precheck` scenario includes both).
async fn run_authorize(
    stack: &Arc<Stack>,
    concurrency: usize,
    warmup: Duration,
    duration: Duration,
    sequence: &Arc<AtomicU64>,
) -> Result<RunResult, String> {
    if stack.dataplane().is_none() {
        return Err("authorize needs the data plane".into());
    }
    let agent = Arc::new(AgentIdentity {
        agent_id: AGENT.into(),
        identity_key: format!("oidc:{}#{AGENT}", kavach_devkit::ISSUER),
        state: kavach_authz::AgentState::Active,
    });
    let stack_op = Arc::clone(stack);
    let measured = measure(concurrency, warmup, duration, sequence, move |n| {
        let (stack, agent) = (Arc::clone(&stack_op), Arc::clone(&agent));
        async move {
            let core = stack.dataplane().ok_or("no data plane")?.core();
            let subject = &stack.subjects[usize::try_from(n).unwrap_or(0) % stack.subjects.len()];
            let mut params = serde_json::Map::new();
            params.insert("subject_ref".into(), subject.subject_ref.clone().into());
            params.insert("channel".into(), "whatsapp".into());
            params.insert("template_id".into(), "emi_reminder_v1".into());
            let request = ToolRequest {
                mandate_id: subject.mandate_id.clone(),
                request_id: format!("bench-authorize-{n}"),
                params,
            };
            let started = Instant::now();
            let call = core
                .tools()
                .extract("send_reminder", request)
                .map_err(|e| e.message)?;
            let decided = core
                .authorize(&agent, &call, Mode::Precheck)
                .await
                .map_err(|e| e.to_string())?;
            let elapsed = started.elapsed();
            if decided.decision != Decision::Pass {
                return Err(format!("expected PASS: {:?}", decided.reasons));
            }
            Ok(elapsed)
        }
    })
    .await;
    Ok(summarise(
        Scenario::Authorize,
        concurrency,
        stack.database_pool(),
        duration,
        measured,
    ))
}

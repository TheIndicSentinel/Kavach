//! Fixed-concurrency load: `concurrency` workers each send one request at a
//! time, back to back, for the run's duration. Latency is measured per
//! request from send to complete response; requests that start during the
//! warm-up are not counted.

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::{json, Value};

use crate::stack::Stack;

/// What each request does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Scenario {
    /// `send_reminder` on a covered subject: decide, record, resolve,
    /// issue a credential, forward, record the outcome. Spread across all
    /// subjects.
    Delivered,
    /// `send_reminder` on a subject no mandate covers: decided and recorded
    /// (BLOCK), never forwarded.
    Blocked,
    /// `POST /v1/authorize`: the decision only, nothing recorded.
    Precheck,
    /// `send_reminder` on one subject only: every call contends for the
    /// same contact-counter row.
    HotSubject,
    /// Micro: the evidence commit alone (`AgentEvidenceStore::commit`),
    /// no HTTP. Postgres only.
    Commit,
    /// Micro: the outcome write alone, as it is today (no lock). Each
    /// operation first commits an allow, which is not timed.
    Outcome,
    /// Micro: the outcome write as E5 would make it: in a transaction that
    /// locks and advances a per-partition outcome head. Timed like
    /// `Outcome`.
    OutcomeLocked,
}

impl Scenario {
    /// The gateway scenarios, over HTTP.
    pub const GATEWAY: [Self; 4] = [
        Self::Delivered,
        Self::Blocked,
        Self::Precheck,
        Self::HotSubject,
    ];
    /// The storage micro-benchmarks (Postgres only).
    pub const MICRO: [Self; 3] = [Self::Commit, Self::Outcome, Self::OutcomeLocked];
    pub const ALL: [Self; 7] = [
        Self::Delivered,
        Self::Blocked,
        Self::Precheck,
        Self::HotSubject,
        Self::Commit,
        Self::Outcome,
        Self::OutcomeLocked,
    ];

    #[must_use]
    pub fn is_micro(self) -> bool {
        Self::MICRO.contains(&self)
    }

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Delivered => "delivered",
            Self::Blocked => "blocked",
            Self::Precheck => "precheck",
            Self::HotSubject => "hot-subject",
            Self::Commit => "commit",
            Self::Outcome => "outcome",
            Self::OutcomeLocked => "outcome-locked",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.name() == value)
    }
}

/// Latency figures for one run, in milliseconds.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RunResult {
    pub scenario: Scenario,
    pub concurrency: usize,
    /// Connections in the Postgres pool (absent for the memory store).
    pub database_pool: Option<u32>,
    pub duration_seconds: f64,
    pub requests: u64,
    pub errors: u64,
    pub requests_per_second: f64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub max_ms: f64,
    /// The first unexpected reply, if any (for the report).
    pub first_error: Option<String>,
}

/// Microseconds as milliseconds. (Exact below 2^52 µs, about 140 years.)
#[allow(clippy::cast_precision_loss)]
fn ms(us: u64) -> f64 {
    us as f64 / 1000.0
}

/// The quantile `per_mille`/1000 (nearest rank) of sorted microsecond
/// samples, in milliseconds.
#[must_use]
pub fn quantile_ms(sorted_us: &[u64], per_mille: usize) -> f64 {
    if sorted_us.is_empty() {
        return 0.0;
    }
    let rank = (per_mille * sorted_us.len()).div_ceil(1000);
    ms(sorted_us[rank.clamp(1, sorted_us.len()) - 1])
}

/// Requests per second.
#[allow(clippy::cast_precision_loss)]
fn rate(requests: usize, seconds: f64) -> f64 {
    requests as f64 / seconds
}

fn request(stack: &Stack, scenario: Scenario, hot: usize, n: u64) -> (String, Value) {
    let subjects = &stack.subjects;
    let i = usize::try_from(n).unwrap_or(0) % subjects.len();
    let hot = hot % subjects.len();
    let (subject, mandate) = match scenario {
        Scenario::HotSubject => (&subjects[hot].subject_ref, &subjects[hot].mandate_id),
        // Another borrower under this subject's mandate.
        Scenario::Blocked => (&stack.stranger, &subjects[i].mandate_id),
        _ => (&subjects[i].subject_ref, &subjects[i].mandate_id),
    };
    let request_id = format!("bench-{}-{n}", scenario.name());
    let params = json!({
        "subject_ref": subject,
        "channel": "whatsapp",
        "template_id": "emi_reminder_v1",
    });
    match scenario {
        Scenario::Precheck => (
            format!("{}/v1/authorize", stack.agent_url),
            json!({ "tool": "send_reminder", "mandate_id": mandate,
                    "request_id": request_id, "params": params }),
        ),
        _ => (
            format!("{}/v1/tools/send_reminder", stack.agent_url),
            json!({ "mandate_id": mandate, "request_id": request_id, "params": params }),
        ),
    }
}

/// Whether a reply is what the scenario must produce.
fn expected(scenario: Scenario, status: u16, body: &Value) -> bool {
    status == 200
        && match scenario {
            Scenario::Delivered | Scenario::HotSubject => body["outcome"] == "delivered",
            Scenario::Blocked => body["decision"] == "BLOCK",
            Scenario::Precheck => body["decision"] == "PASS",
            _ => false,
        }
}

/// What a run produced: one sample per counted operation (µs), and the
/// operations that went wrong.
#[derive(Debug, Default)]
pub struct Measured {
    pub samples: Vec<u64>,
    pub errors: u64,
    pub first_error: Option<String>,
}

/// Runs `op` from `concurrency` workers, back to back, for `warmup +
/// duration`. `op(n)` gets a sequence number unique across the run and
/// returns the time to count for it (so it can leave its own set-up out).
/// Operations that start during the warm-up are not counted.
pub async fn measure<F, Fut>(
    concurrency: usize,
    warmup: Duration,
    duration: Duration,
    sequence: &Arc<AtomicU64>,
    op: F,
) -> Measured
where
    F: Fn(u64) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = Result<Duration, String>> + Send,
{
    let start = Instant::now();
    let measure_from = start + warmup;
    let end = measure_from + duration;
    let workers: Vec<_> = (0..concurrency.max(1))
        .map(|_| {
            let (sequence, op) = (Arc::clone(sequence), op.clone());
            tokio::spawn(async move {
                let mut measured = Measured::default();
                while Instant::now() < end {
                    let n = sequence.fetch_add(1, Ordering::Relaxed);
                    let started = Instant::now();
                    let result = op(n).await;
                    if started < measure_from {
                        continue;
                    }
                    match result {
                        Ok(took) => measured
                            .samples
                            .push(u64::try_from(took.as_micros()).unwrap_or(u64::MAX)),
                        Err(reason) => {
                            measured.errors += 1;
                            measured.first_error.get_or_insert(reason);
                        }
                    }
                }
                measured
            })
        })
        .collect();
    let mut all = Measured::default();
    for worker in workers {
        let measured = worker.await.unwrap_or_default();
        all.samples.extend(measured.samples);
        all.errors += measured.errors;
        if all.first_error.is_none() {
            all.first_error = measured.first_error;
        }
    }
    all.samples.sort_unstable();
    all
}

/// Turns what a run measured into its figures.
#[must_use]
pub fn summarise(
    scenario: Scenario,
    concurrency: usize,
    database_pool: Option<u32>,
    duration: Duration,
    measured: Measured,
) -> RunResult {
    let samples = &measured.samples;
    let seconds = duration.as_secs_f64();
    RunResult {
        scenario,
        concurrency,
        database_pool,
        duration_seconds: seconds,
        requests: samples.len() as u64,
        errors: measured.errors,
        requests_per_second: rate(samples.len(), seconds),
        p50_ms: quantile_ms(samples, 500),
        p95_ms: quantile_ms(samples, 950),
        p99_ms: quantile_ms(samples, 990),
        max_ms: samples.last().map_or(0.0, |us| ms(*us)),
        first_error: measured.first_error,
    }
}

/// One gateway run over HTTP: `concurrency` workers for `warmup +
/// duration`. A hot-subject run sends every call to subject `hot`.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    stack: &Arc<Stack>,
    client: &reqwest::Client,
    scenario: Scenario,
    hot: usize,
    concurrency: usize,
    warmup: Duration,
    duration: Duration,
    sequence: &Arc<AtomicU64>,
) -> RunResult {
    let (stack_op, client) = (Arc::clone(stack), client.clone());
    let measured = measure(concurrency, warmup, duration, sequence, move |n| {
        let (stack, client) = (Arc::clone(&stack_op), client.clone());
        async move {
            let (url, body) = request(&stack, scenario, hot, n);
            let sent = Instant::now();
            let response = client
                .post(url)
                .bearer_auth(&stack.agent_token)
                .json(&body)
                .send()
                .await
                .map_err(|e| e.to_string())?;
            let status = response.status().as_u16();
            let body: Value = response.json().await.unwrap_or(Value::Null);
            let took = sent.elapsed();
            if expected(scenario, status, &body) {
                Ok(took)
            } else {
                Err(format!("{status} {body}"))
            }
        }
    })
    .await;
    summarise(
        scenario,
        concurrency,
        stack.database_pool(),
        duration,
        measured,
    )
}

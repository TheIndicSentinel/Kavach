//! Fixed-concurrency load: `concurrency` workers each send one request at a
//! time, back to back, for the run's duration. Latency is measured per
//! request from send to complete response; requests that start during the
//! warm-up are not counted.

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
}

impl Scenario {
    pub const ALL: [Self; 4] = [
        Self::Delivered,
        Self::Blocked,
        Self::Precheck,
        Self::HotSubject,
    ];

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Delivered => "delivered",
            Self::Blocked => "blocked",
            Self::Precheck => "precheck",
            Self::HotSubject => "hot-subject",
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
        }
}

/// One run: `concurrency` workers for `warmup + duration`. A hot-subject
/// run sends every call to subject `hot`.
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
    let start = Instant::now();
    let measure_from = start + warmup;
    let end = measure_from + duration;
    let workers: Vec<_> = (0..concurrency.max(1))
        .map(|_| {
            let (stack, client, sequence) =
                (Arc::clone(stack), client.clone(), Arc::clone(sequence));
            tokio::spawn(async move {
                let mut samples = Vec::new();
                let (mut errors, mut first_error) = (0u64, None);
                while Instant::now() < end {
                    let n = sequence.fetch_add(1, Ordering::Relaxed);
                    let (url, body) = request(&stack, scenario, hot, n);
                    let sent = Instant::now();
                    let reply = client
                        .post(url)
                        .bearer_auth(&stack.agent_token)
                        .json(&body)
                        .send()
                        .await;
                    let outcome = match reply {
                        Ok(response) => {
                            let status = response.status().as_u16();
                            let body: Value = response.json().await.unwrap_or(Value::Null);
                            if expected(scenario, status, &body) {
                                Ok(())
                            } else {
                                Err(format!("{status} {body}"))
                            }
                        }
                        Err(e) => Err(e.to_string()),
                    };
                    if sent < measure_from {
                        continue;
                    }
                    let elapsed = u64::try_from(sent.elapsed().as_micros()).unwrap_or(u64::MAX);
                    match outcome {
                        Ok(()) => samples.push(elapsed),
                        Err(reason) => {
                            errors += 1;
                            first_error.get_or_insert(reason);
                        }
                    }
                }
                (samples, errors, first_error)
            })
        })
        .collect();

    let mut samples = Vec::new();
    let (mut errors, mut first_error) = (0, None);
    for worker in workers {
        let (worker_samples, worker_errors, worker_error) = worker.await.unwrap_or_default();
        samples.extend(worker_samples);
        errors += worker_errors;
        if first_error.is_none() {
            first_error = worker_error;
        }
    }
    samples.sort_unstable();
    let seconds = duration.as_secs_f64();
    RunResult {
        scenario,
        concurrency,
        duration_seconds: seconds,
        requests: samples.len() as u64,
        errors,
        requests_per_second: rate(samples.len(), seconds),
        p50_ms: quantile_ms(&samples, 500),
        p95_ms: quantile_ms(&samples, 950),
        p99_ms: quantile_ms(&samples, 990),
        max_ms: samples.last().map_or(0.0, |us| ms(*us)),
        first_error,
    }
}

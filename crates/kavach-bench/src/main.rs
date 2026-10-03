use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use kavach_bench::load::{run, Scenario};
use kavach_bench::micro::run_micro;
use kavach_bench::report::{Environment, Report};
use kavach_bench::stack::{Stack, StackOptions, Store};
use kavach_storage::DatabaseTls;

/// Benchmarks the Kavach gateway path at fixed concurrency.
#[derive(Parser)]
#[command(name = "kavach-bench")]
struct Cli {
    /// Postgres URL of a role that may create a schema (a fresh one is used
    /// per run). Without it, the memory store is used: a smoke run only.
    #[arg(long, env = "KAVACH_BENCH_DATABASE_URL", hide_env_values = true)]
    database_url: Option<String>,
    /// Extra CA certificates (PEM) for the database server's certificate.
    #[arg(long, env = "KAVACH_DATABASE_CA")]
    database_ca: Option<PathBuf>,
    /// Keep the run's schema afterwards.
    #[arg(long)]
    keep_schema: bool,
    /// Concurrency levels, comma separated.
    #[arg(long, value_delimiter = ',', default_value = "1,8,32,64")]
    concurrency: Vec<usize>,
    /// Scenarios, comma separated. Gateway (HTTP): delivered, blocked,
    /// precheck, hot-subject. Storage micro-benchmarks (Postgres only):
    /// commit, outcome, outcome-locked.
    #[arg(
        long,
        value_delimiter = ',',
        default_value = "delivered,blocked,precheck,hot-subject,commit,seal,outcome,outcome-locked"
    )]
    scenarios: Vec<String>,
    /// Postgres pool sizes to compare, comma separated: each gets its own
    /// stack and fresh schema.
    #[arg(long, value_delimiter = ',', default_value = "5")]
    pool_sizes: Vec<u32>,
    #[arg(long, default_value_t = 30)]
    duration_seconds: u64,
    #[arg(long, default_value_t = 5)]
    warmup_seconds: u64,
    #[arg(long, default_value_t = 1000)]
    subjects: usize,
    /// Added to every provider response (0: Kavach's own cost only).
    #[arg(long, default_value_t = 0)]
    provider_delay_ms: u64,
    /// Write the report as JSON here.
    #[arg(long)]
    out: Option<PathBuf>,
}

fn cpu_model() -> Option<String> {
    if let Ok(info) = std::fs::read_to_string("/proc/cpuinfo") {
        return info
            .lines()
            .find_map(|l| l.strip_prefix("model name"))
            .and_then(|l| l.split(':').nth(1))
            .map(|m| m.trim().to_string());
    }
    std::process::Command::new("sysctl")
        .args(["-n", "machdep.cpu.brand_string"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|m| m.trim().to_string())
        .filter(|m| !m.is_empty())
}

/// Where and how the figures were measured.
fn environment(cli: &Cli, database: Option<&kavach_bench::stack::DatabaseInfo>) -> Environment {
    Environment {
        kavach_version: env!("CARGO_PKG_VERSION").into(),
        git_commit: std::env::var("GITHUB_SHA").ok(),
        measured_at: chrono::Utc::now().to_rfc3339(),
        os: std::env::consts::OS.into(),
        arch: std::env::consts::ARCH.into(),
        cpu: cpu_model(),
        logical_cpus: std::thread::available_parallelism().map_or(1, usize::from),
        evidence_store: database.map_or_else(|| "memory".into(), |d| d.version.clone()),
        database_sslmode: database.map(|d| d.sslmode.clone()),
        provider_delay_ms: cli.provider_delay_ms,
        subjects: cli.subjects,
        warmup_seconds: cli.warmup_seconds,
        duration_seconds: cli.duration_seconds,
    }
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let cli = Cli::parse();
    let scenarios = cli
        .scenarios
        .iter()
        .map(|s| Scenario::parse(s).ok_or_else(|| format!("unknown scenario {s}")))
        .collect::<Result<Vec<_>, _>>()?;
    let work = std::env::temp_dir().join(format!("kavach-bench-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(&work).map_err(|e| e.to_string())?;
    let store = match &cli.database_url {
        // A development stack: an sslmode=disable URL is accepted (the
        // report says so); any other URL connects with verify-full.
        Some(url) => Store::Postgres {
            database_url: url.clone(),
            tls: DatabaseTls::new(true, cli.database_ca.clone()),
            keep_schema: cli.keep_schema,
        },
        None => Store::Memory,
    };
    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(256)
        .build()
        .map_err(|e| e.to_string())?;
    let (warmup, duration) = (
        Duration::from_secs(cli.warmup_seconds),
        Duration::from_secs(cli.duration_seconds.max(1)),
    );
    let mut runs = Vec::new();
    let mut database = None;
    let mut skipped = false;
    for &pool_size in &cli.pool_sizes {
        eprintln!("pool {pool_size}: setting up {} subjects…", cli.subjects);
        let stack = Arc::new(
            Stack::start(&StackOptions {
                store: store.clone(),
                subjects: cli.subjects.max(1),
                provider_delay: Duration::from_millis(cli.provider_delay_ms),
                pool_size: pool_size.max(1),
                work: work.join(format!("pool-{pool_size}")),
            })
            .await?,
        );
        database.clone_from(&stack.database);
        let sequence = Arc::new(AtomicU64::new(0));
        for scenario in &scenarios {
            if scenario.needs_database() && stack.storage.is_none() {
                skipped = true;
                continue;
            }
            for (index, &concurrency) in cli.concurrency.iter().enumerate() {
                eprintln!(
                    "pool {pool_size}: {} at concurrency {concurrency}…",
                    scenario.name()
                );
                let result = if scenario.is_micro() {
                    run_micro(&stack, *scenario, concurrency, warmup, duration, &sequence).await?
                } else {
                    run(
                        &stack,
                        &client,
                        *scenario,
                        index,
                        concurrency,
                        warmup,
                        duration,
                        &sequence,
                    )
                    .await
                };
                runs.push(result);
            }
        }
        if let Ok(stack) = Arc::try_unwrap(stack) {
            stack.finish().await;
        }
    }
    if skipped {
        eprintln!(
            "the storage micro-benchmarks (commit, outcome, outcome-locked) need Postgres: \
             skipped on the memory store"
        );
    }
    let environment = environment(&cli, database.as_ref());
    let report = Report::new(environment, runs);
    print!("{}", report.markdown());
    if let Some(out) = &cli.out {
        let json = serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?;
        std::fs::write(out, json + "\n").map_err(|e| format!("{}: {e}", out.display()))?;
    }
    let errors: u64 = report.runs.iter().map(|r| r.errors).sum();
    let _ = std::fs::remove_dir_all(&work);
    if errors > 0 {
        return Err(format!("{errors} unexpected replies (see the report)"));
    }
    Ok(())
}

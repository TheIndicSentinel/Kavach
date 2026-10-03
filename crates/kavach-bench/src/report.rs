//! The benchmark report: what was measured, on what, and the figures. The
//! environment is part of every report: a number without its machine,
//! database and provider delay is not a number to quote.

use std::fmt::Write as _;

use serde::Serialize;

use crate::load::RunResult;

/// Where and how the figures were measured.
#[derive(Debug, Clone, Serialize)]
pub struct Environment {
    pub kavach_version: String,
    pub git_commit: Option<String>,
    pub measured_at: String,
    pub os: String,
    pub arch: String,
    pub cpu: Option<String>,
    pub logical_cpus: usize,
    /// `memory`, or the Postgres version string.
    pub evidence_store: String,
    /// The `sslmode` of the database connections (`VerifyFull`, `Disable`);
    /// absent for the memory store.
    pub database_sslmode: Option<String>,
    pub provider_delay_ms: u64,
    pub subjects: usize,
    pub warmup_seconds: u64,
    pub duration_seconds: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub environment: Environment,
    /// Caveats a reader must see with the figures.
    pub notes: Vec<String>,
    pub runs: Vec<RunResult>,
}

impl Report {
    #[must_use]
    pub fn new(environment: Environment, runs: Vec<RunResult>) -> Self {
        let mut notes = Vec::new();
        if environment.provider_delay_ms == 0 {
            notes.push(
                "The mock provider answers with no delay: these figures measure Kavach's own \
                 cost only. A real provider adds its own latency to every delivered call."
                    .into(),
            );
        } else {
            notes.push(format!(
                "The mock provider adds {} ms to every response, standing in for a real \
                 provider.",
                environment.provider_delay_ms
            ));
        }
        if environment.evidence_store == "memory" {
            notes.push(
                "Memory store: a smoke run. These figures say nothing about a deployment.".into(),
            );
        }
        if environment.database_sslmode.as_deref() == Some("Disable") {
            notes.push(
                "Plaintext database connections: a baseline only. Quote the TLS (verify-full) \
                 figures."
                    .into(),
            );
        }
        notes.push(
            "Kavach runs in-process with a fixed trusted clock and an effectively unlimited \
             daily contact cap (checked, never reached). One evidence partition serialises \
             every recorded decision."
                .into(),
        );
        Self {
            environment,
            notes,
            runs,
        }
    }

    /// A table for people.
    #[must_use]
    pub fn markdown(&self) -> String {
        let e = &self.environment;
        let mut out = String::new();
        let _ = writeln!(
            out,
            "Kavach {} ({}), {} {}, {} logical CPUs{}",
            e.kavach_version,
            e.git_commit.as_deref().unwrap_or("unknown commit"),
            e.os,
            e.arch,
            e.logical_cpus,
            e.cpu
                .as_deref()
                .map(|c| format!(" ({c})"))
                .unwrap_or_default(),
        );
        let _ = writeln!(
            out,
            "Evidence: {}{}; provider delay {} ms; {} subjects; {} s warm-up, {} s per run\n",
            e.evidence_store,
            e.database_sslmode
                .as_deref()
                .map(|m| format!(", sslmode {m}"))
                .unwrap_or_default(),
            e.provider_delay_ms,
            e.subjects,
            e.warmup_seconds,
            e.duration_seconds,
        );
        for note in &self.notes {
            let _ = writeln!(out, "> {note}");
        }
        out.push_str(
            "\n| Scenario | Pool | Concurrency | Requests | Errors | Req/s | p50 ms | p95 ms | p99 ms | max ms |\n\
             |---|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n",
        );
        for r in &self.runs {
            let _ = writeln!(
                out,
                "| {} | {} | {} | {} | {} | {:.1} | {:.2} | {:.2} | {:.2} | {:.2} |",
                r.scenario.name(),
                r.database_pool
                    .map_or_else(|| "-".to_string(), |p| p.to_string()),
                r.concurrency,
                r.requests,
                r.errors,
                r.requests_per_second,
                r.p50_ms,
                r.p95_ms,
                r.p99_ms,
                r.max_ms
            );
        }
        let staged: Vec<_> = self.runs.iter().filter(|r| !r.stages.is_empty()).collect();
        if !staged.is_empty() {
            out.push_str(
                "\nWhere a gateway call's time goes (mean ms per call; \"other\" is the rest of \
                 the mean: HTTP, authentication, request parsing):\n\n\
                 | Scenario | Pool | Concurrency | Mean | decide | commit | resolve | credential | forward | outcome | other |\n\
                 |---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n",
            );
            for r in staged {
                let stage = |name: &str| r.stages.get(name).copied().unwrap_or(0.0);
                let names = [
                    "decide",
                    "commit",
                    "resolve",
                    "credential",
                    "forward",
                    "outcome",
                ];
                let known: f64 = names.iter().map(|n| stage(n)).sum();
                let cells: Vec<String> = names.iter().map(|n| format!("{:.2}", stage(n))).collect();
                let _ = writeln!(
                    out,
                    "| {} | {} | {} | {:.2} | {} | {:.2} |",
                    r.scenario.name(),
                    r.database_pool
                        .map_or_else(|| "-".to_string(), |p| p.to_string()),
                    r.concurrency,
                    r.mean_ms,
                    cells.join(" | "),
                    (r.mean_ms - known).max(0.0),
                );
            }
        }
        let failed: Vec<_> = self.runs.iter().filter(|r| r.errors > 0).collect();
        for r in failed {
            let _ = writeln!(
                out,
                "\n{} at {} (pool {}): {} unexpected replies, first: {}",
                r.scenario.name(),
                r.concurrency,
                r.database_pool
                    .map_or_else(|| "-".to_string(), |p| p.to_string()),
                r.errors,
                r.first_error.as_deref().unwrap_or("?")
            );
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::load::{quantile_ms, Scenario};

    fn environment(delay: u64, store: &str, sslmode: Option<&str>) -> Environment {
        Environment {
            kavach_version: "0.1.0".into(),
            git_commit: Some("abc1234".into()),
            measured_at: "2026-10-03T00:00:00Z".into(),
            os: "linux".into(),
            arch: "x86_64".into(),
            cpu: Some("Test CPU".into()),
            logical_cpus: 4,
            evidence_store: store.into(),
            database_sslmode: sslmode.map(Into::into),
            provider_delay_ms: delay,
            subjects: 10,
            warmup_seconds: 1,
            duration_seconds: 2,
        }
    }

    fn result(errors: u64) -> RunResult {
        RunResult {
            scenario: Scenario::HotSubject,
            concurrency: 8,
            database_pool: Some(16),
            duration_seconds: 2.0,
            requests: 100,
            errors,
            requests_per_second: 50.0,
            p50_ms: 1.0,
            p95_ms: 2.0,
            p99_ms: 3.0,
            max_ms: 4.0,
            first_error: (errors > 0).then(|| "409 {}".into()),
            mean_ms: 1.5,
            stages: [("commit".to_string(), 0.75), ("decide".to_string(), 0.25)].into(),
        }
    }

    fn close(actual: f64, expected: f64) {
        assert!((actual - expected).abs() < 1e-9, "{actual} != {expected}");
    }

    #[test]
    fn quantiles_use_the_nearest_rank() {
        let samples: Vec<u64> = (1..=100).map(|ms| ms * 1000).collect();
        close(quantile_ms(&samples, 500), 50.0);
        close(quantile_ms(&samples, 950), 95.0);
        close(quantile_ms(&samples, 990), 99.0);
        close(quantile_ms(&samples, 1000), 100.0);
        close(quantile_ms(&[7_000], 990), 7.0);
        close(quantile_ms(&[], 500), 0.0);
    }

    #[test]
    fn the_report_states_what_the_figures_do_and_do_not_measure() {
        // Zero provider delay: Kavach's own cost only, said in the report.
        let report = Report::new(
            environment(0, "PostgreSQL 16.4", Some("VerifyFull")),
            vec![],
        );
        assert!(
            report.notes[0].contains("Kavach's own cost only"),
            "{:?}",
            report.notes
        );
        assert!(!report.notes.iter().any(|n| n.contains("baseline")));
        // A plaintext database is a baseline; memory is a smoke run.
        let plaintext = Report::new(environment(50, "PostgreSQL 16.4", Some("Disable")), vec![]);
        assert!(plaintext.notes[0].contains("adds 50 ms"));
        assert!(plaintext.notes.iter().any(|n| n.contains("baseline only")));
        let memory = Report::new(environment(0, "memory", None), vec![]);
        assert!(memory.notes.iter().any(|n| n.contains("smoke run")));

        // The table: the environment first, then one row per run, and the
        // first unexpected reply of any run with errors.
        let text = Report::new(
            environment(0, "PostgreSQL 16.4", Some("VerifyFull")),
            vec![result(0), result(3)],
        )
        .markdown();
        assert!(
            text.starts_with("Kavach 0.1.0 (abc1234), linux x86_64, 4 logical CPUs (Test CPU)\n"),
            "{text}"
        );
        assert!(
            text.contains("sslmode VerifyFull; provider delay 0 ms"),
            "{text}"
        );
        assert!(
            text.contains("|---:|\n| hot-subject | 16 | 8 | 100 | 0 | 50.0 | 1.00 |"),
            "{text}"
        );
        assert!(
            text.contains(
                "| hot-subject | 16 | 8 | 1.50 | 0.25 | 0.75 | 0.00 | 0.00 | 0.00 | 0.00 | 0.50 |"
            ),
            "{text}"
        );
        assert!(
            text.contains("hot-subject at 8 (pool 16): 3 unexpected replies, first: 409 {}"),
            "{text}"
        );
        // And the JSON carries the same.
        let json =
            serde_json::to_value(Report::new(environment(0, "memory", None), vec![result(0)]))
                .unwrap();
        assert_eq!(json["runs"][0]["scenario"], "hot-subject");
        assert_eq!(json["environment"]["provider_delay_ms"], 0);
    }
}

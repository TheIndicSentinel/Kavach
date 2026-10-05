//! `kavach simulate` (pre-alpha): a scenario of synthetic agents over
//! simulated days, run against a throwaway dev stack (its own project,
//! fixed clock, loopback, synthetic data), judged by an independent
//! oracle (`kavach-sim`), with the stack's evidence exported as it stops
//! and verified. Never attaches to a running stack.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use chrono::{DateTime, Utc};
use kavach_sim::driver::{self, Stack};
use kavach_sim::oracle::Rules;
use kavach_sim::report::{Bundle, Report};
use kavach_sim::scenario::{self, Scenario, BUILTINS};
use kavach_sim::world::World;
use serde_json::{json, Value};

use crate::output::{CliError, Status, Style, Ui};
use crate::project::Project;
use crate::run::RunFile;
use crate::scene::Scene;

/// What `simulate run` was asked for.
pub struct Ask<'a> {
    pub file: Option<&'a Path>,
    pub builtin: Option<&'a str>,
    pub seed: Option<u64>,
    pub days: Option<u32>,
    pub borrowers: Option<u32>,
    pub keep: bool,
    pub report: Option<&'a Path>,
}

pub fn list(ui: Ui) -> i32 {
    let scenarios: Vec<Value> = BUILTINS
        .iter()
        .filter_map(|(name, _)| scenario::builtin(name).ok())
        .map(|s| {
            json!({ "name": s.name, "description": s.description, "days": s.days,
            "borrowers": s.borrowers, "agents": s.agents.iter().map(|a| a.count).sum::<u32>() })
        })
        .collect();
    let mut human = String::from("Built-in scenarios (nothing is run):\n\n");
    for s in &scenarios {
        let _ = writeln!(
            human,
            "  {:<26} {}",
            s["name"].as_str().unwrap_or_default(),
            s["description"].as_str().unwrap_or_default()
        );
    }
    human.push_str(
        "\nAgent types: compliant (keeps the hours and its own limit), eager (late, too often, wrong channel, by its rates).\n\
         Run one: kavach simulate run --builtin <name>, or kavach simulate run <scenario.yaml>",
    );
    let data = json!({ "scenarios": scenarios, "agent_types": ["compliant", "eager"] });
    ui.finish("simulate list", Status::Ok, &data, &human)
}

fn load(ask: &Ask<'_>) -> Result<Scenario, CliError> {
    let mut s = match (ask.file, ask.builtin) {
        (Some(file), None) => {
            let text = std::fs::read_to_string(file)
                .map_err(|e| CliError::new(format!("cannot read {}", file.display()), e))?;
            scenario::parse(&text)
        }
        (None, name) => scenario::builtin(name.unwrap_or("normal-day")),
        (Some(_), Some(_)) => Err("give a scenario file or --builtin, not both".into()),
    }
    .map_err(|e| crate::authorize::usage("the scenario is not valid", e))?;
    if let Some(seed) = ask.seed {
        s.seed = seed;
    }
    if let Some(days) = ask.days {
        s.days = days;
    }
    if let Some(borrowers) = ask.borrowers {
        s.borrowers = borrowers;
    }
    s.validate()
        .map_err(|e| crate::authorize::usage("the scenario is not valid", e))?;
    Ok(s)
}

pub async fn run(ui: &Ui, ask: &Ask<'_>) -> Result<i32, CliError> {
    let scenario = load(ask)?;
    let world = World::build(&scenario);
    let start =
        driver::start_time(&scenario).map_err(|e| crate::authorize::usage("bad schedule", e))?;

    let mut scene = Scene::new("kavach-sim", ask.keep, &[])?;
    let evidence = scene.dir.join("evidence");
    scene.set_up_args(vec![
        "dev".into(),
        "up".into(),
        "--clock".into(),
        start.to_rfc3339(),
        "--export-on-exit".into(),
        evidence.display().to_string(),
    ]);
    crate::init::create(&scene.dir, &world.devkit()).await?;
    scene.start_stack()?;

    let project = Project::find(&scene.dir)?;
    let live = Live::new(&project, start)?;
    let ledger = driver::run(&live, &scenario, &world).await;
    // Stopped either way: the bundle is written as it stops.
    let clean = scene.stop_gracefully(Duration::from_secs(60));
    let ledger = ledger.map_err(|e| {
        CliError::new("the simulation could not run", e)
            .fix("run again with --keep, and read .kavach/dev-up.log in the kept directory")
    })?;
    let bundle = check_evidence(&project, &evidence, clean);
    let report = Report::build(&scenario, &world, &ledger, bundle, Rules::default());

    let mut data =
        serde_json::to_value(&report).map_err(|e| CliError::new("cannot write the report", e))?;
    data["kept"] = json!(ask.keep.then(|| scene.dir.display().to_string()));
    if let Some(path) = ask.report {
        let text = serde_json::to_string_pretty(&json!({ "report": data, "ledger": ledger }))
            .unwrap_or_default();
        std::fs::write(path, text + "\n")
            .map_err(|e| CliError::new(format!("cannot write {}", path.display()), e))?;
    }
    let status = match report.exit_code() {
        0 => Status::Ok,
        2 => Status::Warnings,
        _ => Status::Failed,
    };
    let human = text(*ui, &report, ask.keep.then_some(scene.dir.as_path()));
    let code = ui.finish("simulate run", status, &data, &human);
    // 2 is "inconclusive" here (no evidence to judge by), as Status maps it.
    Ok(code)
}

/// The bundle the stack wrote as it stopped, verified with the auditor's
/// development keys; missing if it did not stop cleanly.
fn check_evidence(project: &Project, evidence: &Path, clean: bool) -> Bundle {
    if !clean || !evidence.is_dir() {
        return Bundle::Missing {
            reason: if clean {
                "the stack stopped without writing its evidence".into()
            } else {
                "the stack did not stop cleanly (killed or crashed): no evidence bundle".into()
            },
        };
    }
    let keys = project.bundle().join("auditor/trusted-keys.json");
    match kavach_evidence_cli::verify::verify_dir(&kavach_evidence_cli::verify::VerifyRequest {
        bundle: evidence,
        keys: &keys,
        expect_checkpoint: None,
        dev: true,
        now: Utc::now(),
    }) {
        Ok(report) => Bundle::Verified {
            signed_with: match &report.signature {
                kavach_ports::bundle::ManifestSignature::Signed { key_id } => key_id.clone(),
                kavach_ports::bundle::ManifestSignature::Unsigned => "unsigned".into(),
            },
            records: report.records,
            not_protected: report
                .not_protected()
                .iter()
                .map(|f| f.kind.to_string())
                .collect(),
        },
        Err(e) => Bundle::Failed {
            reason: e.to_string(),
        },
    }
}

fn text(ui: Ui, r: &Report, kept: Option<&Path>) -> String {
    let mut out = format!(
        "SIMULATION (synthetic data, mock provider, dev keys) scenario={} seed={} days={} borrowers={}\n\nNOT COVERED:\n",
        r.scenario, r.seed, r.days, r.borrowers
    );
    for item in &r.not_covered {
        let _ = writeln!(out, "  - {item}");
    }
    let reasons: Vec<String> = r
        .blocked_by_reason
        .iter()
        .map(|(k, v)| format!("{k} {v}"))
        .collect();
    let _ = write!(
        out,
        "\nCalls {} · Allowed {} (delivered {}) · Blocked {}{}\n",
        r.calls,
        r.allowed,
        r.delivered,
        r.blocked,
        if reasons.is_empty() {
            String::new()
        } else {
            format!(" ({})", reasons.join(", "))
        }
    );
    for (agent, c) in &r.agents {
        let _ = writeln!(
            out,
            "  {agent:<20} {:<9} allowed {:>3}  blocked {:>3}",
            c.kind, c.allowed, c.blocked
        );
    }
    let _ = writeln!(
        out,
        "Violations {} · Mismatches {} · Leaks {}",
        r.violations.len(),
        r.mismatches.len(),
        r.leaks.len()
    );
    for (what, list) in [
        ("violation", &r.violations),
        ("mismatch", &r.mismatches),
        ("leak", &r.leaks),
    ] {
        for f in list {
            let _ = writeln!(
                out,
                "  {what} #{} {} {} at {}: {}",
                f.seq, f.agent, f.borrower, f.at, f.detail
            );
        }
    }
    let _ = writeln!(
        out,
        "Evidence: {}",
        match &r.evidence {
            Bundle::Verified {
                signed_with,
                records,
                ..
            } =>
                format!("{records} records, verified against dev keys (signed with {signed_with})"),
            Bundle::Missing { reason } => format!("INCONCLUSIVE: {reason}"),
            Bundle::Failed { reason } => format!("FAILED to verify: {reason}"),
        }
    );
    let _ = writeln!(out, "Digest {} (same seed, same digest)", r.digest);
    for unmet in &r.expectations_unmet {
        let _ = writeln!(out, "  expected: {unmet}");
    }
    if let Some(dir) = kept {
        let _ = writeln!(out, "Kept at {}", dir.display());
    }
    out.push_str(&match r.exit_code() {
        0 => ui.paint(Style::Ok, "RESULT: as expected. This shows these synthetic scenarios behave as expected here; it is not a security assessment."),
        2 => ui.paint(Style::Warn, "RESULT: INCONCLUSIVE: no evidence to judge by."),
        _ => ui.paint(Style::Fail, "RESULT: NOT as expected (see above)."),
    });
    out
}

/// The throwaway stack, over HTTP.
struct Live {
    client: reqwest::Client,
    run: RunFile,
    bundle: PathBuf,
    operator_token: String,
    now: Mutex<DateTime<Utc>>,
}

impl Live {
    fn new(project: &Project, start: DateTime<Utc>) -> Result<Self, CliError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| CliError::new("cannot start an HTTP client", e))?;
        let operator_token = std::fs::read_to_string(project.bundle().join("operator.jwt"))
            .map_err(|e| CliError::new("cannot read the operator token", e))?
            .trim()
            .to_string();
        Ok(Self {
            client,
            run: RunFile::live(project)?,
            bundle: project.bundle(),
            operator_token,
            now: Mutex::new(start),
        })
    }

    fn token(&self, agent: &str) -> Result<String, String> {
        std::fs::read_to_string(self.bundle.join(format!("agents/{agent}.jwt")))
            .map(|t| t.trim().to_string())
            .map_err(|e| format!("token of {agent}: {e}"))
    }

    fn time(&self) -> DateTime<Utc> {
        *self
            .now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Stack for Live {
    async fn issue(&self, agent: &str, subject_ref: &str) -> Result<String, String> {
        let event_id = format!("sim-evt-{}", uuid::Uuid::new_v4());
        let event =
            kavach_devkit::sor_event(&self.bundle, &event_id, subject_ref, agent, self.time())
                .await?;
        // The SoR listener is rate-limited: wait out a 429 and send again.
        for _ in 0..60 {
            let response = self
                .client
                .post(format!("http://{}/v1/sor/events", self.run.sor))
                .json(&json!({ "event": event }))
                .send()
                .await
                .map_err(|e| e.to_string())?;
            let status = response.status().as_u16();
            let body: Value = response.json().await.unwrap_or(Value::Null);
            match status {
                200 | 201 => {
                    return body["mandate_id"]
                        .as_str()
                        .map(str::to_string)
                        .ok_or_else(|| "no mandate_id in the reply".into())
                }
                429 => tokio::time::sleep(Duration::from_secs(1)).await,
                _ => {
                    return Err(format!(
                        "{status} {}",
                        crate::problem::detail(status, &body)
                    ))
                }
            }
        }
        Err("the SoR listener stayed rate-limited".into())
    }

    async fn call(&self, agent: &str, tool: &str, body: Value) -> Result<(u16, Value), String> {
        let response = self
            .client
            .post(format!("http://{}/v1/tools/{tool}", self.run.agent))
            .bearer_auth(self.token(agent)?)
            .json(&body)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let status = response.status().as_u16();
        Ok((status, response.json().await.unwrap_or(Value::Null)))
    }

    async fn move_clock(&self, at: DateTime<Utc>) -> Result<(), String> {
        let response = self
            .client
            .post(format!("http://{}/v1/dev/clock", self.run.operator))
            .bearer_auth(&self.operator_token)
            .json(&json!({ "at": at }))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let status = response.status().as_u16();
        if status != 200 {
            let body: Value = response.json().await.unwrap_or(Value::Null);
            return Err(format!(
                "{status} {}",
                crate::problem::detail(status, &body)
            ));
        }
        *self
            .now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = at;
        Ok(())
    }
}

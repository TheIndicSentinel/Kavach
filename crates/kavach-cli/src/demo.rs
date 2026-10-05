//! `kavach demo`: what Kavach does, in about a minute, at any hour.
//!
//! A throwaway project in a temporary directory (deleted afterwards unless
//! `--keep`), a stack with a fixed development clock at 11:00 IST on free
//! loopback ports, and a scripted story told with the real commands, each
//! shown so it can be repeated. Every step checks that it behaved as
//! scripted: exit 0 if all did, 1 if one did not (a regression). Nothing
//! leaves this machine: loopback, the mock provider, synthetic numbers.

use std::fmt::Write as _;
use std::io::IsTerminal;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

use crate::output::{CliError, Status, Style, Ui};

/// The golden consent-mismatch credit request (synthetic data).
const CREDIT: &str = include_str!("../../../golden/finance/v0/credit_missing_consent.json");

/// The temporary project and its stack, cleaned up however the demo ends.
struct Scene {
    dir: PathBuf,
    stack: Option<Child>,
    /// The stack's pid, for the Ctrl-C handler (0: none).
    stack_pid: Arc<AtomicU32>,
    keep: bool,
}

impl Drop for Scene {
    fn drop(&mut self) {
        if let Some(mut stack) = self.stack.take() {
            // SIGTERM first, so `dev up` stops cleanly (and removes run.json).
            stop(stack.id());
            for _ in 0..40 {
                if stack.try_wait().ok().flatten().is_some() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            let _ = stack.kill();
            let _ = stack.wait();
            let _ = std::fs::remove_file(self.dir.join(".kavach/run.json"));
        }
        if !self.keep {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

/// One step of the story, as told and as checked.
struct Step {
    title: String,
    command: String,
    ok: bool,
    detail: String,
}

impl Scene {
    fn kavach(&self, args: &[&str]) -> Result<(i32, Value), CliError> {
        let exe = std::env::current_exe()
            .map_err(|e| CliError::new("cannot find the kavach binary", e))?;
        let out = Command::new(exe)
            .arg("-C")
            .arg(&self.dir)
            .arg("--json")
            .args(args)
            .env("NO_COLOR", "1")
            .stdin(Stdio::null())
            .output()
            .map_err(|e| CliError::new("cannot run kavach", e))?;
        Ok((
            out.status.code().unwrap_or(1),
            serde_json::from_slice(&out.stdout).unwrap_or(Value::Null),
        ))
    }

    fn start_stack(&mut self) -> Result<(), CliError> {
        let exe = std::env::current_exe()
            .map_err(|e| CliError::new("cannot find the kavach binary", e))?;
        let child = Command::new(exe)
            .arg("-C")
            .arg(&self.dir)
            .args(["dev", "up", "--clock", "11:00"])
            .env("NO_COLOR", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| CliError::new("cannot start the dev stack", e))?;
        self.stack_pid.store(child.id(), Ordering::SeqCst);
        self.stack = Some(child);
        let run = self.dir.join(".kavach/run.json");
        for _ in 0..240 {
            if run.is_file() {
                return Ok(());
            }
            if let Some(stack) = self.stack.as_mut() {
                if stack.try_wait().ok().flatten().is_some() {
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        Err(
            CliError::new("the dev stack did not start", "no run.json appeared")
                .fix("run `kavach demo --keep` and then `kavach doctor` in the printed directory"),
        )
    }
}

/// Asks a process to stop (SIGTERM on Unix); 0 is no process.
fn stop(pid: u32) {
    #[cfg(unix)]
    if pid != 0 {
        let _ = Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map_or(0, |a| a.port())
}

/// Moves the project's listeners to free loopback ports.
fn use_free_ports(dir: &Path) -> Result<(), CliError> {
    let path = dir.join(crate::project::FILE);
    let mut text = std::fs::read_to_string(&path)
        .map_err(|e| CliError::new("cannot read the demo project", e))?;
    for port in ["8080", "8091", "8090", "8443", "8444"] {
        text = text.replace(
            &format!("127.0.0.1:{port}\""),
            &format!("127.0.0.1:{}\"", free_port()),
        );
    }
    std::fs::write(&path, text).map_err(|e| CliError::new("cannot write the demo project", e))
}

/// A JSON value as a plain word (no quotes).
fn w(value: &Value) -> String {
    value
        .as_str()
        .map_or_else(|| value.to_string(), str::to_string)
}

fn reasons(reply: &Value) -> String {
    reply["reasons"]
        .as_array()
        .map(|r| {
            r.iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default()
}

/// Posts the golden credit request to `/v1/evaluate` (no CLI command makes
/// credit decisions); returns its evidence id.
async fn credit_decision(dir: &Path) -> Result<String, String> {
    let run: Value = serde_json::from_str(
        &std::fs::read_to_string(dir.join(".kavach/run.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let token =
        std::fs::read_to_string(dir.join(".kavach/operator.jwt")).map_err(|e| e.to_string())?;
    let fixture: Value = serde_json::from_str(CREDIT).map_err(|e| e.to_string())?;
    let mut request = fixture["request"].clone();
    let now = chrono::Utc::now().to_rfc3339();
    request["decision_time"] = now.clone().into();
    request["consent"]["timestamp"] = now.into();
    request["correlation_id"] = format!("demo-{}", uuid::Uuid::new_v4().simple()).into();
    let reply: Value = reqwest::Client::new()
        .post(format!(
            "http://{}/v1/evaluate",
            run["operator"].as_str().unwrap_or_default()
        ))
        .bearer_auth(token.trim())
        .json(&request)
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json()
        .await
        .map_err(|e| e.to_string())?;
    reply["evidence_id"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| format!("no evidence id: {reply}"))
}

/// Waits for Enter between steps, on a terminal only.
fn pause(step_mode: bool) {
    if step_mode && std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
    }
}

// One story, told in order: splitting it would scatter the script.
#[allow(clippy::too_many_lines)]
pub async fn run(ui: &Ui, keep: bool, step_mode: bool, attack: bool) -> Result<i32, CliError> {
    let dir = std::env::temp_dir().join(format!("kavach-demo-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(&dir)
        .map_err(|e| CliError::new(format!("cannot create {}", dir.display()), e))?;
    // Ctrl-C: the stack (same process group) stops on its own signal; the
    // throwaway project is removed here, unless kept.
    let stack_pid = Arc::new(AtomicU32::new(0));
    {
        let (dir, pid) = (dir.clone(), Arc::clone(&stack_pid));
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                stop(pid.load(Ordering::SeqCst));
                if !keep {
                    let _ = std::fs::remove_dir_all(&dir);
                }
                std::process::exit(130);
            }
        });
    }
    let mut scene = Scene {
        dir: dir.clone(),
        stack: None,
        stack_pid,
        keep,
    };
    let mut steps: Vec<Step> = Vec::new();
    let mut step = |title: &str, command: &str, ok: bool, detail: String| {
        steps.push(Step {
            title: title.into(),
            command: command.into(),
            ok,
            detail,
        });
    };

    // The project and the stack (not part of the story).
    let (code, _) = scene.kavach(&["init"])?;
    if code != 0 {
        return Err(CliError::new(
            "kavach init failed in the demo directory",
            code,
        ));
    }
    use_free_ports(&dir)?;
    scene.start_stack()?;

    let (_, issued) = scene.kavach(&["sor", "event"])?;
    let mandate = issued["mandate_id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    step(
        "A loan goes 30 days past due. Its system of record sends a signed event, and Kavach issues a mandate: what the collections agent may do, for whom, and when.",
        "kavach sor event",
        !mandate.is_empty(),
        format!("mandate {mandate}"),
    );
    pause(step_mode);

    let (_, call) = scene.kavach(&["call", "send_reminder", "--mandate", &mandate])?;
    let record = call["reply"]["record_id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let delivered = call["reply"]["outcome"] == "delivered";
    step(
        "At 11:00 IST the agent asks to send a reminder. Kavach allows it, resolves the borrower's number itself and delivers. The agent never sees the number.",
        &format!("kavach call send_reminder --mandate {mandate}"),
        call["decision"] == "PASS" && delivered,
        format!("{} ({}), record {record}", w(&call["decision"]), w(&call["reply"]["outcome"])),
    );
    pause(step_mode);

    let (_, why) = scene.kavach(&["why", &record])?;
    step(
        "Every decision is a signed record. `why` explains it from the record and checks its signature against local keys.",
        &format!("kavach why {record}"),
        why["verification"]["record_signature"] == "verified",
        format!(
            "record signature {} against {}",
            w(&why["verification"]["record_signature"]),
            w(&why["verification"]["against"])
        ),
    );
    pause(step_mode);

    let (_, raw) = scene.kavach(&[
        "call",
        "send_reminder",
        "--mandate",
        &mandate,
        "-p",
        "subject_ref=ref:borrower:9876543210",
    ])?;
    step(
        "The agent tries a raw phone number instead of the borrower's reference. Blocked, and the number is never recorded.",
        "kavach call send_reminder -p subject_ref=ref:borrower:9876543210",
        raw["decision"] == "BLOCK" && reasons(&raw["reply"]).contains("raw_identifier"),
        format!("{} ({})", w(&raw["decision"]), reasons(&raw["reply"])),
    );
    pause(step_mode);

    let (_, other) = scene.kavach(&[
        "call",
        "send_reminder",
        "--mandate",
        &mandate,
        "-p",
        "subject_ref=ref:borrower:B-1",
    ])?;
    step(
        "It tries another borrower under this mandate. Blocked: a mandate covers one borrower.",
        "kavach call send_reminder -p subject_ref=ref:borrower:B-1",
        other["decision"] == "BLOCK" && reasons(&other["reply"]).contains("subject-binding"),
        format!("{} ({})", w(&other["decision"]), reasons(&other["reply"])),
    );
    pause(step_mode);

    let (moved, _) = scene.kavach(&["dev", "clock", "20:30"])?;
    let (_, late) = scene.kavach(&["call", "send_reminder", "--mandate", &mandate])?;
    step(
        "The (development) clock moves to 20:30 IST. The same reminder is now blocked: contact is allowed only 08:00 to 19:00.",
        "kavach dev clock 20:30 && kavach call send_reminder",
        moved == 0
            && late["decision"] == "BLOCK"
            && reasons(&late["reply"]).contains("contact-window"),
        format!("{} ({})", w(&late["decision"]), reasons(&late["reply"])),
    );
    let (_, whatif) = scene.kavach(&["authorize", "send_reminder", "--at", "20:30"])?;
    let suggestion = whatif["counterfactuals"]["changes"][0]["suggestion"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    step(
        "Offline, `authorize` says what single change would pass. It records nothing, and agents never get this hint.",
        "kavach authorize send_reminder --at 20:30",
        suggestion.starts_with("at 08:00 IST"),
        format!("what-if under current policies: {suggestion}"),
    );
    pause(step_mode);

    match credit_decision(&dir).await {
        Ok(evidence) => {
            let (_, credit) = scene.kavach(&["why", &evidence])?;
            step(
                "A credit model's decision, with a consent given for another purpose. The policy says BLOCK, but the model runs in shadow mode, so the caller got PASS, and `why` says so.",
                &format!("kavach why {evidence}"),
                credit["policy_decision"] == "BLOCK"
                    && credit["returned_decision"] == "PASS"
                    && credit["shadow_hides_decision"] == true,
                format!(
                    "policy {}, returned {} ({} mode)",
                    w(&credit["policy_decision"]),
                    w(&credit["returned_decision"]),
                    w(&credit["governance_mode"])
                ),
            );
        }
        Err(e) => step(
            "A credit decision in shadow mode.",
            "POST /v1/evaluate",
            false,
            e,
        ),
    }
    pause(step_mode);

    if attack {
        let (code, report) = scene.kavach(&["attack"])?;
        let ran = report["outcomes"].as_array().map_or(0, Vec::len);
        step(
            "Finally, the catalog of known attacks that CI runs. Each must be refused, and nothing may be minted or delivered.",
            "kavach attack",
            code == 0 && report["breached"] == false,
            format!(
                "{ran} attacks, none got through (credentials minted {}, messages delivered {}); not a security assessment",
                w(&report["credentials_minted"]),
                w(&report["messages_delivered"])
            ),
        );
    }

    let all_ok = steps.iter().all(|s| s.ok);
    let mut human = format!(
        "{}\n{}\n\n",
        ui.paint(Style::Bold, "Kavach, in a minute"),
        ui.paint(
            Style::Dim,
            "A throwaway project, a dev stack on loopback with a fixed clock at 11:00 IST, synthetic data only."
        )
    );
    for (n, s) in steps.iter().enumerate() {
        let _ = writeln!(human, "{}. {}", n + 1, s.title);
        let _ = writeln!(human, "   {} {}", ui.paint(Style::Dim, "$"), s.command);
        let mark = if s.ok {
            ui.paint(Style::Ok, "→")
        } else {
            ui.paint(Style::Fail, "✗ not as scripted:")
        };
        let _ = writeln!(human, "   {mark} {}\n", s.detail);
    }
    let _ = write!(
        human,
        "{}",
        if all_ok {
            "Next: `kavach init` in a directory of your own, then `kavach doctor` and `kavach dev up`. See docs/DEVELOPING.md."
        } else {
            "A step did not behave as scripted: that is a regression worth reporting."
        }
    );
    if keep {
        let _ = write!(human, "\n\nThe demo project is kept at {}.", dir.display());
    }
    let data = json!({
        "steps": steps.iter().map(|s| json!({
            "title": s.title, "command": s.command, "ok": s.ok, "detail": s.detail,
        })).collect::<Vec<_>>(),
        "all_as_scripted": all_ok,
        "kept": keep.then(|| dir.display().to_string()),
    });
    drop(scene);
    Ok(ui.finish(
        "demo",
        if all_ok { Status::Ok } else { Status::Failed },
        &data,
        &human,
    ))
}

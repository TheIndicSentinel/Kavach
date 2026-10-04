//! `kavach attack`: the shared attack catalog (`kavach-attacks`) against
//! the running `kavach dev up`. The same catalog the acceptance tests run.
//!
//! Safety: loopback addresses only, dev keys only (a bundle with any other
//! key is refused), at most ten requests a second, and nothing beyond
//! ordinary calls: every attack aims at a refusal, so none consumes a
//! contact or sends a message. The BLOCK records it leaves carry request
//! ids starting with `attack-`.
//!
//! Exit 0 every attack refused as expected; 1 an attack succeeded (ground
//! truth: a credential minted or a message delivered) or was refused for
//! an unexpected reason (the catalog no longer matches the policies);
//! 2 inconclusive: the stack is unhealthy, its trusted time is unsynced,
//! or its clock is outside contact hours.

use std::fmt::Write as _;
use std::path::Path;
use std::time::Duration;

use kavach_attacks::{Attack, Report, Target, Verdict, CATALOG, CATALOG_VERSION, SUBJECT};
use serde_json::{json, Value};

use crate::output::{CliError, Status, Style, Ui};
use crate::project::Project;
use crate::run::RunFile;

/// Pause between requests: at most ten a second.
const PAUSE: Duration = Duration::from_millis(100);

/// `kavach attack --list`: the scope, without running anything.
pub fn list(ui: Ui) -> i32 {
    let attacks: Vec<Value> = CATALOG.iter().map(describe).collect();
    let mut human = format!(
        "Attack catalog version {CATALOG_VERSION}: {} attacks (nothing is run)\n\n",
        CATALOG.len()
    );
    for a in &CATALOG {
        let _ = writeln!(human, "  {:<30} {:<20} {}", a.id, a.group, a.tries);
    }
    let _ = write!(
        human,
        "\n{}",
        ui.paint(
            Style::Dim,
            "Each attack maps to a SECURITY_PROPERTIES.md row (and BYPASS_INVENTORY.md where one applies); see --json."
        )
    );
    ui.finish(
        "attack",
        Status::Ok,
        &json!({ "catalog_version": CATALOG_VERSION, "attacks": attacks, "ran": false }),
        &human,
    )
}

fn describe(a: &Attack) -> Value {
    json!({
        "id": a.id,
        "group": a.group,
        "tries": a.tries,
        "expected": a.expect,
        "security_property": a.security_property,
        "bypass": a.bypass,
    })
}

/// Why the run cannot be judged.
fn inconclusive(ui: Ui, why: &str, fix: &str) -> i32 {
    let human = format!(
        "{} {why}\n  {} {fix}\n\nNothing was attacked.",
        ui.paint(Style::Warn, "Inconclusive:"),
        ui.paint(Style::Dim, "fix:")
    );
    ui.finish(
        "attack",
        Status::Warnings,
        &json!({ "inconclusive": why, "fix": fix, "ran": false }),
        &human,
    )
}

/// The live stack, over HTTP.
struct Live {
    run: RunFile,
    agent: String,
    other_agent: String,
    operator: String,
    mandate: String,
    /// The event that issued the mandate, kept to replay it.
    event: String,
    http: reqwest::Client,
    provider: reqwest::Client,
}

impl Target for Live {
    fn agent_token(&self) -> String {
        self.agent.clone()
    }

    fn other_agent_token(&self) -> String {
        self.other_agent.clone()
    }

    fn operator_token(&self) -> String {
        self.operator.clone()
    }

    fn mandate(&self) -> String {
        self.mandate.clone()
    }

    async fn post_agent(
        &self,
        path: &str,
        headers: Vec<(String, String)>,
        body: Value,
    ) -> Result<(u16, Value), String> {
        let mut request = self
            .http
            .post(format!("http://{}{path}", self.run.agent))
            .json(&body);
        for (k, v) in headers {
            request = request.header(k, v);
        }
        let response = request.send().await.map_err(|e| e.to_string())?;
        let status = response.status().as_u16();
        Ok((status, response.json().await.unwrap_or(Value::Null)))
    }

    async fn get_operator(
        &self,
        path: &str,
        headers: Vec<(String, String)>,
    ) -> Result<u16, String> {
        let mut request = self.http.get(format!("http://{}{path}", self.run.operator));
        for (k, v) in headers {
            request = request.header(k, v);
        }
        let response = request.send().await.map_err(|e| e.to_string())?;
        Ok(response.status().as_u16())
    }

    async fn replay_sor_event(&self) -> Result<(u16, Value), String> {
        let response = self
            .http
            .post(format!("http://{}/v1/sor/events", self.run.sor))
            .json(&json!({ "event": self.event }))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let status = response.status().as_u16();
        Ok((status, response.json().await.unwrap_or(Value::Null)))
    }

    async fn post_provider(&self) -> Result<u16, String> {
        let response = self
            .provider
            .post(format!(
                "https://localhost:{}/v1/messages",
                self.run.provider.port()
            ))
            .json(&json!({ "to": SUBJECT, "template_id": "emi_reminder_v1" }))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        Ok(response.status().as_u16())
    }

    async fn delivered(&self) -> Result<usize, String> {
        let inbox: Value = self
            .http
            .get(format!("http://{}/v1/inbox", self.run.inspect))
            .send()
            .await
            .map_err(|e| e.to_string())?
            .json()
            .await
            .map_err(|e| e.to_string())?;
        inbox
            .as_array()
            .map(Vec::len)
            .ok_or_else(|| "the provider inbox is not a list".to_string())
    }

    async fn allowed(&self) -> Result<u64, String> {
        let text = self
            .http
            .get(format!("http://{}/metrics", self.run.operator))
            .bearer_auth(&self.operator)
            .send()
            .await
            .map_err(|e| e.to_string())?
            .text()
            .await
            .map_err(|e| e.to_string())?;
        Ok(kavach_attacks::allowed_calls(&text))
    }

    async fn pause(&self) {
        tokio::time::sleep(PAUSE).await;
    }
}

fn read(path: &Path) -> Result<String, CliError> {
    std::fs::read_to_string(path)
        .map(|s| s.trim().to_string())
        .map_err(|e| CliError::new(format!("cannot read {}", path.display()), e))
}

/// Refuses anything but a dev stack on loopback.
fn safe(project: &Project, run: &RunFile) -> Result<(), CliError> {
    for (name, addr) in [
        ("operator", run.operator),
        ("agent", run.agent),
        ("sor", run.sor),
        ("provider", run.provider),
        ("inspect", run.inspect),
    ] {
        if !addr.ip().is_loopback() {
            return Err(CliError::new(
                "kavach attack runs against loopback only",
                format!("the {name} listener is at {addr}"),
            ));
        }
    }
    let config: Value =
        serde_json::from_str(&read(&project.kavach_dir().join("mandate-config.json"))?)
            .map_err(|e| CliError::new("the mandate configuration is not JSON", e))?;
    let kid = config["signing_kid"].as_str().unwrap_or_default();
    if !kavach_ports::agent_evidence::is_dev_key(kid) {
        return Err(CliError::new(
            "kavach attack runs against development keys only",
            format!("the mandate key is {kid:?}, not a dev- key"),
        ));
    }
    Ok(())
}

fn client(ca: Option<&Path>) -> Result<reqwest::Client, CliError> {
    let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(10));
    if let Some(ca) = ca {
        let pem = std::fs::read(ca)
            .map_err(|e| CliError::new(format!("cannot read {}", ca.display()), e))?;
        let cert = reqwest::Certificate::from_pem(&pem)
            .map_err(|e| CliError::new("the dev CA is not valid", e))?;
        builder = builder.add_root_certificate(cert);
    }
    builder
        .build()
        .map_err(|e| CliError::new("cannot start an HTTP client", e))
}

pub async fn run(ui: &Ui, dir: &Path) -> Result<i32, CliError> {
    let project = Project::find(dir)?;
    let run = RunFile::live(&project)?;
    safe(&project, &run)?;
    let bundle = project.bundle();
    let http = client(None)?;

    // Health: the operator listener answers, and a legitimate pre-check (which
    // records nothing) is allowed. Otherwise the run cannot be judged.
    let operator = read(&bundle.join("operator.jwt"))?;
    let healthy = http
        .get(format!("http://{}/health", run.operator))
        .bearer_auth(&operator)
        .send()
        .await
        .is_ok_and(|r| r.status().is_success());
    if !healthy {
        return Ok(inconclusive(
            *ui,
            "the stack is unhealthy: /health does not answer 200",
            "restart `kavach dev up` and run `kavach doctor`",
        ));
    }
    let agent = read(&bundle.join("agents/collections-agent.jwt"))?;
    let event_id = format!("attack-evt-{}", uuid::Uuid::new_v4().simple());
    let event =
        kavach_devkit::sor_event(&bundle, &event_id, SUBJECT, "collections-agent", run.now())
            .await
            .map_err(|e| CliError::new("cannot sign the system-of-record event", e))?;
    let issued: Value = http
        .post(format!("http://{}/v1/sor/events", run.sor))
        .json(&json!({ "event": event }))
        .send()
        .await
        .map_err(|e| CliError::new("the SoR listener did not answer", e))?
        .json()
        .await
        .unwrap_or(Value::Null);
    let Some(mandate) = issued["mandate_id"].as_str().map(str::to_string) else {
        return Ok(inconclusive(
            *ui,
            &format!(
                "the stack is unhealthy: no mandate was issued ({})",
                issued["error"]
            ),
            "run `kavach doctor`",
        ));
    };
    let baseline: Value = http
        .post(format!("http://{}/v1/authorize", run.agent))
        .bearer_auth(&agent)
        .json(&json!({
            "tool": "send_reminder",
            "mandate_id": mandate,
            "request_id": "attack-baseline",
            "params": { "subject_ref": SUBJECT, "channel": "whatsapp", "template_id": "emi_reminder_v1" },
        }))
        .send()
        .await
        .map_err(|e| CliError::new("the agent listener did not answer", e))?
        .json()
        .await
        .unwrap_or(Value::Null);
    if baseline["decision"] != "PASS" {
        let reasons = baseline["reasons"].to_string();
        return Ok(if reasons.contains("trusted_time_unavailable") {
            inconclusive(
                *ui,
                "trusted time is unsynced: every decision would BLOCK for that reason",
                "sync the clock (or restart `kavach dev up`)",
            )
        } else if reasons.contains("contact-window") || reasons.contains("contact-hours-floor") {
            inconclusive(
                *ui,
                "the stack's clock is outside contact hours, so decisions would BLOCK for the window, not for each attack",
                "start the stack with `kavach dev up --at 11:00`",
            )
        } else {
            inconclusive(
                *ui,
                &format!("the stack is unhealthy: a legitimate call is not allowed ({reasons})"),
                "run `kavach doctor`",
            )
        });
    }

    let live = Live {
        agent,
        other_agent: read(&bundle.join("agents/translation-agent.jwt"))?,
        operator,
        mandate,
        event,
        http,
        provider: client(Some(&project.kavach_dir().join("tls/ca.pem")))?,
        run,
    };
    let report = kavach_attacks::run(&live, &CATALOG).await;
    Ok(finish(*ui, &report))
}

fn finish(ui: Ui, report: &Report) -> i32 {
    let mut human = format!(
        "Attack catalog version {} against the dev stack (loopback, dev keys)\n\n",
        report.catalog_version
    );
    for o in &report.outcomes {
        let word = match o.verdict {
            Verdict::Refused => ui.paint(Style::Ok, "refused"),
            Verdict::RefusedUnexpectedly => ui.paint(Style::Warn, "REFUSED, unexpected reason"),
            Verdict::Succeeded => ui.paint(Style::Fail, "SUCCEEDED"),
            Verdict::Error => ui.paint(Style::Warn, "error"),
        };
        let _ = writeln!(human, "  {:<30} {word}", o.id);
        if o.verdict != Verdict::Refused {
            let _ = writeln!(human, "  {:<30} {}", "", o.observed);
        }
    }
    let _ = writeln!(
        human,
        "\n  ground truth: {} credential(s) minted, {} message(s) delivered",
        report.credentials_minted, report.messages_delivered
    );
    let status = if report.all_refused_as_expected() {
        let _ = write!(
            human,
            "\nAll {} attacks were refused. That shows these known attacks fail; it is not a \
             security assessment (see docs/ACCEPTANCE.md and docs/THREAT_MODEL.md).",
            report.outcomes.len()
        );
        Status::Ok
    } else {
        human.push_str(if report.breached() {
            "\nAN ATTACK SUCCEEDED."
        } else {
            "\nEvery attack was refused, but not all as the catalog expects."
        });
        Status::Failed
    };
    let mut data = serde_json::to_value(report).unwrap_or(Value::Null);
    if let Some(map) = data.as_object_mut() {
        map.insert("ran".into(), Value::Bool(true));
        map.insert("breached".into(), Value::Bool(report.breached()));
    }
    ui.finish("attack", status, &data, &human)
}

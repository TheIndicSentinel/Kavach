//! The live path, against the running `kavach dev up`: `kavach sor event`
//! issues a mandate, `kavach call` goes through the gateway. Both are
//! recorded by the stack (the mandate store, the evidence chain) and use up
//! contact caps, unlike `kavach authorize`.

use std::fmt::Write as _;
use std::path::Path;
use std::time::Duration;

use kavach_dataplane::{RegistryTrust, ToolRegistry};
use kavach_keys::TrustedSigners;
use reqwest::StatusCode;
use serde_json::{json, Value};

use crate::authorize::{build_params, show, usage};
use crate::output::{CliError, Status, Style, Ui, EXIT_USAGE};
use crate::project::Project;
use crate::run::RunFile;

fn client() -> Result<reqwest::Client, CliError> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| CliError::new("cannot start an HTTP client", e))
}

/// A fresh id the stack has not seen (random, so retries are explicit).
fn fresh_id(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4())
}

/// A mandate the stack issued.
pub struct Issued {
    pub mandate_id: String,
    pub event_id: String,
    pub replayed: bool,
    pub exp: String,
}

/// Signs a synthetic system-of-record event on the stack's clock and sends
/// it to the SoR listener.
async fn issue(
    project: &Project,
    run: &RunFile,
    subject: &str,
    agent: &str,
    event_id: Option<&str>,
) -> Result<Issued, CliError> {
    let event_id = event_id.map_or_else(|| fresh_id("evt"), str::to_string);
    let event = kavach_devkit::sor_event(
        &project.bundle(),
        &event_id,
        subject,
        agent,
        run.stack_now(project).await?,
    )
    .await
    .map_err(|e| CliError::new("cannot sign the event", e))?;
    let response = client()?
        .post(format!("http://{}/v1/sor/events", run.sor))
        .json(&json!({ "event": event }))
        .send()
        .await
        .map_err(|e| CliError::new("the SoR listener did not answer", e))?;
    let status = response.status();
    let body: Value = response.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        return Err(crate::problem::error(
            "the stack refused the event",
            status.as_u16(),
            &body,
        ));
    }
    Ok(Issued {
        mandate_id: body["mandate_id"].as_str().unwrap_or_default().into(),
        event_id,
        replayed: body["replayed"].as_bool().unwrap_or(false),
        exp: body["exp"].as_str().unwrap_or_default().into(),
    })
}

/// `kavach sor event`.
pub async fn sor_event(
    ui: &Ui,
    dir: &Path,
    subject: &str,
    agent: &str,
    event_id: Option<&str>,
) -> Result<i32, CliError> {
    let project = Project::find(dir)?;
    let run = RunFile::live(&project)?;
    let issued = issue(&project, &run, subject, agent, event_id).await?;
    let data = json!({
        "mandate_id": issued.mandate_id,
        "event_id": issued.event_id,
        "subject": subject,
        "assigned_to": agent,
        "exp": issued.exp,
        "replayed": issued.replayed,
    });
    let human = format!(
        "{} mandate {}\n  for       {subject}, assigned to {agent}\n  event     {}{}\n  expires   {}\n\n{}",
        ui.paint(Style::Ok, if issued.replayed { "Existing" } else { "Issued" }),
        issued.mandate_id,
        issued.event_id,
        if issued.replayed { " (already seen: the same mandate)" } else { "" },
        issued.exp,
        ui.paint(
            Style::Dim,
            &format!("Next: kavach call send_reminder --mandate {}", issued.mandate_id)
        ),
    );
    Ok(ui.finish("sor event", Status::Ok, &data, &human))
}

/// What to call.
pub struct CallAsk<'a> {
    pub tool: &'a str,
    pub agent: &'a str,
    pub mandate: Option<&'a str>,
    /// Issue a mandate first (assigned to `agent`, for `subject`).
    pub issue_mandate: bool,
    pub subject: &'a str,
    pub params: &'a [(String, String)],
    pub request_id: Option<&'a str>,
}

pub(crate) fn registry(project: &Project) -> Result<ToolRegistry, CliError> {
    let kavach = project.kavach_dir();
    let signers = TrustedSigners::from_file(&kavach.join("tool-signers.json"))
        .map_err(|e| CliError::new("cannot read the tool signers", e.message))?;
    ToolRegistry::load(
        &kavach.join("tools/agent-tools.yaml"),
        RegistryTrust {
            signers: Some(&signers),
            pin: None,
            require_signature: true,
        },
    )
    .map_err(|e| {
        CliError::new("cannot load the tool registry", e.message).fix("run `kavach doctor`")
    })
}

/// `kavach call`.
pub async fn call(ui: &Ui, dir: &Path, ask: &CallAsk<'_>) -> Result<i32, CliError> {
    let project = Project::find(dir)?;
    let token_path = project.bundle().join(format!("agents/{}.jwt", ask.agent));
    let token = std::fs::read_to_string(&token_path).map_err(|_| {
        usage(
            format!("no access token for agent {}", ask.agent),
            format!("{} does not exist", token_path.display()),
        )
        .fix("use an agent from .kavach/agents/")
    })?;
    let registry = registry(&project)?;
    let Some(spec) = registry.tool(ask.tool) else {
        let known: Vec<_> = registry.tools().map(|t| t.name.as_str()).collect();
        return Err(usage(
            format!("no tool named {}", ask.tool),
            format!("the registry has {}", known.join(", ")),
        ));
    };
    let (params, defaulted) = build_params(spec, ask.subject, ask.params)?;
    let run = RunFile::live(&project)?;

    let issued = if ask.issue_mandate {
        Some(issue(&project, &run, ask.subject, ask.agent, None).await?)
    } else {
        None
    };
    let mandate_id = match (&issued, ask.mandate) {
        (Some(issued), _) => issued.mandate_id.clone(),
        (None, Some(id)) => id.to_string(),
        (None, None) => {
            return Err(
                usage("which mandate?", "no --mandate and no --issue-mandate")
                    .fix("pass --mandate <id> from `kavach sor event`, or --issue-mandate"),
            )
        }
    };
    let request_id = ask
        .request_id
        .map_or_else(|| fresh_id("req"), str::to_string);
    let response = client()?
        .post(format!("http://{}/v1/tools/{}", run.agent, ask.tool))
        .bearer_auth(token.trim())
        .json(&json!({ "mandate_id": mandate_id, "request_id": request_id, "params": params }))
        .send()
        .await
        .map_err(|e| CliError::new("the agent listener did not answer", e))?;
    let status = response.status();
    let reply: Value = response.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        let mut error = crate::problem::error(
            format!("the gateway refused the call ({})", status.as_u16()),
            status.as_u16(),
            &reply,
        );
        if status == StatusCode::BAD_REQUEST {
            error.code = EXIT_USAGE;
        }
        return Err(error);
    }

    let decision = reply["decision"].as_str().unwrap_or_default().to_string();
    let allowed = matches!(decision.as_str(), "PASS" | "ALERT");
    let data = json!({
        "decision": decision,
        "allowed": allowed,
        "reply": reply,
        "tool": ask.tool,
        "agent": ask.agent,
        "mandate_id": mandate_id,
        "issued_mandate": issued.as_ref().map(|i| json!({ "event_id": i.event_id, "exp": i.exp })),
        "params": params,
        "defaulted": defaulted,
        "recorded": reply.get("record_id").is_some(),
    });
    let status = if allowed { Status::Ok } else { Status::Failed };
    Ok(ui.finish("call", status, &data, &human(*ui, &data)))
}

fn human(ui: Ui, data: &Value) -> String {
    let reply = &data["reply"];
    let allowed = data["allowed"].as_bool().unwrap_or(false);
    let mut out = String::new();
    if let Some(issued) = data["issued_mandate"].as_object() {
        let _ = writeln!(
            out,
            "{} mandate {} (event {}, --issue-mandate)\n",
            ui.paint(Style::Dim, "Issued"),
            show(&data["mandate_id"]),
            show(&issued["event_id"])
        );
    }
    let _ = writeln!(
        out,
        "{}  {} by {}",
        ui.paint(
            if allowed { Style::Ok } else { Style::Fail },
            &show(&data["decision"])
        ),
        show(&data["tool"]),
        show(&data["agent"])
    );
    let reasons: Vec<_> = reply["reasons"]
        .as_array()
        .map(|r| r.iter().map(show).collect())
        .unwrap_or_default();
    let _ = writeln!(
        out,
        "  reasons   {}",
        if reasons.is_empty() {
            "none".into()
        } else {
            reasons.join(", ")
        }
    );
    let params: Vec<_> = data["params"]
        .as_object()
        .map(|p| p.iter().map(|(k, v)| format!("{k}={}", show(v))).collect())
        .unwrap_or_default();
    let _ = writeln!(
        out,
        "  request   {} ({})",
        params.join(" "),
        show(&reply["request_id"])
    );
    let _ = writeln!(out, "  mandate   {}", show(&data["mandate_id"]));
    if let Some(record) = reply["record_id"].as_str() {
        let _ = writeln!(out, "  record    {record}");
    }
    if let Some(outcome) = reply["outcome"].as_str() {
        let reason = reply["outcome_reason"].as_str().unwrap_or("-");
        let _ = writeln!(out, "  outcome   {outcome} ({reason})");
    }
    if reply["replayed"].as_bool() == Some(true) {
        let _ = writeln!(
            out,
            "  replayed  the stored result of an earlier identical call"
        );
    }
    let note = if data["recorded"].as_bool() == Some(true) {
        "Live: this call went through the gateway and is in the evidence chain."
    } else {
        "Live: this call went through the gateway; no record was returned."
    };
    let _ = write!(out, "\n{}", ui.paint(Style::Dim, note));
    out
}

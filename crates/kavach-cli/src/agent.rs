//! `kavach agent`: the kill switch from the command line (ADR-013).
//!
//! `status`, `restrict`, `quarantine` and `revoke` call the running stack's
//! operator API. Stopping takes one principal and only ever tightens;
//! `reinstate` **proposes** the change, and a second principal approves it
//! (it is never applied from here). Nothing here touches a store directly.

use std::fmt::Write as _;
use std::path::Path;

use kavach_domain::ReasonCode;
use serde_json::{json, Value};

use crate::authorize::usage;
use crate::output::{Status, Ui};
use crate::project::Project;
use crate::run::RunFile;
use crate::CliError;

fn reason_code(text: &str) -> Result<ReasonCode, CliError> {
    ReasonCode::parse(text).ok_or_else(|| {
        let known: Vec<&str> = ReasonCode::ALL.iter().map(|c| c.as_str()).collect();
        usage(
            format!("{text:?} is not a reason code"),
            format!("use one of: {}", known.join(", ")),
        )
    })
}

fn read_token(project: &Project) -> Result<String, CliError> {
    std::fs::read_to_string(project.bundle().join("operator.jwt"))
        .map(|t| t.trim().to_string())
        .map_err(|e| CliError::new("cannot read the operator token", e))
}

/// The operator listener's answer, or the error it gave, in the CLI's terms.
async fn finish_call(response: reqwest::Response, what: &str) -> Result<(u16, Value), CliError> {
    let status = response.status().as_u16();
    let body: Value = response.json().await.unwrap_or(Value::Null);
    if (200..300).contains(&status) {
        return Ok((status, body));
    }
    let error = crate::problem::error(
        format!("the stack refused: {what} ({status})"),
        status,
        &body,
    );
    Err(match status {
        401 | 403 => error.fix("run it as an operator principal that may do this"),
        404 => error.fix("agent ids are matched exactly against the passports in this project"),
        429 => error.fix("stops are rate limited across the process; wait a moment"),
        _ => error,
    })
}

fn state_line(body: &Value) -> String {
    let mut line = format!(
        "{}: {} (change {})",
        body["agent_id"].as_str().unwrap_or("?"),
        body["state"].as_str().unwrap_or("?"),
        body["change_no"]
    );
    if let Some(by) = body["changed_by"].as_str() {
        let _ = write!(line, ", by {by}");
    }
    if let Some(approver) = body["approved_by"].as_str() {
        let _ = write!(line, ", approved by {approver}");
    }
    if let Some(code) = body["reason_code"].as_str() {
        let _ = write!(line, ", {code}");
    }
    line
}

/// `kavach agent status <agent>`.
pub async fn status(ui: &Ui, dir: &Path, agent: &str) -> Result<i32, CliError> {
    let project = Project::find(dir)?;
    let run = RunFile::live(&project)?;
    let response = reqwest::Client::new()
        .get(format!("http://{}/v1/agents/{agent}", run.operator))
        .bearer_auth(read_token(&project)?)
        .send()
        .await
        .map_err(|e| CliError::new("the operator listener did not answer", e))?;
    let (_, body) = finish_call(response, "reading the agent's state").await?;
    Ok(ui.finish("agent status", Status::Ok, &body, &state_line(&body)))
}

/// `kavach agent restrict | quarantine | revoke <agent>`.
pub async fn stop(
    ui: &Ui,
    dir: &Path,
    agent: &str,
    verb: &str,
    reason: &str,
    note: &str,
) -> Result<i32, CliError> {
    let code = reason_code(reason)?;
    let project = Project::find(dir)?;
    let run = RunFile::live(&project)?;
    let response = reqwest::Client::new()
        .post(format!("http://{}/v1/agents/{agent}/{verb}", run.operator))
        .bearer_auth(read_token(&project)?)
        .json(&json!({ "reason_code": code.as_str(), "note": note }))
        .send()
        .await
        .map_err(|e| CliError::new("the operator listener did not answer", e))?;
    let (_, body) = finish_call(response, &format!("{verb} {agent}")).await?;
    let mut human = state_line(&body);
    if body["applied"] == json!(false) {
        human.push_str("\nnothing changed: it was already in that state");
    }
    if body["record"] == json!("pending") {
        human.push_str("\nits evidence record is pending (the reconciler writes it)");
    }
    if let Some(revoked) = body["mandates_revoked"].as_array() {
        let _ = write!(human, "\nmandates revoked: {}", revoked.len());
    }
    if body["mandates_not_revoked"]
        .as_array()
        .is_some_and(|a| !a.is_empty())
    {
        human.push_str("\nsome mandates were not revoked: run the same command again to finish");
    }
    Ok(ui.finish(&format!("agent {verb}"), Status::Ok, &body, &human))
}

/// `kavach agent reinstate <agent>`: proposes the change; another principal
/// approves it.
pub async fn reinstate(
    ui: &Ui,
    dir: &Path,
    agent: &str,
    to: &str,
    reason: &str,
    note: &str,
) -> Result<i32, CliError> {
    let code = reason_code(reason)?;
    if !matches!(to, "active" | "restricted") {
        return Err(usage(
            format!("{to:?} is not a state to reinstate to"),
            "use active or restricted",
        ));
    }
    let project = Project::find(dir)?;
    let run = RunFile::live(&project)?;
    let response = reqwest::Client::new()
        .post(format!("http://{}/v1/change-requests", run.operator))
        .bearer_auth(read_token(&project)?)
        .json(&json!({
            "kind": "reinstate_agent",
            "params": { "agent_id": agent, "to": to, "reason_code": code.as_str(), "note": note },
        }))
        .send()
        .await
        .map_err(|e| CliError::new("the operator listener did not answer", e))?;
    let (_, body) = finish_call(response, &format!("reinstate {agent}"))
        .await
        .map_err(|e| {
            e.fix("a revoked agent cannot be reinstated: issue a new passport with a new agent id")
        })?;
    let human = format!(
        "proposed: change request {}\n{agent} stays stopped until a second principal approves it:\n  POST /v1/change-requests/{}/approve  with change_digest {}",
        body["id"].as_str().unwrap_or("?"),
        body["id"].as_str().unwrap_or("?"),
        body["change_digest"].as_str().unwrap_or("?"),
    );
    Ok(ui.finish("agent reinstate", Status::Ok, &body, &human))
}

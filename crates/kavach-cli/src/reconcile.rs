//! `kavach reconcile`: the lender's closed loans against the live authority
//! Kavach holds (snapshot reconciliation, ADR-012 addendum).
//!
//! It reads a JSON file the lender (or a fixture) supplies, sends it to the
//! running stack's operator API and prints what was found. It **reports and
//! revokes nothing**: a finding means a payment or dispute event did not
//! arrive, and the remedy is to resend the signed event or stop the agent.

use std::fmt::Write as _;
use std::path::Path;

use serde_json::Value;

use crate::output::{Status, Ui};
use crate::project::Project;
use crate::run::RunFile;
use crate::CliError;

/// `kavach reconcile <file>`. Exit 0 when no closed loan holds live
/// authority, 1 when one does.
pub async fn run(ui: &Ui, dir: &Path, file: &Path) -> Result<i32, CliError> {
    let text = std::fs::read_to_string(file)
        .map_err(|e| CliError::new(format!("cannot read {}", file.display()), e))?;
    let body: Value = serde_json::from_str(&text).map_err(|e| {
        CliError::new(format!("{} is not valid JSON", file.display()), e)
            .fix("the file is {\"system\": \"lms\", \"records\": [{\"record_ref\": ..., \"state\": \"paid\" | \"disputed\", \"closed_at\": <RFC 3339>}]}")
    })?;
    let project = Project::find(dir)?;
    let run = RunFile::live(&project)?;
    let token = std::fs::read_to_string(project.bundle().join("operator.jwt"))
        .map(|t| t.trim().to_string())
        .map_err(|e| CliError::new("cannot read the operator token", e))?;
    let response = reqwest::Client::new()
        .post(format!(
            "http://{}/v1/reconciliation/closed-records",
            run.operator
        ))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .map_err(|e| CliError::new("the operator listener did not answer", e))?;
    let status = response.status().as_u16();
    let reply: Value = response.json().await.unwrap_or(Value::Null);
    if !(200..300).contains(&status) {
        return Err(crate::problem::error(
            format!("the stack refused the reconciliation ({status})"),
            status,
            &reply,
        )
        .fix("run it as an operator principal in `admins`; at most six a minute"));
    }

    let mismatches = reply["mismatches"].as_u64().unwrap_or(0);
    let information = reply["information"].as_u64().unwrap_or(0);
    let mut human = format!(
        "{} loans checked: {mismatches} with authority that should have been revoked, {information} to confirm",
        reply["checked"]
    );
    for f in reply["findings"].as_array().into_iter().flatten() {
        let _ = write!(
            human,
            "\n  {} {} ({}): mandate {} held by {}, issued {}",
            if f["kind"] == "should_have_been_revoked" {
                "MISMATCH"
            } else {
                "confirm "
            },
            f["record_ref"].as_str().unwrap_or("?"),
            f["state"].as_str().unwrap_or("?"),
            f["mandate_id"].as_str().unwrap_or("?"),
            f["holder"].as_str().unwrap_or("?"),
            f["issued_at"].as_str().unwrap_or("?"),
        );
    }
    if mismatches > 0 {
        let _ = write!(human, "\n{}", reply["remedy"].as_str().unwrap_or_default());
    }
    let status = if mismatches > 0 {
        Status::Failed
    } else {
        Status::Ok
    };
    Ok(ui.finish("reconcile", status, &reply, &human))
}

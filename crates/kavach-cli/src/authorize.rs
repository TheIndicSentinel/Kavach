//! `kavach authorize`: what the gateway would decide for a tool call, offline.
//!
//! Runs the authorization core in pre-check mode, in this process, on the
//! project's bundle: the same mandate checks, agent policies and tool
//! registry as the gateway. The mandate is issued in memory from a
//! synthetic system-of-record event and dropped on exit. Nothing is
//! recorded and no contact is reserved, so the time (`--at`), the contacts
//! already made (`--contacts-today`) and the parameters can be varied
//! freely. Exit 0 if the call would be allowed, 1 if not.

use std::fmt::Write as _;
use std::path::Path;
use std::sync::Arc;

use chrono::{DateTime, FixedOffset, Utc};
use kavach_api::dataplane::{TestClock, WhatIf};
use kavach_dataplane::tools::{ParamKind, ToolSpec};
use kavach_dataplane::ToolRequest;
use kavach_ports::agent_evidence::is_allow;
use serde_json::{json, Map, Value};

use crate::dev::{dataplane_config, parse_at, StartedAt};
use crate::output::{CliError, Status, Style, Ui, EXIT_USAGE};
use crate::project::Project;

/// The bundle's synthetic borrower (`references.json`).
pub const DEFAULT_SUBJECT: &str = "ref:borrower:B-9382";
/// The agent the dev mandate template assigns.
pub const DEFAULT_AGENT: &str = "collections-agent";

/// What to decide.
pub struct Ask<'a> {
    pub tool: &'a str,
    pub agent: &'a str,
    /// The borrower the synthetic event assigns (and the default
    /// `subject_ref`).
    pub subject: &'a str,
    /// The agent the synthetic event assigns the borrower to.
    pub mandate_for: &'a str,
    pub params: &'a [(String, String)],
    pub at: Option<&'a str>,
    pub contacts_today: u32,
}

pub(crate) fn usage(what: impl Into<String>, why: impl std::fmt::Display) -> CliError {
    let mut error = CliError::new(what, why);
    error.code = EXIT_USAGE;
    error
}

/// `k=v` (for clap).
pub fn parse_param(text: &str) -> Result<(String, String), String> {
    text.split_once('=')
        .filter(|(k, _)| !k.is_empty())
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .ok_or_else(|| "use NAME=VALUE, e.g. --param channel=sms".to_string())
}

/// The tool's parameters: those given, typed by the registry, and a
/// default for each required one left out. Returns the names defaulted.
pub(crate) fn build_params(
    spec: &ToolSpec,
    subject: &str,
    given: &[(String, String)],
) -> Result<(Map<String, Value>, Vec<String>), CliError> {
    let mut params = Map::new();
    for (name, value) in given {
        let Some(param) = spec.params.get(name) else {
            let known: Vec<_> = spec.params.keys().map(String::as_str).collect();
            return Err(usage(
                format!("{} has no parameter {name}", spec.name),
                format!("its parameters are {}", known.join(", ")),
            ));
        };
        let typed = match param.kind {
            ParamKind::Integer => value.parse::<i64>().map(Value::from).map_err(|_| {
                usage(
                    format!("{name} must be an integer"),
                    format!("got {value:?}"),
                )
            })?,
            ParamKind::FieldSet => Value::from(
                value
                    .split(',')
                    .filter(|f| !f.is_empty())
                    .collect::<Vec<_>>(),
            ),
            ParamKind::CapabilityRef | ParamKind::Enum => Value::from(value.as_str()),
        };
        params.insert(name.clone(), typed);
    }
    let mut defaulted = Vec::new();
    for (name, param) in &spec.params {
        if params.contains_key(name) || param.optional {
            continue;
        }
        let value = match param.kind {
            ParamKind::CapabilityRef => Value::from(subject),
            ParamKind::Integer => Value::from(param.min.unwrap_or(0)),
            ParamKind::Enum => Value::from(param.values.first().cloned().unwrap_or_default()),
            ParamKind::FieldSet => Value::from(
                param
                    .values
                    .first()
                    .cloned()
                    .into_iter()
                    .collect::<Vec<_>>(),
            ),
        };
        params.insert(name.clone(), value);
        defaulted.push(name.clone());
    }
    Ok((params, defaulted))
}

fn ist(t: DateTime<Utc>) -> String {
    FixedOffset::east_opt(5 * 3600 + 1800)
        .map(|o| t.with_timezone(&o).format("%H:%M IST").to_string())
        .unwrap_or_default()
}

pub(crate) fn show(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Array(items) => items.iter().map(show).collect::<Vec<_>>().join(","),
        other => other.to_string(),
    }
}

/// The text for people, from the JSON document (one source for both).
fn human(ui: Ui, data: &Value) -> String {
    let text = |key: &str| data[key].as_str().unwrap_or_default().to_string();
    let list = |key: &str| {
        data[key]
            .as_array()
            .map(|items| items.iter().map(show).collect::<Vec<_>>())
            .unwrap_or_default()
    };
    let allowed = data["allowed"].as_bool().unwrap_or(false);
    let mut out = format!(
        "{}  {} by {} at {}\n",
        ui.paint(
            if allowed { Style::Ok } else { Style::Fail },
            &text("decision")
        ),
        text("tool"),
        text("agent"),
        text("at"),
    );
    let reasons = list("reasons");
    let reasons = if reasons.is_empty() {
        "none".to_string()
    } else {
        reasons.join(", ")
    };
    let _ = writeln!(out, "  reasons   {reasons}");
    let shown: Vec<_> = data["params"]
        .as_object()
        .map(|params| {
            params
                .iter()
                .map(|(k, v)| format!("{k}={}", show(v)))
                .collect()
        })
        .unwrap_or_default();
    let _ = write!(out, "  request   {}", shown.join(" "));
    let defaulted = list("defaulted");
    if !defaulted.is_empty() {
        let note = format!("(defaulted: {})", defaulted.join(", "));
        let _ = write!(out, " {}", ui.paint(Style::Dim, &note));
    }
    let mandate = &data["mandate"];
    let _ = writeln!(
        out,
        "\n  mandate   what-if: issued in memory for {} assigned to {}",
        show(&mandate["subject"]),
        show(&mandate["assigned_to"])
    );
    let _ = writeln!(out, "  contacts  {} today", data["contacts_today"]);
    let _ = write!(
        out,
        "\n{}",
        ui.paint(
            Style::Dim,
            "What-if only: nothing was recorded and no contact was reserved."
        )
    );
    out
}

pub async fn run(ui: &Ui, dir: &Path, ask: &Ask<'_>) -> Result<i32, CliError> {
    let project = Project::find(dir)?;
    let at = match ask.at {
        Some(text) => parse_at(text)?,
        None => Utc::now(),
    };
    let clock = TestClock(Arc::new(StartedAt::new(at)));
    let what_if = WhatIf::build(&dataplane_config(&project, None), clock, ask.contacts_today)
        .await
        .map_err(|e| {
            CliError::new("cannot load the project's bundle", e).fix("run `kavach doctor`")
        })?;

    let Some(spec) = what_if.tools().tool(ask.tool) else {
        let known: Vec<_> = what_if.tools().tools().map(|t| t.name.as_str()).collect();
        return Err(usage(
            format!("no tool named {}", ask.tool),
            format!("the registry has {}", known.join(", ")),
        ));
    };
    let (params, defaulted) = build_params(spec, ask.subject, ask.params)?;

    let event = kavach_devkit::sor_event(
        &project.bundle(),
        "what-if-1",
        ask.subject,
        ask.mandate_for,
        at,
    )
    .await
    .map_err(|e| CliError::new("cannot sign the synthetic event", e))?;
    let mandate_id = what_if.issue(&event).await.map_err(|e| {
        usage("no mandate for this borrower and agent", e).fix(format!(
            "the dev template assigns borrowers to {DEFAULT_AGENT}"
        ))
    })?;

    let decided = what_if
        .precheck(
            ask.agent,
            ask.tool,
            ToolRequest {
                mandate_id,
                request_id: "what-if-1".into(),
                params: params.clone(),
            },
        )
        .await
        .map_err(|e| usage("the gateway would refuse this request", e))?;

    let allowed = is_allow(decided.decision);
    let decision = serde_json::to_value(decided.decision)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default();
    let status = if allowed { Status::Ok } else { Status::Failed };
    let data = json!({
        "decision": decision,
        "allowed": allowed,
        "reasons": decided.reasons,
        "tool": ask.tool,
        "agent": ask.agent,
        "at": ist(at),
        "contacts_today": ask.contacts_today,
        "params": params,
        "defaulted": defaulted,
        "mandate": {
            "what_if": true,
            "subject": ask.subject,
            "assigned_to": ask.mandate_for,
        },
        "recorded": false,
    });

    let human = human(*ui, &data);
    Ok(ui.finish("authorize", status, &data, &human))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn params_are_split_at_the_first_equals_sign() {
        assert_eq!(
            parse_param("subject_ref=ref:a=b").unwrap(),
            ("subject_ref".into(), "ref:a=b".into())
        );
        assert!(parse_param("channel").is_err());
        assert!(parse_param("=sms").is_err());
    }
}

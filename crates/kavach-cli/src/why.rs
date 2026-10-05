//! `kavach why <record-id>`: what an agent decision record says, in words.
//!
//! - Live: reads the record from the running `kavach dev up` (operator
//!   endpoint, audited), then checks the record's own hash and signature.
//!   That proves the record is intact and signed, **not** that the chain
//!   around it is complete.
//! - `--bundle <dir>`: verifies an evidence bundle offline (the
//!   `verify-bundle` checks: files, chain, checkpoints) and explains the
//!   record from it. No network. Exit 2 if the bundle verifies but
//!   something is not protected (as `verify-bundle`).
//!
//! Trusted keys always come from local configuration (`--keys`, default
//! the project's `.kavach/auditor/trusted-keys.json`), never from the
//! server or the bundle being checked.

use std::fmt::Write as _;
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::{DateTime, FixedOffset, Utc};
use kavach_domain::reasons::explain;
use kavach_evidence_cli::verify::{load_trusted_keys, verify_dir, VerifyRequest};
use kavach_ports::agent_evidence::{
    check_record_signature, is_dev_key, outcome_verifies, AgentDecisionRecord, OutcomeRecord,
};
use kavach_ports::bundle::RECORDS_FILE;
use serde_json::{json, Value};

use crate::authorize::usage;
use crate::output::{CliError, Digest, Status, Style, Ui};
use crate::project::Project;
use crate::run::RunFile;

/// Where the record came from, and what was verified about it.
enum Source {
    /// The running stack: only the record's own signature is checked.
    Live,
    /// A bundle that verified: the chain around the record was checked.
    Bundle { dir: PathBuf, warnings: Vec<String> },
}

fn default_keys(dir: &Path) -> Result<PathBuf, CliError> {
    let project = Project::find(dir)
        .map_err(|e| e.fix("pass --keys <trusted-keys.json>, or run inside a Kavach project"))?;
    Ok(project.bundle().join("auditor/trusted-keys.json"))
}

async fn fetch_live(
    dir: &Path,
    record_id: &str,
) -> Result<(AgentDecisionRecord, Option<OutcomeRecord>), CliError> {
    let project = Project::find(dir)?;
    let run = RunFile::live(&project)?;
    let token = std::fs::read_to_string(project.bundle().join("operator.jwt"))
        .map_err(|e| CliError::new("cannot read the operator token", e))?;
    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| CliError::new("cannot start an HTTP client", e))?
        .get(format!(
            "http://{}/v1/agent-decisions/{record_id}",
            run.operator
        ))
        .bearer_auth(token.trim())
        .send()
        .await
        .map_err(|e| CliError::new("the operator listener did not answer", e))?;
    let status = response.status();
    let body: Value = response.json().await.unwrap_or(Value::Null);
    let code = status.as_u16();
    let error = crate::problem::detail(code, &body);
    match code {
        200 => {}
        404 => {
            return Err(
                crate::problem::error(format!("no record {record_id}"), code, &body).fix(
                    "check the id from `kavach call`; the memory store forgets records when \
                 `kavach dev up` stops (set [database] in kavach.toml to keep them)",
                ),
            )
        }
        400 => return Err(usage(format!("{record_id} is not a record id"), error)),
        _ => {
            return Err(crate::problem::error(
                format!("the stack refused the read ({code})"),
                code,
                &body,
            ))
        }
    }
    let record: AgentDecisionRecord = serde_json::from_value(body["record"].clone())
        .map_err(|e| CliError::new("the stack returned a record that does not parse", e))?;
    let outcome: Option<OutcomeRecord> =
        serde_json::from_value(body["outcome"].clone()).unwrap_or(None);
    Ok((record, outcome))
}

/// Verifies the bundle, then finds the record in it.
fn from_bundle(
    bundle: &Path,
    keys: &Path,
    dev: bool,
    record_id: &str,
) -> Result<(AgentDecisionRecord, Vec<String>), CliError> {
    let report = verify_dir(&VerifyRequest {
        bundle,
        keys,
        expect_checkpoint: None,
        dev,
        now: Utc::now(),
    })
    .map_err(|e| {
        CliError::new(
            format!("the bundle {} does not verify", bundle.display()),
            e,
        )
        .fix("run `kavach-evidence verify-bundle` for the full report")
    })?;
    let warnings = report
        .not_protected()
        .iter()
        .map(|f| format!("{}: {}", f.kind, f.detail))
        .collect();
    let file = std::fs::File::open(bundle.join(RECORDS_FILE))
        .map_err(|e| CliError::new(format!("cannot read {RECORDS_FILE}"), e))?;
    for line in std::io::BufReader::new(file).lines() {
        let line = line.map_err(|e| CliError::new(format!("cannot read {RECORDS_FILE}"), e))?;
        if !line.contains(record_id) {
            continue;
        }
        let record: AgentDecisionRecord = serde_json::from_str(&line)
            .map_err(|e| CliError::new(format!("{RECORDS_FILE} has a bad line"), e))?;
        if record.payload.record_id == record_id {
            return Ok((record, warnings));
        }
    }
    Err(CliError::new(
        format!("no record {record_id} in the bundle"),
        format!("{} has no such record", bundle.display()),
    ))
}

/// For a decision blocked by business constraints only, the offline
/// `kavach authorize` command to explore it with. Placeholders only: the
/// record holds no raw values, and none are printed.
fn explore(
    dir: &Path,
    action: &str,
    decision: kavach_domain::Decision,
    signals: &[String],
) -> Option<String> {
    if kavach_ports::agent_evidence::is_allow(decision)
        || crate::counterfactual::withheld(signals).is_some()
    {
        return None;
    }
    let params: Vec<String> = Project::find(dir)
        .ok()
        .and_then(|project| crate::live::registry(&project).ok())
        .and_then(|registry| {
            registry.for_action(action).map(|spec| {
                spec.params
                    .keys()
                    .map(|name| format!("-p {name}=<value>"))
                    .collect()
            })
        })
        .unwrap_or_else(|| vec!["-p <name>=<value>".into()]);
    Some(format!(
        "kavach authorize {action} {} --at <HH:MM> --contacts-today <n>",
        params.join(" ")
    ))
}

fn ist(t: DateTime<Utc>) -> String {
    FixedOffset::east_opt(5 * 3600 + 1800)
        .map(|o| {
            t.with_timezone(&o)
                .format("%H:%M IST on %d %b %Y")
                .to_string()
        })
        .unwrap_or_default()
}

fn word(value: impl serde::Serialize) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

pub async fn run(
    ui: &Ui,
    dir: &Path,
    record_id: &str,
    bundle: Option<&Path>,
    keys: Option<&Path>,
) -> Result<i32, CliError> {
    let keys_path = match keys {
        Some(k) => k.to_path_buf(),
        None => default_keys(dir)?,
    };
    // Keys must never come from what is being checked: the bundle, or the
    // server's own configuration directory.
    let checked_dir = match bundle {
        Some(b) => b.to_path_buf(),
        None => Project::find(dir)?.kavach_dir(),
    };
    let trusted = load_trusted_keys(&keys_path, &checked_dir)
        .map_err(|e| CliError::new("cannot load the trusted keys", e))?;
    let dev_keys = trusted.keys.keys().any(|k| is_dev_key(k));

    let (record, outcome, source) = if let Some(b) = bundle {
        let (record, warnings) = from_bundle(b, &keys_path, dev_keys, record_id)?;
        let source = Source::Bundle {
            dir: b.to_path_buf(),
            warnings,
        };
        (record, None, source)
    } else {
        let (record, outcome) = fetch_live(dir, record_id).await?;
        (record, outcome, Source::Live)
    };

    // The record on its own, against local keys.
    let signature = check_record_signature(&record, &trusted.keys, dev_keys);
    let against = if is_dev_key(&record.payload.key_id) {
        "dev keys"
    } else {
        "trusted keys"
    };
    let outcome_ok = outcome.as_ref().map(|o| outcome_verifies(o, &trusted.keys));
    let verified = signature.is_ok() && outcome_ok != Some(false);

    let p = &record.payload;
    let reasons: Vec<Value> = p
        .signals
        .iter()
        .map(|code| match explain(code) {
            Some(r) => json!({ "code": code, "meaning": r.meaning, "fix": r.fix }),
            None => json!({ "code": code, "meaning": null, "fix": null }),
        })
        .collect();
    let chain = match &source {
        Source::Live => {
            json!({ "checked": false, "note": "a single record proves nothing about the chain; verify a bundle with --bundle" })
        }
        Source::Bundle { dir, warnings } => {
            json!({ "checked": true, "bundle": dir, "not_protected": warnings })
        }
    };
    let data = json!({
        "record_id": p.record_id,
        "decision": word(p.returned_decision),
        "policy_decision": word(p.policy_decision),
        "action": p.action,
        "agent": p.actor.agent_id,
        "at": p.ts,
        "reasons": reasons,
        "mandate": { "id": p.mandate_id, "chain": p.chain, "purpose": p.purpose, "consent_refs": p.consent_refs },
        "subject_pseudonym": p.subject_pseudonym,
        "policy_versions": p.policy_versions,
        "time_sync": p.time_sync,
        "send_by": p.send_by,
        "credential_id": p.credential_id,
        "outcome": outcome.as_ref().map(|o| json!({ "outcome": o.outcome.as_str(), "reason": o.reason, "signature_verified": outcome_ok })),
        "explore": explore(dir, &p.action, p.returned_decision, &p.signals),
        "verification": {
            "record_signature": if signature.is_ok() { "verified" } else { "failed" },
            "against": against,
            "error": signature.as_ref().err().map(ToString::to_string),
            "chain": chain,
        },
    });
    // Warnings: the bundle verified, but something is not protected.
    let status = match &source {
        _ if !verified => Status::Failed,
        Source::Bundle { warnings, .. } if !warnings.is_empty() => Status::Warnings,
        _ => Status::Ok,
    };
    Ok(ui.finish("why", status, &data, &human(*ui, &data, &record)))
}

/// The record and chain lines: what was verified, and what was not.
fn verification_lines(ui: Ui, v: &Value, record_id: &str, out: &mut String) {
    let s = |v: &Value| v.as_str().unwrap_or("-").to_string();
    let verified = s(&v["record_signature"]) == "verified";
    let _ = writeln!(
        *out,
        "  record    {}  {}",
        record_id,
        if verified {
            ui.paint(
                Style::Ok,
                &format!("record signature verified against {}", s(&v["against"])),
            )
        } else {
            ui.paint(
                Style::Fail,
                &format!("record signature FAILED: {}", s(&v["error"])),
            )
        }
    );
    match v["chain"]["checked"].as_bool() {
        Some(true) => {
            let _ = writeln!(
                *out,
                "  chain     the bundle verified (files, chain, checkpoints)"
            );
            for w in v["chain"]["not_protected"].as_array().into_iter().flatten() {
                let _ = writeln!(
                    *out,
                    "            {} {}",
                    ui.paint(Style::Warn, "not protected:"),
                    s(w)
                );
            }
        }
        _ => {
            let _ = writeln!(
                *out,
                "  chain     {}",
                ui.paint(
                    Style::Dim,
                    "not checked: one record proves nothing about the chain (use --bundle)"
                )
            );
        }
    }
}

fn human(ui: Ui, data: &Value, record: &AgentDecisionRecord) -> String {
    let p = &record.payload;
    let s = |v: &Value| v.as_str().unwrap_or("-").to_string();
    let allowed = matches!(s(&data["decision"]).as_str(), "PASS" | "ALERT");
    let mut out = format!(
        "{}  {} by {} at {}\n",
        ui.paint(
            if allowed { Style::Ok } else { Style::Fail },
            &s(&data["decision"])
        ),
        p.action,
        p.actor.agent_id,
        ist(p.ts)
    );
    verification_lines(ui, &data["verification"], &p.record_id, &mut out);
    let _ = writeln!(out, "  reasons");
    for r in data["reasons"].as_array().into_iter().flatten() {
        let meaning = r["meaning"]
            .as_str()
            .unwrap_or("(not in the reason catalog)");
        let _ = writeln!(out, "    {:<26} {meaning}", s(&r["code"]));
        if let Some(fix) = r["fix"].as_str().filter(|f| !f.is_empty()) {
            let _ = writeln!(out, "    {:<26} {} {fix}", "", ui.paint(Style::Dim, "fix:"));
        }
    }
    let chain = if p.chain.len() > 1 {
        format!(" (delegated: {})", p.chain.join(" → "))
    } else {
        String::new()
    };
    let _ = writeln!(
        out,
        "  mandate   {}{chain}, purpose {}",
        p.mandate_id, p.purpose
    );
    let _ = writeln!(
        out,
        "  subject   pseudonym {}",
        Digest(&p.subject_pseudonym.chars().take(16).collect::<String>())
    );
    let _ = writeln!(
        out,
        "  time      {} ({}{})",
        p.ts.to_rfc3339(),
        p.time_sync.status,
        p.time_sync
            .max_error_ms
            .map_or_else(String::new, |e| format!(", max error {e} ms"))
    );
    let _ = writeln!(
        out,
        "  policies  cedar {}  tools {}",
        Digest(&p.policy_versions.cedar),
        Digest(p.policy_versions.tools.as_deref().unwrap_or("-"))
    );
    if let Some(command) = data["explore"].as_str() {
        let _ = writeln!(
            out,
            "  explore   {command}  {}",
            ui.paint(Style::Dim, &format!("({})", crate::counterfactual::LABEL))
        );
    }
    if let Some(o) = data["outcome"].as_object() {
        let _ = writeln!(
            out,
            "  outcome   {} ({}){}",
            s(&o["outcome"]),
            o["reason"].as_str().unwrap_or("-"),
            if o["signature_verified"] == true {
                ", outcome signature verified"
            } else {
                ", outcome signature FAILED"
            }
        );
    }
    out.truncate(out.trim_end().len());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const RECORDS: &str =
        include_str!("../../kavach-evidence-cli/tests/vectors/bundle-v1/records.jsonl");

    fn keys() -> std::collections::BTreeMap<String, kavach_ports::PublicKey> {
        let dir =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../kavach-evidence-cli/tests/vectors");
        load_trusted_keys(&dir.join("bundle-v1.keys.json"), &dir.join("bundle-v1"))
            .unwrap()
            .keys
    }

    #[test]
    fn a_changed_record_fails_its_signature_check() {
        let line = RECORDS.lines().next().unwrap();
        let record: AgentDecisionRecord = serde_json::from_str(line).unwrap();
        assert!(check_record_signature(&record, &keys(), false).is_ok());
        let mut changed = record.clone();
        changed.payload.signals.push("authorized-by-me".into());
        assert!(check_record_signature(&changed, &keys(), false).is_err());
        let mut other_key = record;
        other_key.payload.key_id = "someone-else".into();
        assert!(check_record_signature(&other_key, &keys(), false).is_err());
    }
}

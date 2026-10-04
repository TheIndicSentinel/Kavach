//! `kavach why <evidence-id>`: an evaluate (credit) decision, explained.
//!
//! Evaluate evidence is hash-chained but **not signed** (v1): anyone with
//! write access to the database can rewrite a record and rehash the chain.
//! So nothing here says "verified" or "signature". A single event can only
//! be checked against its own hash; `--export <file>` checks the whole
//! chain first and reports a break before showing anything. Either way the
//! output says what that does not prove.
//!
//! Both decisions are shown, with the governance mode (ADR-001): in shadow
//! mode a PASS return can hide a would-be BLOCK. Reasons are explained;
//! there are no counterfactuals for credit decisions, since telling someone
//! how to pass a credit check would help game lending rules.

use std::fmt::Write as _;
use std::path::Path;
use std::time::Duration;

use chrono::{DateTime, FixedOffset, Utc};
use kavach_domain::reasons::explain;
use kavach_domain::{DecisionEvent, GovernanceMode};
use kavach_evidence::{parse_export, verify_chain, verify_event_hash};
use serde_json::{json, Value};

use crate::authorize::usage;
use crate::output::{CliError, Status, Style, Ui};
use crate::project::Project;
use crate::run::RunFile;

/// What an unsigned hash chain does not prove.
pub const NOT_SIGNED: &str = "not signed, so this does not prove the record wasn't rewritten";

/// Whether `id` is an evidence id (a canonical lowercase UUID).
#[must_use]
pub fn is_evidence_id(id: &str) -> bool {
    id.len() == 36
        && id.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_digit() || (b'a'..=b'f').contains(&b),
        })
}

/// How the event's integrity was checked.
enum Integrity {
    /// One event from the running stack: its own hash only.
    OwnHash(bool),
    /// The whole export's chain linked and hashed.
    Chain { events: usize },
    /// Tombstoned: redacted, so its hash cannot be rechecked.
    Tombstoned,
}

async fn fetch_live(dir: &Path, id: &str) -> Result<(DecisionEvent, bool), CliError> {
    let project = Project::find(dir)?;
    let run = RunFile::live(&project)?;
    let token = std::fs::read_to_string(project.bundle().join("operator.jwt"))
        .map_err(|e| CliError::new("cannot read the operator token", e))?;
    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| CliError::new("cannot start an HTTP client", e))?
        .get(format!("http://{}/v1/decision-events/{id}", run.operator))
        .bearer_auth(token.trim())
        .send()
        .await
        .map_err(|e| CliError::new("the operator listener did not answer", e))?;
    let status = response.status().as_u16();
    let body: Value = response.json().await.unwrap_or(Value::Null);
    let error = body["error"].as_str().unwrap_or_default().to_string();
    match status {
        200 => {}
        404 => {
            return Err(CliError::new(format!("no decision event {id}"), error).fix(
                "the memory store forgets events when `kavach dev up` stops \
                 (set [database] in kavach.toml to keep them)",
            ))
        }
        400 => return Err(usage(format!("{id} is not an evidence id"), error)),
        _ => {
            return Err(CliError::new(
                format!("the stack refused the read ({status})"),
                error,
            ))
        }
    }
    let event: DecisionEvent = serde_json::from_value(body["event"].clone())
        .map_err(|e| CliError::new("the stack returned an event that does not parse", e))?;
    Ok((event, body["tombstoned"].as_bool().unwrap_or(false)))
}

/// Checks the whole export's chain first; a break is reported before
/// anything about the event.
fn from_export(path: &Path, id: &str) -> Result<(DecisionEvent, usize), CliError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| CliError::new(format!("cannot read {}", path.display()), e))?;
    let events = parse_export(&text).map_err(|e| {
        CliError::new(
            format!("{} is not a decision event export", path.display()),
            e,
        )
    })?;
    let report = verify_chain(&events).map_err(|e| {
        CliError::new(format!("the chain in {} is broken", path.display()), e)
            .fix("nothing in this export can be relied on; get a fresh export and investigate")
    })?;
    let event = events
        .into_iter()
        .find(|e| e.evidence_id == id)
        .ok_or_else(|| {
            CliError::new(
                format!("no decision event {id} in the export"),
                format!("{} has no such event", path.display()),
            )
        })?;
    Ok((event, report.events_checked))
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

pub async fn run(ui: &Ui, dir: &Path, id: &str, export: Option<&Path>) -> Result<i32, CliError> {
    let (event, integrity) = if let Some(path) = export {
        let (event, events) = from_export(path, id)?;
        (event, Integrity::Chain { events })
    } else {
        let (event, tombstoned) = fetch_live(dir, id).await?;
        let integrity = if tombstoned {
            Integrity::Tombstoned
        } else {
            Integrity::OwnHash(verify_event_hash(&event).is_ok())
        };
        (event, integrity)
    };

    let shadow = event.governance_mode == GovernanceMode::Shadow;
    let hidden = shadow && event.policy_decision != event.returned_decision;
    let reasons: Vec<Value> = event
        .reason_codes
        .iter()
        .map(|code| match explain(code) {
            Some(r) => json!({ "code": code, "meaning": r.meaning, "fix": r.fix }),
            None => json!({ "code": code, "meaning": null, "fix": null }),
        })
        .collect();
    let (integrity_json, status) = match integrity {
        Integrity::OwnHash(true) => (
            json!({ "hash": "matches the content", "chain": "not checked", "signed": false, "note": NOT_SIGNED }),
            Status::Ok,
        ),
        Integrity::OwnHash(false) => (
            json!({ "hash": "does NOT match the content", "chain": "not checked", "signed": false }),
            Status::Failed,
        ),
        Integrity::Chain { events } => (
            json!({ "hash": "matches the content", "chain": format!("links consistent ({events} events)"), "signed": false, "note": NOT_SIGNED }),
            Status::Ok,
        ),
        Integrity::Tombstoned => (
            json!({ "hash": "not checked: the event is tombstoned and redacted", "chain": "not checked", "signed": false }),
            Status::Warnings,
        ),
    };
    let data = json!({
        "evidence_id": event.evidence_id,
        "policy_decision": word(event.policy_decision),
        "returned_decision": word(event.returned_decision),
        "governance_mode": word(event.governance_mode),
        "shadow_hides_decision": hidden,
        "model": { "id": event.model_id, "version": event.model_version, "origin": word(event.model_origin) },
        "pack": { "id": event.pack_id, "version": event.pack_version },
        "decision_time": event.decision_time,
        "evaluated_at": event.evaluated_at,
        "correlation_id": event.correlation_id,
        "reasons": reasons,
        "policy_hits": event.policy_hits,
        "input_digest": event.input_digest,
        "tombstoned": matches!(integrity, Integrity::Tombstoned),
        "integrity": integrity_json,
    });
    Ok(ui.finish("why", status, &data, &human(*ui, &data)))
}

fn human(ui: Ui, data: &Value) -> String {
    let s = |v: &Value| v.as_str().unwrap_or("-").to_string();
    let returned = s(&data["returned_decision"]);
    let allowed = matches!(returned.as_str(), "PASS" | "ALERT");
    let at = data["decision_time"]
        .as_str()
        .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
        .map(|t| ist(t.with_timezone(&Utc)))
        .unwrap_or_default();
    let mut out = format!(
        "{}  credit decision by {} {} at {at}\n",
        ui.paint(if allowed { Style::Ok } else { Style::Fail }, &returned),
        s(&data["model"]["id"]),
        s(&data["model"]["version"]),
    );
    let _ = writeln!(
        out,
        "  decision  policy {}, returned {} ({} mode)",
        s(&data["policy_decision"]),
        returned,
        s(&data["governance_mode"])
    );
    if data["shadow_hides_decision"] == true {
        let _ = writeln!(
            out,
            "            {}",
            ui.paint(
                Style::Warn,
                &format!(
                    "shadow mode: the {} return hides a would-be {}",
                    returned,
                    s(&data["policy_decision"])
                )
            )
        );
    }
    let i = &data["integrity"];
    let integrity = match i["note"].as_str() {
        Some(note) => format!("hash {}; {note}", s(&i["hash"])),
        None => format!("hash {}", s(&i["hash"])),
    };
    let ok = !s(&i["hash"]).contains("NOT");
    let _ = writeln!(
        out,
        "  integrity {}",
        ui.paint(if ok { Style::Dim } else { Style::Fail }, &integrity)
    );
    let chain = s(&i["chain"]);
    let _ = writeln!(
        out,
        "  chain     {}",
        if chain == "not checked" {
            "not checked (use --export <file> to check the whole chain)".to_string()
        } else {
            chain
        }
    );
    if data["tombstoned"] == true {
        let _ = writeln!(
            out,
            "  {}",
            ui.paint(
                Style::Warn,
                "tombstoned: its details are redacted, as in export views"
            )
        );
    }
    let _ = writeln!(out, "  reasons");
    for r in data["reasons"].as_array().into_iter().flatten() {
        let meaning = r["meaning"]
            .as_str()
            .unwrap_or("(not in the reason catalog)");
        let _ = writeln!(out, "    {:<26} {meaning}", s(&r["code"]));
    }
    let _ = writeln!(
        out,
        "  pack      {} {}",
        s(&data["pack"]["id"]),
        s(&data["pack"]["version"])
    );
    let _ = writeln!(
        out,
        "  input     digest {} (the input itself is never stored)",
        s(&data["input_digest"])
    );
    let _ = write!(
        out,
        "  caller    correlation id {}",
        s(&data["correlation_id"])
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_ids_are_uuids_and_record_ids_are_not() {
        assert!(is_evidence_id("9771a6c1-edc5-4b2b-b38d-ffb397b7df55"));
        assert!(!is_evidence_id("adr:default:0:1"));
        assert!(!is_evidence_id("9771A6C1-EDC5-4B2B-B38D-FFB397B7DF55"));
    }

    /// A real export: the golden credit requests through the evaluate
    /// service into an in-memory chain, written as JSON lines.
    fn export(dir: &Path) -> (std::path::PathBuf, Vec<DecisionEvent>) {
        use kavach_domain::golden::{load_fixtures, workspace_golden_v0_dir};
        use kavach_evaluate::{
            EvaluateConfig, EvaluatePath, EvaluateService, NoopIncidentRecorder,
        };
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let pack =
            kavach_policy::PackLoader::load_from_path(&root.join("packs/finance/v0.yaml")).unwrap();
        let model: kavach_domain::ModelRecord = serde_yaml::from_str(
            &std::fs::read_to_string(root.join("models/finance/credit-underwriting-v1.yaml"))
                .unwrap(),
        )
        .unwrap();
        let mut service = EvaluateService::new(
            pack,
            model,
            kavach_evidence::MemoryChain::new(),
            NoopIncidentRecorder,
            EvaluateConfig::default(),
        )
        .unwrap();
        for fixture in load_fixtures(&workspace_golden_v0_dir()).unwrap() {
            let at = fixture.request.decision_time;
            service
                .evaluate(EvaluatePath::Sync, &fixture.request, at)
                .unwrap();
        }
        let events = service.evidence_store().events().to_vec();
        let path = dir.join("export.jsonl");
        let lines: Vec<_> = events
            .iter()
            .map(|e| serde_json::to_string(e).unwrap())
            .collect();
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();
        (path, events)
    }

    #[test]
    fn an_export_is_checked_whole_before_anything_is_shown() {
        let dir = std::env::temp_dir().join(format!("kavach-why-export-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (path, events) = export(&dir);
        assert!(events.len() >= 4);
        let id = &events[1].evidence_id;
        let (event, checked) = from_export(&path, id).unwrap();
        assert_eq!(&event.evidence_id, id);
        assert_eq!(checked, events.len());

        // An event rewritten (even one not asked about): the chain is broken.
        let text = std::fs::read_to_string(&path).unwrap();
        let changed = text.replacen(
            "\"policy_decision\":\"BLOCK\"",
            "\"policy_decision\":\"PASS\"",
            1,
        );
        assert_ne!(changed, text, "the export has a BLOCK to rewrite");
        std::fs::write(&path, changed).unwrap();
        let err = from_export(&path, &events[0].evidence_id).unwrap_err();
        assert!(err.what.contains("broken"), "{}", err.what);

        // Unknown id in an intact export.
        let (path, _) = export(&dir);
        assert!(from_export(&path, "00000000-0000-4000-8000-0000000000aa").is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// An export mixing a record from before evidence timestamps were kept
    /// at storage precision with a newer one: `why --export` checks the
    /// chain and explains either.
    #[test]
    fn why_export_reads_a_chain_of_old_and_new_records() {
        let events = kavach_evidence::mixed_chain();
        let path =
            std::env::temp_dir().join(format!("kavach-why-mixed-{}.jsonl", std::process::id()));
        let lines: Vec<_> = events
            .iter()
            .map(|e| serde_json::to_string(e).unwrap())
            .collect();
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();
        for event in &events {
            let (found, checked) = from_export(&path, &event.evidence_id).unwrap();
            assert_eq!(&found, event);
            assert_eq!(checked, 2);
        }
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn the_wording_never_claims_a_signature() {
        assert!(NOT_SIGNED.contains("not signed"));
        assert!(!NOT_SIGNED.contains("verified"));
    }
}

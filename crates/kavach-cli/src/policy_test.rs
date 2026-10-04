//! `kavach policy test`: cases that pin what the policies decide.
//!
//! A suite is a YAML file (`version: 1`, pre-alpha) of cases:
//!
//! - `kind: tool_call`: a tool call decided offline, as `kavach authorize`
//!   does: the bundled agent policies (Cedar), the project's signed tool
//!   registry and the raw-identifier checks, over a mandate issued in
//!   memory (optionally for another borrower, or delegated).
//! - `kind: evaluate`: a decision request evaluated against the project's
//!   policy pack (CEL) and model.
//!
//! Every key is checked (a typo fails the file), and every case asserts a
//! decision or a refusal. Exit 0 if every case passes, 1 if one fails, 64
//! if a file is not a valid suite.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, FixedOffset, NaiveDate, NaiveTime, TimeZone, Utc};
use kavach_api::dataplane::{TestClock, WhatIf};
use kavach_dataplane::ToolRequest;
use kavach_domain::mandate::DelegationRequest;
use kavach_domain::{Decision, EvaluateRequest, GovernanceMode, ModelRecord};
use kavach_evaluate::{EvaluateConfig, EvaluateError, EvaluatePath, EvaluateService};
use kavach_ports::MandateStore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::authorize::{usage, DEFAULT_AGENT, DEFAULT_SUBJECT};
use crate::dev::{dataplane_config, StartedAt};
use crate::init::{MODEL_FILE, PACK_FILE};
use crate::output::{CliError, Status, Style, Ui};
use crate::project::Project;

/// Where `kavach init` puts suites, relative to the project.
pub const DIR: &str = "policy-tests";
/// The suite format this command reads.
pub const VERSION: u32 = 1;
/// `at: "HH:MM"` means this IST date (a fixed day keeps runs repeatable).
pub const SHORTHAND_DATE: (i32, u32, u32) = (2026, 10, 1);
/// When a tool call case gives no `at`.
const DEFAULT_AT: &str = "11:00";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Suite {
    version: u32,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Case {
    ToolCall(ToolCase),
    Evaluate(EvaluateCase),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolCase {
    name: String,
    tool: String,
    /// Default: the delegate if the mandate is delegated, else the agent
    /// the mandate is assigned to.
    agent: Option<String>,
    at: Option<String>,
    #[serde(default)]
    contacts_today: u32,
    /// Sent as given: nothing is defaulted, so the registry is tested too.
    #[serde(default)]
    params: Map<String, Value>,
    #[serde(default)]
    mandate: MandateSpec,
    expect: Expect,
}

/// The what-if mandate: a real one, issued in memory from a synthetic
/// system-of-record event, and optionally delegated through the real
/// delegation rules.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct MandateSpec {
    subject: Option<String>,
    assigned_to: Option<String>,
    delegate: Option<Delegate>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Delegate {
    to: String,
    actions: BTreeSet<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvaluateCase {
    name: String,
    /// A decision request, as `POST /v1/evaluate` takes it.
    request: Value,
    #[serde(default)]
    governance_mode: Mode,
    /// Server time. Default: the request's `decision_time`.
    at: Option<String>,
    expect: Expect,
}

#[derive(Debug, Default, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Mode {
    #[default]
    Enforce,
    Shadow,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Expect {
    decision: Option<Decision>,
    refused: Option<Refused>,
    /// Exactly these reasons (in any order).
    reasons: Option<BTreeSet<String>>,
    /// At least these reasons.
    #[serde(default)]
    reasons_include: BTreeSet<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Refused {
    Yes(bool),
    Code(RefusedCode),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RefusedCode {
    code: String,
}

impl Expect {
    fn validate(&self) -> Result<(), String> {
        match (&self.decision, &self.refused) {
            (None, None) => Err("expect needs a decision or refused".into()),
            (Some(_), Some(_)) => Err("expect has both a decision and refused".into()),
            (None, Some(Refused::Yes(false))) => {
                Err("refused: false asserts nothing; expect a decision instead".into())
            }
            (None, Some(_)) if self.reasons.is_some() || !self.reasons_include.is_empty() => {
                Err("reasons apply to a decision, not to refused".into())
            }
            _ => Ok(()),
        }
    }
}

/// What a case produced.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
enum Actual {
    Decided {
        decision: Decision,
        reasons: Vec<String>,
    },
    Refused {
        code: String,
        message: String,
    },
    /// The case could not run (e.g. no mandate could be issued).
    Error {
        message: String,
    },
}

impl Expect {
    /// `None` if the actual result meets the expectation, else why not.
    fn check(&self, actual: &Actual) -> Option<String> {
        match (actual, &self.decision, &self.refused) {
            (Actual::Error { message }, _, _) => Some(format!("could not run: {message}")),
            (Actual::Refused { code, .. }, Some(want), _) => {
                Some(format!("expected {}, refused ({code})", word(*want)))
            }
            (Actual::Decided { decision, .. }, None, Some(_)) => {
                Some(format!("expected a refusal, decided {}", word(*decision)))
            }
            (Actual::Refused { code, .. }, None, Some(Refused::Code(want))) => {
                (code != &want.code).then(|| format!("refused with {code}, expected {}", want.code))
            }
            (Actual::Refused { .. }, None, _) => None,
            (Actual::Decided { decision, reasons }, Some(want), _) => {
                let got: BTreeSet<String> = reasons.iter().cloned().collect();
                if decision != want {
                    Some(format!(
                        "expected {}, decided {} [{}]",
                        word(*want),
                        word(*decision),
                        reasons.join(", ")
                    ))
                } else if self.reasons.as_ref().is_some_and(|exact| exact != &got) {
                    Some(format!(
                        "reasons [{}], expected exactly [{}]",
                        reasons.join(", "),
                        join(self.reasons.iter().flatten())
                    ))
                } else {
                    let missing: Vec<_> = self.reasons_include.difference(&got).collect();
                    (!missing.is_empty()).then(|| {
                        format!("reasons [{}] lack [{}]", reasons.join(", "), join(missing))
                    })
                }
            }
            (_, None, None) => Some("no expectation".into()),
        }
    }

    fn summary(&self) -> String {
        match (&self.decision, &self.refused) {
            (Some(d), _) => word(*d),
            (None, Some(Refused::Code(c))) => format!("refused ({})", c.code),
            _ => "refused".into(),
        }
    }
}

fn join<'a>(items: impl IntoIterator<Item = &'a String>) -> String {
    items.into_iter().cloned().collect::<Vec<_>>().join(", ")
}

fn word(decision: Decision) -> String {
    serde_json::to_value(decision)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// `at`: RFC 3339, or `HH:MM` meaning IST on [`SHORTHAND_DATE`].
fn parse_time(text: &str) -> Result<DateTime<Utc>, String> {
    if let Ok(t) = DateTime::parse_from_rfc3339(text) {
        return Ok(t.with_timezone(&Utc));
    }
    let time = NaiveTime::parse_from_str(text, "%H:%M")
        .map_err(|_| format!("at {text:?}: use RFC 3339 or HH:MM (IST)"))?;
    let (y, m, d) = SHORTHAND_DATE;
    let date = NaiveDate::from_ymd_opt(y, m, d).ok_or("shorthand date")?;
    FixedOffset::east_opt(5 * 3600 + 1800)
        .and_then(|ist| ist.from_local_datetime(&date.and_time(time)).single())
        .map(|t| t.with_timezone(&Utc))
        .ok_or_else(|| format!("at {text:?}: not a time"))
}

/// Keys in `given` that `parsed` (the same value after a typed round trip)
/// dropped: unknown fields in a type that would otherwise ignore them.
fn unknown_keys(given: &Value, parsed: &Value, path: &str, out: &mut Vec<String>) {
    if let (Value::Object(given), Value::Object(parsed)) = (given, parsed) {
        for (key, value) in given {
            let here = format!("{path}.{key}");
            match parsed.get(key) {
                None => out.push(here),
                Some(kept) => unknown_keys(value, kept, &here, out),
            }
        }
    }
}

/// A suite file, read and checked.
fn load(path: &Path) -> Result<Suite, CliError> {
    let bad = |why: String| {
        usage(
            format!("{} is not a valid policy test suite", path.display()),
            why,
        )
        .fix("see docs/DEVELOPING.md (policy tests) for the format")
    };
    let text = std::fs::read_to_string(path)
        .map_err(|e| CliError::new(format!("cannot read {}", path.display()), e))?;
    let suite: Suite = serde_yaml::from_str(&text).map_err(|e| bad(e.to_string()))?;
    if suite.version != VERSION {
        return Err(bad(format!(
            "version {} (this kavach reads version {VERSION})",
            suite.version
        )));
    }
    if suite.cases.is_empty() {
        return Err(bad("no cases".into()));
    }
    let mut names = BTreeSet::new();
    for case in &suite.cases {
        let (name, expect) = match case {
            Case::ToolCall(c) => (&c.name, &c.expect),
            Case::Evaluate(c) => (&c.name, &c.expect),
        };
        if !names.insert(name.clone()) {
            return Err(bad(format!("case {name:?} appears twice")));
        }
        expect
            .validate()
            .map_err(|e| bad(format!("case {name:?}: {e}")))?;
        match case {
            Case::ToolCall(c) => {
                parse_time(c.at.as_deref().unwrap_or(DEFAULT_AT))
                    .map_err(|e| bad(format!("case {name:?}: {e}")))?;
            }
            Case::Evaluate(c) => {
                let request: EvaluateRequest = serde_json::from_value(c.request.clone())
                    .map_err(|e| bad(format!("case {name:?}: request: {e}")))?;
                let mut unknown = Vec::new();
                let parsed = serde_json::to_value(&request).unwrap_or_default();
                unknown_keys(&c.request, &parsed, "request", &mut unknown);
                if !unknown.is_empty() {
                    return Err(bad(format!(
                        "case {name:?}: unknown keys {}",
                        unknown.join(", ")
                    )));
                }
                if let Some(at) = &c.at {
                    parse_time(at).map_err(|e| bad(format!("case {name:?}: {e}")))?;
                }
            }
        }
    }
    Ok(suite)
}

/// The agents with a passport in the bundle's mandate configuration.
fn passports(project: &Project) -> Result<BTreeSet<String>, CliError> {
    let path = project.kavach_dir().join("mandate-config.json");
    let text = std::fs::read_to_string(&path)
        .map_err(|e| CliError::new(format!("cannot read {}", path.display()), e))?;
    let config: Value = serde_json::from_str(&text)
        .map_err(|e| CliError::new("the mandate configuration is not JSON", e))?;
    Ok(config["passports"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|p| p["tenant_id"] == kavach_devkit::TENANT)
        .filter_map(|p| p["agent_id"].as_str().map(str::to_string))
        .collect())
}

async fn run_tool(project: &Project, passports: &BTreeSet<String>, case: &ToolCase) -> Actual {
    match tool_decision(project, passports, case).await {
        Ok(actual) => actual,
        Err(message) => Actual::Error { message },
    }
}

async fn tool_decision(
    project: &Project,
    passports: &BTreeSet<String>,
    case: &ToolCase,
) -> Result<Actual, String> {
    let at = parse_time(case.at.as_deref().unwrap_or(DEFAULT_AT))?;
    let what_if = WhatIf::build(
        &dataplane_config(project, None),
        TestClock(Arc::new(StartedAt::new(at))),
        case.contacts_today,
    )
    .await?;
    let subject = case.mandate.subject.as_deref().unwrap_or(DEFAULT_SUBJECT);
    let holder = case.mandate.assigned_to.as_deref().unwrap_or(DEFAULT_AGENT);
    let event =
        kavach_devkit::sor_event(&project.bundle(), "policy-test", subject, holder, at).await?;
    let mut mandate_id = what_if
        .issue(&event)
        .await
        .map_err(|e| format!("no mandate: {e}"))?;
    if let Some(delegate) = &case.mandate.delegate {
        mandate_id = delegated(&what_if, &mandate_id, holder, delegate).await?;
    }
    let agent = case.agent.as_deref().unwrap_or_else(|| {
        case.mandate
            .delegate
            .as_ref()
            .map_or(holder, |d| d.to.as_str())
    });
    if !passports.contains(agent) {
        return Ok(Actual::Refused {
            code: "no_passport".into(),
            message: format!("agent {agent} has no passport"),
        });
    }
    let request = ToolRequest {
        mandate_id,
        request_id: "policy-test".into(),
        params: case.params.clone(),
    };
    if let Err(refusal) = what_if.tools().check(&case.tool, request.clone()) {
        return Ok(Actual::Refused {
            code: refusal.code.as_str().into(),
            message: refusal.message,
        });
    }
    let decided = what_if.precheck(agent, &case.tool, request).await?;
    Ok(Actual::Decided {
        decision: decided.decision,
        reasons: decided.reasons,
    })
}

/// A child of `parent_id`, through the real delegation rules.
async fn delegated(
    what_if: &WhatIf,
    parent_id: &str,
    holder: &str,
    delegate: &Delegate,
) -> Result<String, String> {
    let mandates = what_if.mandates();
    let stored = mandates
        .store()
        .get(kavach_devkit::TENANT, parent_id)
        .await
        .map_err(|e| e.message)?
        .ok_or("the parent mandate is gone")?;
    let parent = mandates
        .verify_active(&stored.token)
        .await
        .map_err(|e| e.message)?;
    let request = DelegationRequest {
        actions: delegate.actions.clone(),
        data_fields: parent.data_fields.clone(),
        channels: parent.channels.clone(),
        window: parent.window,
        ceilings: parent.ceilings.clone(),
        exp: None,
        allowed_agents: BTreeSet::new(),
    };
    mandates
        .delegate(
            kavach_devkit::TENANT,
            parent_id,
            holder,
            &delegate.to,
            &request,
        )
        .await
        .map(|issued| issued.mandate.id)
        .map_err(|e| format!("no delegation: {}", e.message))
}

fn refusal_code(error: &EvaluateError) -> &'static str {
    match error {
        EvaluateError::Validation(_) => "validation",
        EvaluateError::ModelMismatch(_) => "model_mismatch",
        EvaluateError::PackNotEffective => "pack_not_effective",
        EvaluateError::IdempotencyConflict(_) => "conflict",
        EvaluateError::Policy(_) => "policy",
        EvaluateError::Domain(_) => "domain",
    }
}

fn run_evaluate(project: &Project, case: &EvaluateCase) -> Actual {
    evaluate_decision(project, case).unwrap_or_else(|message| Actual::Error { message })
}

fn evaluate_decision(project: &Project, case: &EvaluateCase) -> Result<Actual, String> {
    let request: EvaluateRequest =
        serde_json::from_value(case.request.clone()).map_err(|e| e.to_string())?;
    let pack = kavach_policy::PackLoader::load_from_path(&project.bundle().join(PACK_FILE))
        .map_err(|e| format!("policy pack: {e}"))?;
    let model_text = std::fs::read_to_string(project.bundle().join(MODEL_FILE))
        .map_err(|e| format!("model: {e}"))?;
    let mut model: ModelRecord =
        serde_yaml::from_str(&model_text).map_err(|e| format!("model: {e}"))?;
    model.governance_mode = match case.governance_mode {
        Mode::Enforce => GovernanceMode::Enforce,
        Mode::Shadow => GovernanceMode::Shadow,
    };
    let now = match &case.at {
        Some(at) => parse_time(at)?,
        None => request.decision_time,
    };
    let mut service = EvaluateService::new(
        pack,
        model,
        kavach_evidence::MemoryChain::new(),
        kavach_evaluate::NoopIncidentRecorder,
        EvaluateConfig::default(),
    )
    .map_err(|e| e.to_string())?;
    Ok(match service.evaluate(EvaluatePath::Sync, &request, now) {
        Ok(result) => Actual::Decided {
            decision: result.response.returned_decision,
            reasons: result.response.reason_codes,
        },
        Err(error) => Actual::Refused {
            code: refusal_code(&error).into(),
            message: error.to_string(),
        },
    })
}

/// The suite files at `path`: the file itself, or every `.yaml`/`.yml` in
/// the directory, in name order.
fn suites(path: &Path) -> Result<Vec<PathBuf>, CliError> {
    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }
    let entries = std::fs::read_dir(path).map_err(|e| {
        usage(format!("no policy tests at {}", path.display()), e).fix(format!(
            "pass a suite file or directory, or add suites to {DIR}/"
        ))
    })?;
    let mut files: Vec<_> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.extension().is_some_and(|x| x == "yaml" || x == "yml"))
        .collect();
    files.sort();
    if files.is_empty() {
        return Err(usage(
            format!("no policy tests at {}", path.display()),
            "the directory has no .yaml files",
        ));
    }
    Ok(files)
}

const HEADER: &str = "Agent policies: the bundled Cedar policies built into this kavach \
                      (your own are not configurable yet). Tool registry, CEL pack and \
                      model: this project's.";

pub async fn run(ui: &Ui, dir: &Path, path: Option<&Path>) -> Result<i32, CliError> {
    let project = Project::find(dir)?;
    let target = path.map_or_else(|| project.root.join(DIR), Path::to_path_buf);
    let files = suites(&target)?;
    // Every file is checked before any case runs.
    let loaded: Vec<(PathBuf, Suite)> = files
        .into_iter()
        .map(|f| load(&f).map(|s| (f, s)))
        .collect::<Result<_, _>>()?;
    let passports = passports(&project)?;

    let (mut passed, mut failed) = (0usize, 0usize);
    let mut human = format!("{}\n", ui.paint(Style::Dim, HEADER));
    let mut reports = Vec::new();
    for (file, suite) in &loaded {
        let shown = file.strip_prefix(&project.root).unwrap_or(file);
        let _ = writeln!(human, "\n{}", shown.display());
        let mut cases = Vec::new();
        for case in &suite.cases {
            let (name, kind, expect, actual) = match case {
                Case::ToolCall(c) => (
                    &c.name,
                    "tool_call",
                    &c.expect,
                    run_tool(&project, &passports, c).await,
                ),
                Case::Evaluate(c) => (&c.name, "evaluate", &c.expect, run_evaluate(&project, c)),
            };
            let failure = expect.check(&actual);
            if failure.is_none() {
                passed += 1;
                let _ = writeln!(human, "  {}  {name}", ui.status(Status::Ok));
            } else {
                failed += 1;
                let _ = writeln!(human, "  {}  {name}", ui.status(Status::Failed));
            }
            if let Some(why) = &failure {
                let _ = writeln!(human, "        {why}");
            }
            cases.push(json!({
                "name": name,
                "kind": kind,
                "passed": failure.is_none(),
                "expected": expect.summary(),
                "actual": actual,
                "failure": failure,
            }));
        }
        reports.push(json!({ "file": shown, "cases": cases }));
    }
    let _ = write!(human, "\n{passed} passed, {failed} failed");
    let status = if failed == 0 {
        Status::Ok
    } else {
        Status::Failed
    };
    let data = json!({
        "format_version": VERSION,
        "agent_policies": "bundled",
        "suites": reports,
        "passed": passed,
        "failed": failed,
    });
    Ok(ui.finish("policy test", status, &data, &human))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<Suite, String> {
        let suite: Suite = serde_yaml::from_str(text).map_err(|e| e.to_string())?;
        for case in &suite.cases {
            match case {
                Case::ToolCall(c) => c.expect.validate()?,
                Case::Evaluate(c) => c.expect.validate()?,
            }
        }
        Ok(suite)
    }

    const CASE: &str =
        "version: 1\ncases:\n  - kind: tool_call\n    name: a\n    tool: send_reminder\n";

    #[test]
    fn typos_fail_at_every_level() {
        for bad in [
            "version: 1\ncaes: []\n",
            &format!("{CASE}    expect: {{ decision: PASS, reasons_inclde: [x] }}\n"),
            &format!("{CASE}    tol: x\n    expect: {{ decision: PASS }}\n"),
            &format!("{CASE}    mandate: {{ subjet: x }}\n    expect: {{ decision: PASS }}\n"),
            &format!(
                "{CASE}    mandate: {{ delegate: {{ to: x, actions: [], extra: 1 }} }}\n    expect: {{ decision: PASS }}\n"
            ),
            &format!("{CASE}    expect: {{ refused: {{ code: x, why: y }} }}\n"),
            &format!("{CASE}    expect: {{ decision: PAS }}\n"),
            "version: 1\ncases:\n  - kind: tool_cal\n    name: a\n",
        ] {
            assert!(parse(bad).is_err(), "accepted: {bad}");
        }
        assert!(parse(&format!("{CASE}    expect: {{ decision: PASS }}\n")).is_ok());
    }

    #[test]
    fn every_case_asserts_something() {
        for bad in [
            "expect: {}",
            "expect: { reasons_include: [x] }",
            "expect: { refused: false }",
            "expect: { decision: PASS, refused: true }",
            "expect: { refused: true, reasons: [x] }",
        ] {
            assert!(parse(&format!("{CASE}    {bad}\n")).is_err(), "{bad}");
        }
        for good in [
            "expect: { refused: true }",
            "expect: { refused: { code: unknown_tool } }",
            "expect: { decision: BLOCK, reasons: [a, b], reasons_include: [a] }",
        ] {
            assert!(parse(&format!("{CASE}    {good}\n")).is_ok(), "{good}");
        }
    }

    #[test]
    fn times_are_rfc3339_or_ist_on_the_fixed_date() {
        assert_eq!(
            parse_time("20:30").unwrap(),
            Utc.with_ymd_and_hms(2026, 10, 1, 15, 0, 0).unwrap()
        );
        assert_eq!(
            parse_time("2026-10-05T08:00:00+05:30").unwrap(),
            Utc.with_ymd_and_hms(2026, 10, 5, 2, 30, 0).unwrap()
        );
        assert!(parse_time("8pm").is_err());
        assert!(parse_time("2026-10-05 08:00").is_err());
    }

    #[test]
    fn exact_and_included_reasons_are_both_checked() {
        let expect = Expect {
            decision: Some(Decision::Block),
            refused: None,
            reasons: Some(["a".to_string()].into()),
            reasons_include: BTreeSet::new(),
        };
        let actual = |reasons: &[&str]| Actual::Decided {
            decision: Decision::Block,
            reasons: reasons.iter().map(ToString::to_string).collect(),
        };
        assert!(expect.check(&actual(&["a"])).is_none());
        assert!(expect.check(&actual(&["a", "b"])).is_some());
        let include = Expect {
            reasons: None,
            reasons_include: ["a".to_string()].into(),
            ..expect
        };
        assert!(include.check(&actual(&["a", "b"])).is_none());
        assert!(include.check(&actual(&["b"])).is_some());
    }
}

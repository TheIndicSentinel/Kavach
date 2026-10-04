//! The `kavach` binary, end to end: exit codes, the JSON envelope, and the
//! files `init` writes. Each test works in its own temporary directory.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

fn kavach(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_kavach"))
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("NO_COLOR", "1")
        .output()
        .expect("run kavach")
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("kavach-cli-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout is not JSON ({e}): {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

/// A free loopback port (released before kavach binds it).
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Moves a project's listeners to free ports, so tests run in parallel and
/// beside anything already on 8080.
fn use_free_ports(dir: &Path) {
    let path = dir.join("kavach.toml");
    let mut text = std::fs::read_to_string(&path).unwrap();
    for port in ["8080", "8091", "8090", "8443"] {
        text = text.replace(
            &format!("127.0.0.1:{port}\""),
            &format!("127.0.0.1:{}\"", free_port()),
        );
    }
    std::fs::write(&path, text).unwrap();
}

#[test]
fn help_and_version_exit_zero() {
    let dir = scratch("help");
    let help = kavach(&dir, &["--help"]);
    assert_eq!(help.status.code(), Some(0));
    let text = String::from_utf8_lossy(&help.stdout);
    for command in ["init", "doctor", "dev"] {
        assert!(text.contains(command), "{text}");
    }
    assert_eq!(kavach(&dir, &["--version"]).status.code(), Some(0));
}

#[test]
fn usage_errors_exit_64() {
    let dir = scratch("usage");
    assert_eq!(kavach(&dir, &["no-such-command"]).status.code(), Some(64));
    assert_eq!(kavach(&dir, &["doctor", "--bogus"]).status.code(), Some(64));
}

#[test]
fn outside_a_project_errors_say_what_why_and_fix() {
    let dir = scratch("noproject");
    let human = kavach(&dir, &["doctor"]);
    assert_eq!(human.status.code(), Some(1));
    let err = String::from_utf8_lossy(&human.stderr);
    assert!(err.contains("error: no Kavach project here"), "{err}");
    assert!(err.contains("why:") && err.contains("fix:"), "{err}");
    assert!(human.stdout.is_empty());

    let machine = kavach(&dir, &["--json", "doctor"]);
    assert_eq!(machine.status.code(), Some(1));
    let doc = json(&machine);
    assert_eq!(doc["schema"], "kavach.cli/v1");
    assert_eq!(doc["command"], "doctor");
    assert_eq!(doc["status"], "failed");
    assert!(doc["error"]["fix"].is_string(), "{doc}");
}

#[test]
fn init_writes_a_dev_project_and_refuses_to_overwrite_it() {
    let dir = scratch("init");
    std::fs::write(dir.join(".gitignore"), "target/").unwrap();
    let out = kavach(&dir, &["--json", "init"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let doc = json(&out);
    assert_eq!(doc["schema"], "kavach.cli/v1");
    assert_eq!(doc["command"], "init");
    assert_eq!(doc["status"], "ok");
    assert_eq!(doc["profile"], "dev");
    assert_eq!(doc["gitignore_updated"], true);

    let project = std::fs::read_to_string(dir.join("kavach.toml")).unwrap();
    assert!(project.contains("profile = \"dev\""), "{project}");
    for file in [
        ".kavach/kavach/jwks.json",
        ".kavach/kavach/tools/agent-tools.yaml.sig",
        ".kavach/operator.jwt",
        ".kavach/policy/finance-v0.yaml",
    ] {
        assert!(dir.join(file).is_file(), "{file}");
    }
    let ignore = std::fs::read_to_string(dir.join(".gitignore")).unwrap();
    assert!(ignore.starts_with("target/\n"), "{ignore}");
    assert!(ignore.lines().any(|l| l == "/.kavach/"), "{ignore}");

    let again = kavach(&dir, &["init"]);
    assert_eq!(again.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&again.stderr).contains("already exists"));
}

#[test]
fn doctor_reports_every_check_in_the_envelope() {
    let dir = scratch("doctor");
    assert_eq!(kavach(&dir, &["init"]).status.code(), Some(0));
    use_free_ports(&dir);
    let out = kavach(&dir, &["--json", "doctor"]);
    let doc = json(&out);
    assert_eq!(doc["schema"], "kavach.cli/v1");
    assert_eq!(doc["command"], "doctor");
    let names: Vec<&str> = doc["checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    for name in [
        "project", "bundle", "secrets", "tokens", "ports", "database", "clock",
    ] {
        assert!(names.contains(&name), "{names:?}");
    }
    // The clock and contact hours depend on the machine and the time of
    // day, so the run may warn; it must not fail.
    let expected = match doc["status"].as_str() {
        Some("ok") => 0,
        Some("warnings") => 2,
        other => panic!("doctor failed ({other:?}): {doc}"),
    };
    assert_eq!(out.status.code(), Some(expected));
}

#[test]
fn dev_up_starts_and_reports_its_endpoints() {
    let dir = scratch("devup");
    assert_eq!(kavach(&dir, &["init"]).status.code(), Some(0));
    use_free_ports(&dir);
    let out = kavach(
        &dir,
        &["--json", "dev", "up", "--at", "11:00", "--exit-when-ready"],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let doc = json(&out);
    assert_eq!(doc["command"], "dev up");
    assert_eq!(doc["store"], "memory");
    assert_eq!(doc["clock"], "11:00 IST");
    let operator = doc["endpoints"]["operator"].as_str().unwrap();
    assert!(operator.starts_with("http://127.0.0.1:"), "{operator}");

    let bad = kavach(&dir, &["dev", "up", "--at", "25:00", "--exit-when-ready"]);
    assert_eq!(bad.status.code(), Some(64));
}

#[test]
fn authorize_decides_offline_and_exits_by_decision() {
    let dir = scratch("authorize");
    assert_eq!(kavach(&dir, &["init"]).status.code(), Some(0));

    let allow = kavach(
        &dir,
        &["--json", "authorize", "send_reminder", "--at", "11:00"],
    );
    let doc = json(&allow);
    assert_eq!(allow.status.code(), Some(0), "{doc}");
    assert_eq!(doc["command"], "authorize");
    assert_eq!(doc["decision"], "PASS");
    assert_eq!(doc["recorded"], false);
    assert_eq!(doc["mandate"]["what_if"], true);

    let cases: [(&[&str], &str); 4] = [
        (&["--at", "20:30"], "contact-window"),
        (
            &["--at", "11:00", "--contacts-today", "3"],
            "contact-daily-cap",
        ),
        (
            &["--at", "11:00", "-p", "channel=sms"],
            "channel-within-mandate",
        ),
        (
            &["--at", "11:00", "-p", "subject_ref=ref:borrower:9876543210"],
            "raw_identifier:subject_ref:phone",
        ),
    ];
    for (args, reason) in cases {
        let mut all = vec!["--json", "authorize", "send_reminder"];
        all.extend_from_slice(args);
        let out = kavach(&dir, &all);
        let doc = json(&out);
        assert_eq!(out.status.code(), Some(1), "{args:?}: {doc}");
        assert_eq!(doc["decision"], "BLOCK", "{args:?}");
        let reasons = doc["reasons"].to_string();
        assert!(reasons.contains(reason), "{args:?}: {reasons}");
        // Raw identifiers never reach the terminal.
        assert!(!String::from_utf8_lossy(&out.stdout).contains("9876543210"));
    }

    let review = kavach(
        &dir,
        &[
            "--json",
            "authorize",
            "propose_plan",
            "--at",
            "11:00",
            "-p",
            "waiver_bps=2500",
        ],
    );
    assert_eq!(review.status.code(), Some(1));
    assert_eq!(json(&review)["decision"], "HUMAN_REVIEW");
}

#[test]
fn authorize_usage_errors_exit_64() {
    let dir = scratch("authorize-usage");
    assert_eq!(kavach(&dir, &["init"]).status.code(), Some(0));
    for args in [
        &["authorize", "no_such_tool"][..],
        &["authorize", "send_reminder", "-p", "bogus=1"],
        &["authorize", "propose_plan", "-p", "waiver_bps=lots"],
        &["authorize", "send_reminder", "-p", "channel"],
        &["authorize", "send_reminder", "--at", "7pm"],
        &["authorize", "send_reminder", "--agent", "no-such-agent"],
    ] {
        let out = kavach(&dir, args);
        assert_eq!(
            out.status.code(),
            Some(64),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// Kills the stack even if the test fails.
struct Stack(std::process::Child);

impl Drop for Stack {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn the_live_path_issues_mandates_and_records_calls() {
    let dir = scratch("live");
    assert_eq!(kavach(&dir, &["init"]).status.code(), Some(0));
    use_free_ports(&dir);
    // Which mandate is a usage error, before any stack is needed.
    assert_eq!(
        kavach(&dir, &["call", "send_reminder"]).status.code(),
        Some(64)
    );
    let not_running = kavach(&dir, &["call", "send_reminder", "--issue-mandate"]);
    assert_eq!(not_running.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&not_running.stderr).contains("not running"));

    let mut stack = Stack(
        Command::new(env!("CARGO_BIN_EXE_kavach"))
            .arg("-C")
            .arg(&dir)
            .args(["dev", "up", "--at", "11:00"])
            .env("NO_COLOR", "1")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    let run = dir.join(".kavach/run.json");
    for _ in 0..120 {
        if run.is_file() {
            break;
        }
        assert!(stack.0.try_wait().unwrap().is_none(), "dev up exited");
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    let text = std::fs::read_to_string(&run).expect("run.json");
    assert!(!text.contains("eyJ"), "no tokens in run.json");

    let issued = kavach(&dir, &["--json", "sor", "event"]);
    let doc = json(&issued);
    assert_eq!(issued.status.code(), Some(0), "{doc}");
    let mandate = doc["mandate_id"].as_str().unwrap().to_string();
    assert_eq!(mandate.len(), 36, "printed whole: {mandate}");
    assert!(doc["exp"].as_str().unwrap().ends_with('Z'), "{doc}");

    let call = kavach(
        &dir,
        &["--json", "call", "send_reminder", "--mandate", &mandate],
    );
    let doc = json(&call);
    assert_eq!(call.status.code(), Some(0), "{doc}");
    assert_eq!(doc["decision"], "PASS");
    assert_eq!(doc["recorded"], true);
    assert!(doc["reply"]["record_id"].is_string(), "{doc}");

    // `why` reads it back (audited), checks its signature against the local
    // dev keys, and says the chain was not checked.
    let record_id = doc["reply"]["record_id"].as_str().unwrap().to_string();
    let why = kavach(&dir, &["--json", "why", &record_id]);
    let doc = json(&why);
    assert_eq!(why.status.code(), Some(0), "{doc}");
    assert_eq!(doc["command"], "why");
    assert_eq!(doc["decision"], "PASS");
    assert_eq!(doc["verification"]["record_signature"], "verified");
    assert_eq!(doc["verification"]["against"], "dev keys");
    assert_eq!(doc["verification"]["chain"]["checked"], false);
    assert!(doc["reasons"][0]["meaning"].is_string(), "{doc}");
    let human = kavach(&dir, &["why", &record_id]);
    let text = String::from_utf8_lossy(&human.stdout);
    assert!(
        text.contains("record signature verified against dev keys"),
        "{text}"
    );
    assert!(!text.contains("[redacted"), "{text}");
    assert_eq!(
        kavach(&dir, &["why", "adr:default:0:999"]).status.code(),
        Some(1)
    );
    assert_eq!(kavach(&dir, &["why", "nope"]).status.code(), Some(64));

    let blocked = kavach(
        &dir,
        &[
            "--json",
            "call",
            "send_reminder",
            "--issue-mandate",
            "-p",
            "channel=sms",
        ],
    );
    let doc = json(&blocked);
    assert_eq!(blocked.status.code(), Some(1), "{doc}");
    assert_eq!(doc["decision"], "BLOCK");
    assert!(
        doc["issued_mandate"]["event_id"].is_string(),
        "says it issued one"
    );

    // A business block: `why` points to offline exploration.
    why_explores_with_placeholders(&dir, doc["reply"]["record_id"].as_str().unwrap());

    // Killed without cleaning up: the stale file is detected.
    let _ = stack.0.kill();
    let _ = stack.0.wait();
    let stale = kavach(&dir, &["call", "send_reminder", "--mandate", &mandate]);
    assert_eq!(stale.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&stale.stderr).contains("nothing answers"));
}

#[test]
fn policy_test_runs_the_starter_suites_and_reports_failures() {
    let dir = scratch("policy");
    assert_eq!(kavach(&dir, &["init"]).status.code(), Some(0));
    assert!(dir.join("policy-tests/collections.yaml").is_file());
    assert!(dir.join("policy-tests/credit.yaml").is_file());

    let out = kavach(&dir, &["--json", "policy", "test"]);
    let doc = json(&out);
    assert_eq!(out.status.code(), Some(0), "{doc}");
    assert_eq!(doc["command"], "policy test");
    assert_eq!(doc["failed"], 0);
    assert_eq!(doc["agent_policies"], "bundled");
    assert!(doc["passed"].as_u64().unwrap() >= 20, "{doc}");

    let human = kavach(&dir, &["policy", "test"]);
    let text = String::from_utf8_lossy(&human.stdout);
    assert!(
        text.starts_with("Agent policies: the bundled Cedar policies"),
        "{text}"
    );

    // A wrong expectation fails the run, and says why.
    let wrong = dir.join("wrong.yaml");
    std::fs::write(
        &wrong,
        "version: 1\ncases:\n  - kind: tool_call\n    name: wrong\n    tool: send_reminder\n    at: \"20:30\"\n    params: { subject_ref: \"ref:borrower:B-9382\", channel: whatsapp, template_id: emi_reminder_v1 }\n    expect: { decision: PASS }\n",
    )
    .unwrap();
    let out = kavach(&dir, &["--json", "policy", "test", wrong.to_str().unwrap()]);
    let doc = json(&out);
    assert_eq!(out.status.code(), Some(1), "{doc}");
    let case = &doc["suites"][0]["cases"][0];
    assert_eq!(case["passed"], false);
    assert_eq!(case["actual"]["decision"], "BLOCK");
    assert!(
        case["failure"].as_str().unwrap().contains("expected PASS"),
        "{case}"
    );

    // A typo is an invalid suite, not a silent pass.
    let typo = dir.join("typo.yaml");
    std::fs::write(
        &typo,
        "version: 1\ncases:\n  - kind: tool_call\n    name: typo\n    tool: send_reminder\n    expect: { decision: BLOCK, reasons_inclde: [x] }\n",
    )
    .unwrap();
    let out = kavach(&dir, &["policy", "test", typo.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(64));
    assert!(String::from_utf8_lossy(&out.stderr).contains("reasons_inclde"));
}

fn vectors() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../kavach-evidence-cli/tests/vectors")
}

#[test]
fn why_explains_a_record_from_a_verified_bundle() {
    let dir = scratch("why-bundle");
    let bundle = vectors().join("bundle-v1");
    let keys = vectors().join("bundle-v1.keys.json");
    let run = |bundle: &Path, keys: &Path| {
        kavach(
            &dir,
            &[
                "--json",
                "why",
                "adr:default:0:1",
                "--bundle",
                bundle.to_str().unwrap(),
                "--keys",
                keys.to_str().unwrap(),
            ],
        )
    };

    // It verifies, with findings that are not protected: exit 2.
    let out = run(&bundle, &keys);
    let doc = json(&out);
    assert_eq!(out.status.code(), Some(2), "{doc}");
    assert_eq!(doc["verification"]["record_signature"], "verified");
    assert_eq!(doc["verification"]["against"], "trusted keys");
    assert_eq!(doc["verification"]["chain"]["checked"], true);
    assert!(!doc["verification"]["chain"]["not_protected"]
        .as_array()
        .unwrap()
        .is_empty());

    // A changed record: the bundle does not verify.
    let copy = dir.join("bundle");
    std::fs::create_dir_all(&copy).unwrap();
    for entry in std::fs::read_dir(&bundle).unwrap().flatten() {
        std::fs::copy(entry.path(), copy.join(entry.file_name())).unwrap();
    }
    let records = copy.join("records.jsonl");
    let text = std::fs::read_to_string(&records).unwrap();
    std::fs::write(&records, text.replacen("\"PASS\"", "\"BLOCK\"", 1)).unwrap();
    assert_eq!(run(&copy, &keys).status.code(), Some(1));

    // Keys are never taken from the bundle being checked.
    let inside = copy.join("keys.json");
    std::fs::copy(&keys, &inside).unwrap();
    let out = run(&copy, &inside);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stdout).contains("keys"));
}

#[test]
fn authorize_suggests_the_smallest_single_change_for_business_blocks_only() {
    let dir = scratch("counterfactual");
    assert_eq!(kavach(&dir, &["init"]).status.code(), Some(0));
    let ask = |args: &[&str]| {
        let mut all = vec!["--json", "authorize"];
        all.extend_from_slice(args);
        json(&kavach(&dir, &all))
    };
    let first = |doc: &Value| doc["counterfactuals"]["changes"][0].clone();

    let late = ask(&["send_reminder", "--at", "20:30"]);
    assert_eq!(
        late["counterfactuals"]["label"],
        "what-if under current policies"
    );
    assert_eq!(
        first(&late),
        serde_json::json!({ "change": "at", "value": "08:00 IST tomorrow", "decision": "PASS" })
    );
    let capped = ask(&["send_reminder", "--at", "11:00", "--contacts-today", "5"]);
    assert_eq!(first(&capped)["change"], "contacts_today");
    assert_eq!(first(&capped)["value"], "2");
    let sms = ask(&["send_reminder", "--at", "11:00", "-p", "channel=sms"]);
    assert_eq!(first(&sms)["value"], "whatsapp");
    let waiver = ask(&["propose_plan", "--at", "11:00", "-p", "waiver_bps=2500"]);
    assert_eq!(first(&waiver)["change"], "waiver_bps");
    assert_eq!(first(&waiver)["value"], "1000");

    // Safety blocks get no suggestions.
    for args in [
        &[
            "send_reminder",
            "--at",
            "11:00",
            "-p",
            "subject_ref=ref:borrower:9876543210",
        ][..],
        &[
            "send_reminder",
            "--at",
            "20:30",
            "-p",
            "subject_ref=ref:borrower:B-1",
        ],
        &[
            "send_reminder",
            "--at",
            "11:00",
            "--agent",
            "translation-agent",
        ],
    ] {
        let doc = ask(args);
        assert!(
            doc["counterfactuals"]["withheld"].is_string(),
            "{args:?}: {doc}"
        );
        assert_eq!(
            doc["counterfactuals"]["changes"],
            serde_json::json!([]),
            "{args:?}"
        );
    }
    // An allowed call has none.
    assert!(ask(&["send_reminder", "--at", "11:00"])["counterfactuals"].is_null());
}

/// `why` on a business block points to offline exploration, with
/// placeholders only.
fn why_explores_with_placeholders(dir: &Path, record_id: &str) {
    let why = json(&kavach(dir, &["--json", "why", record_id]));
    let explore = why["explore"].as_str().unwrap_or_default();
    assert!(
        explore.starts_with("kavach authorize send_reminder"),
        "{why}"
    );
    assert!(explore.contains("-p channel=<value>"), "{explore}");
    assert!(
        !explore.contains("sms") && !explore.contains("ref:"),
        "{explore}"
    );
}

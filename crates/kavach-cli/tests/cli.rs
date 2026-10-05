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

/// `n` distinct free loopback ports: every probe socket stays open until
/// all are chosen, so the system cannot hand out the same port twice.
fn free_ports(n: usize) -> Vec<u16> {
    let probes: Vec<TcpListener> = (0..n)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    probes
        .iter()
        .map(|l| l.local_addr().unwrap().port())
        .collect()
}

/// Moves every listener of a project (`"127.0.0.1:<port>"`) to its own free
/// port, so tests run in parallel and beside anything already on 8080. Safe
/// to run again: a retry gets new ports.
fn use_free_ports(dir: &Path) {
    const HOST: &str = "\"127.0.0.1:";
    let path = dir.join("kavach.toml");
    let text = std::fs::read_to_string(&path).unwrap();
    let mut ports = free_ports(text.matches(HOST).count()).into_iter();
    let mut out = String::with_capacity(text.len());
    let mut rest = text.as_str();
    while let Some(at) = rest.find(HOST) {
        let after = &rest[at + HOST.len()..];
        let digits = after.bytes().take_while(u8::is_ascii_digit).count();
        out.push_str(&rest[..at + HOST.len()]);
        if digits > 0 && after[digits..].starts_with('"') {
            out.push_str(&ports.next().unwrap().to_string());
            rest = &after[digits..];
        } else {
            rest = after;
        }
    }
    out.push_str(rest);
    std::fs::write(&path, out).unwrap();
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
    // A port another test took between choosing and binding: new ports, and
    // up to two more tries.
    let mut out = None;
    for _ in 0..3 {
        use_free_ports(&dir);
        let tried = kavach(
            &dir,
            &["--json", "dev", "up", "--at", "11:00", "--exit-when-ready"],
        );
        let done = tried.status.code() == Some(0);
        out = Some(tried);
        if done {
            break;
        }
    }
    let out = out.unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let doc = json(&out);
    assert_eq!(doc["command"], "dev up");
    assert_eq!(doc["store"], "memory");
    assert_eq!(doc["clock"]["kind"], "started_at");
    assert_eq!(doc["clock"]["development_only"], true);
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
    let cedar = doc["policy_versions"]["cedar"].as_str().unwrap();
    assert_eq!(cedar.len(), "sha256:".len() + 64, "printed whole: {cedar}");
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
fn authorize_suggests_the_bound_for_a_single_business_block_only() {
    let dir = scratch("counterfactual");
    assert_eq!(kavach(&dir, &["init"]).status.code(), Some(0));
    let ask = |args: &[&str]| {
        let mut all = vec!["--json", "authorize"];
        all.extend_from_slice(args);
        json(&kavach(&dir, &all))
    };
    let only = |doc: &Value| {
        assert_eq!(
            doc["counterfactuals"]["label"],
            "what-if under current policies"
        );
        let changes = doc["counterfactuals"]["changes"]
            .as_array()
            .unwrap()
            .clone();
        assert_eq!(changes.len(), 1, "{doc}");
        assert_eq!(changes[0]["decision"], "PASS");
        (
            changes[0]["suggestion"].as_str().unwrap().to_string(),
            changes[0]["bound"].as_str().unwrap().to_string(),
        )
    };

    let (s, b) = only(&ask(&["send_reminder", "--at", "20:30"]));
    assert_eq!(s, "at 08:00 IST tomorrow");
    assert_eq!(b, "contact window 08:00–19:00 IST");
    let (s, b) = only(&ask(&[
        "send_reminder",
        "--at",
        "11:00",
        "--contacts-today",
        "5",
    ]));
    assert_eq!(s, "after the daily cap resets (08:00 IST tomorrow)");
    assert_eq!(b, "contacts < 3 per IST day");
    let (s, _) = only(&ask(&[
        "send_reminder",
        "--at",
        "11:00",
        "-p",
        "channel=sms",
    ]));
    assert_eq!(s, "channel ∈ {whatsapp}");
    let (s, _) = only(&ask(&[
        "propose_plan",
        "--at",
        "11:00",
        "-p",
        "waiver_bps=2500",
    ]));
    assert_eq!(s, "waiver_bps ≤ 1000");

    // Two business constraints fail: no single change passes, so none is offered.
    let both = ask(&["send_reminder", "--at", "20:30", "--contacts-today", "3"]);
    let why = both["counterfactuals"]["withheld"].as_str().unwrap();
    assert!(why.contains("no single change passes"), "{both}");
    assert_eq!(both["counterfactuals"]["changes"], serde_json::json!([]));

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

/// A minimal HTTP/1.1 POST over loopback (the tests have no HTTP client).
fn post_json(addr: &str, path: &str, token: &str, body: &str) -> String {
    use std::io::{Read, Write};
    let mut stream = std::net::TcpStream::connect(addr).unwrap();
    write!(
        stream,
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {token}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default()
}

#[test]
fn why_explains_a_credit_decision_without_claiming_a_signature() {
    let dir = scratch("why-credit");
    assert_eq!(kavach(&dir, &["init"]).status.code(), Some(0));
    use_free_ports(&dir);
    let _stack = Stack(
        Command::new(env!("CARGO_BIN_EXE_kavach"))
            .arg("-C")
            .arg(&dir)
            .args(["dev", "up"])
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
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    let run: Value = serde_json::from_str(&std::fs::read_to_string(&run).unwrap()).unwrap();
    let operator = run["operator"].as_str().unwrap().to_string();
    let token = std::fs::read_to_string(dir.join(".kavach/operator.jwt")).unwrap();

    let fixture: Value = serde_json::from_str(
        &std::fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../golden/finance/v0/credit_missing_consent.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let mut request = fixture["request"].clone();
    let now = chrono_now();
    request["decision_time"] = now.clone().into();
    request["consent"]["timestamp"] = now.into();
    let reply = post_json(
        &operator,
        "/v1/evaluate",
        token.trim(),
        &request.to_string(),
    );
    let reply: Value = serde_json::from_str(&reply).unwrap_or_else(|_| panic!("{reply}"));
    let id = reply["evidence_id"].as_str().unwrap().to_string();

    let out = kavach(&dir, &["--json", "why", &id]);
    let doc = json(&out);
    assert_eq!(out.status.code(), Some(0), "{doc}");
    assert_eq!(doc["policy_decision"], "BLOCK");
    assert_eq!(doc["returned_decision"], "PASS");
    assert_eq!(doc["governance_mode"], "shadow");
    assert_eq!(doc["shadow_hides_decision"], true);
    assert_eq!(doc["integrity"]["signed"], false);
    assert_eq!(doc["reasons"][0]["code"], "CONSENT_MISMATCH");
    assert!(doc["counterfactuals"].is_null() && doc["explore"].is_null());
    // The digest is a known digest field: printed whole, never masked.
    let digest = doc["input_digest"].as_str().unwrap();
    assert_eq!(digest.len(), 64, "{digest}");
    assert!(digest.bytes().all(|b| b.is_ascii_hexdigit()), "{digest}");

    let text = String::from_utf8_lossy(&kavach(&dir, &["why", &id]).stdout).into_owned();
    assert!(
        text.contains("not signed, so this does not prove the record wasn't rewritten"),
        "{text}"
    );
    assert!(text.contains("hides a would-be BLOCK"), "{text}");
    assert!(!text.to_lowercase().contains("verified"), "{text}");
    assert!(!text.contains("signature"), "{text}");
}

/// Now as RFC 3339, without a chrono dependency in the tests.
fn chrono_now() -> String {
    let out = Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Starts `kavach dev up` in `dir` with extra arguments; waits for run.json.
fn dev_up(dir: &Path, extra: &[&str]) -> Stack {
    // A port another test took between choosing and binding makes the stack
    // exit at start: new ports, and up to two more tries.
    for attempt in 0..3 {
        if attempt > 0 {
            use_free_ports(dir);
        }
        if let Some(stack) = try_dev_up(dir, extra) {
            return stack;
        }
    }
    let log = std::fs::read_to_string(dir.join(".kavach/dev-up-test.log")).unwrap_or_default();
    panic!("dev up exited three times; its last stderr:\n{log}");
}

/// The stack, once its run.json appears; `None` if it exits first.
fn try_dev_up(dir: &Path, extra: &[&str]) -> Option<Stack> {
    let run = dir.join(".kavach/run.json");
    let _ = std::fs::remove_file(&run);
    let log = std::fs::File::create(dir.join(".kavach/dev-up-test.log")).unwrap();
    let mut args = vec!["dev", "up"];
    args.extend_from_slice(extra);
    let mut stack = Stack(
        Command::new(env!("CARGO_BIN_EXE_kavach"))
            .arg("-C")
            .arg(dir)
            .args(args)
            .stdout(std::process::Stdio::null())
            .stderr(log)
            .spawn()
            .unwrap(),
    );
    for _ in 0..120 {
        if run.is_file() {
            return Some(stack);
        }
        if stack.0.try_wait().unwrap().is_some() {
            return None;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    panic!("dev up did not start within 30 s");
}

/// `kavach attack`: the shared catalog against a real dev stack. Every
/// attack is refused as expected and ground truth agrees. Part of the 20×
/// acceptance gate.
#[test]
fn attack_catalog_is_refused_against_a_dev_stack() {
    let dir = scratch("attack");
    assert_eq!(kavach(&dir, &["init"]).status.code(), Some(0));
    use_free_ports(&dir);

    // The scope first, without a stack and without running anything.
    let listed = kavach(&dir, &["--json", "attack", "--list"]);
    let doc = json(&listed);
    assert_eq!(listed.status.code(), Some(0), "{doc}");
    assert_eq!(doc["ran"], false);
    let count = doc["attacks"].as_array().unwrap().len();
    assert!(count >= 18, "{doc}");
    assert!(doc["attacks"][0]["security_property"].is_string());

    // No stack: an error, nothing attacked.
    assert_eq!(kavach(&dir, &["attack"]).status.code(), Some(1));

    // A fixed clock, starting outside contact hours: the run moves it.
    let stack = dev_up(&dir, &["--clock", "20:30"]);
    let out = kavach(&dir, &["--json", "attack"]);
    let doc = json(&out);
    assert_eq!(out.status.code(), Some(0), "{doc}");
    assert_eq!(doc["ran"], true);
    assert_eq!(doc["breached"], false);
    assert_eq!(doc["credentials_minted"], 0);
    assert_eq!(doc["messages_delivered"], 0);
    assert_eq!(doc["setup_messages"], 3, "the daily-cap setup, declared");
    let outcomes = doc["outcomes"].as_array().unwrap();
    assert_eq!(outcomes.len(), count);
    for o in outcomes {
        assert_eq!(o["verdict"], "refused", "{o}");
    }
    drop(stack);

    // Outside contact hours on a clock it cannot move: inconclusive (2).
    let _stack = dev_up(&dir, &["--at", "20:30"]);
    let out = kavach(&dir, &["--json", "attack"]);
    let doc = json(&out);
    assert_eq!(out.status.code(), Some(2), "{doc}");
    assert_eq!(doc["ran"], false);
    assert!(
        doc["inconclusive"]
            .as_str()
            .unwrap()
            .contains("contact hours"),
        "{doc}"
    );
}

/// One raw HTTP/1.1 request; returns the status code.
fn raw_status(addr: &str, method: &str, path: &str, host: &str, headers: &[(&str, &str)]) -> u16 {
    use std::fmt::Write as _;
    use std::io::{Read, Write};
    let mut stream = std::net::TcpStream::connect(addr).unwrap();
    let extra = headers.iter().fold(String::new(), |mut out, (k, v)| {
        let _ = write!(out, "{k}: {v}\r\n");
        out
    });
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\n{extra}Content-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// `dev up`: the operator API needs the project's operator token, and every
/// listener refuses a foreign Host header (DNS rebinding) and the
/// self-asserted X-Kavach-Principal header.
#[test]
fn dev_up_requires_the_operator_token_and_a_local_host() {
    let dir = scratch("guard");
    assert_eq!(kavach(&dir, &["init"]).status.code(), Some(0));
    assert!(dir.join(".kavach/kavach/cedar/kavach.cedar").is_file());
    use_free_ports(&dir);
    let _stack = dev_up(&dir, &["--at", "11:00"]);
    let run: Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join(".kavach/run.json")).unwrap())
            .unwrap();
    let addr = |name: &str| run[name].as_str().unwrap().to_string();
    let operator = addr("operator");
    let token = std::fs::read_to_string(dir.join(".kavach/operator.jwt")).unwrap();
    let agent_token =
        std::fs::read_to_string(dir.join(".kavach/agents/collections-agent.jwt")).unwrap();
    let bearer = format!("Bearer {}", token.trim());
    let agent_bearer = format!("Bearer {}", agent_token.trim());

    let get = |headers: &[(&str, &str)]| {
        raw_status(&operator, "GET", "/v1/runtime", "127.0.0.1", headers)
    };
    assert_eq!(get(&[]), 401, "no token");
    assert_eq!(
        get(&[("Authorization", &bearer)]),
        200,
        "the operator token"
    );
    assert_eq!(
        get(&[("Authorization", &agent_bearer)]),
        401,
        "an agent's token"
    );
    assert_eq!(
        get(&[("X-Kavach-Principal", "admin-1")]),
        401,
        "a claimed identity"
    );
    assert_eq!(
        raw_status(
            &operator,
            "GET",
            "/v1/runtime",
            "localhost",
            &[("Authorization", &bearer)]
        ),
        200
    );

    // A foreign Host header, on every listener.
    for (name, method, path) in [
        ("operator", "GET", "/v1/runtime"),
        ("agent", "POST", "/v1/tools/send_reminder"),
        ("sor", "POST", "/v1/sor/events"),
        ("inspect", "GET", "/v1/inbox"),
    ] {
        assert_eq!(
            raw_status(
                &addr(name),
                method,
                path,
                "evil.example",
                &[("Authorization", &bearer)]
            ),
            421,
            "{name}"
        );
    }
}

/// `dev up --clock`: a fixed dev clock, moved only forward, that marks
/// evidence `dev_fixed`. The same stack allows at 11:00 and blocks at 20:30.
#[test]
fn a_fixed_dev_clock_moves_forward_and_marks_evidence() {
    let dir = scratch("clock");
    assert_eq!(kavach(&dir, &["init"]).status.code(), Some(0));
    use_free_ports(&dir);

    let banner = kavach(
        &dir,
        &[
            "--json",
            "dev",
            "up",
            "--clock",
            "11:00",
            "--exit-when-ready",
        ],
    );
    let doc = json(&banner);
    assert_eq!(banner.status.code(), Some(0), "{doc}");
    assert_eq!(doc["clock"]["kind"], "fixed");
    assert_eq!(doc["clock"]["at"], "2026-10-01T05:30:00Z");

    let stack = dev_up(&dir, &["--clock", "11:00"]);
    let call = |args: &[&str]| {
        let mut all = vec!["--json", "call", "send_reminder", "--issue-mandate"];
        all.extend_from_slice(args);
        json(&kavach(&dir, &all))
    };
    let allowed = call(&[]);
    assert_eq!(allowed["decision"], "PASS", "{allowed}");
    let record = allowed["reply"]["record_id"].as_str().unwrap().to_string();

    assert_eq!(
        kavach(&dir, &["dev", "clock", "20:30"]).status.code(),
        Some(0)
    );
    let late = call(&[]);
    assert_eq!(late["decision"], "BLOCK", "{late}");
    assert!(late["reply"]["reasons"]
        .to_string()
        .contains("contact-window"));

    // Only forward.
    assert_eq!(
        kavach(&dir, &["dev", "clock", "2026-10-01T05:00:00Z"])
            .status
            .code(),
        Some(64)
    );
    // HH:MM is the next occurrence: 11:00 tomorrow.
    let moved = json(&kavach(&dir, &["--json", "dev", "clock", "11:00"]));
    assert_eq!(moved["to"], "2026-10-02T05:30:00Z", "{moved}");

    let why = json(&kavach(&dir, &["--json", "why", &record]));
    assert_eq!(why["time_sync"]["status"], "dev_fixed", "{why}");
    drop(stack);

    // A started-at clock (--at) is marked too, and cannot be moved.
    let _stack = dev_up(&dir, &["--at", "11:00"]);
    let ran = call(&[]);
    let record = ran["reply"]["record_id"].as_str().unwrap().to_string();
    let why = json(&kavach(&dir, &["--json", "why", &record]));
    assert_eq!(why["time_sync"]["status"], "dev_fixed", "{why}");
    assert_eq!(
        kavach(&dir, &["dev", "clock", "12:00"]).status.code(),
        Some(1)
    );
}

/// `kavach demo`: every step of the story behaves as scripted, at any hour,
/// and the throwaway project is gone afterwards (kept with --keep). Part of
/// the 20× acceptance gate: it is the first-impression path.
#[test]
fn demo_runs_every_step_as_scripted() {
    let dir = scratch("demo");
    let out = kavach(&dir, &["--json", "demo"]);
    let doc = json(&out);
    assert_eq!(out.status.code(), Some(0), "{doc}");
    assert_eq!(doc["all_as_scripted"], true, "{doc}");
    let steps = doc["steps"].as_array().unwrap();
    assert_eq!(steps.len(), 9, "{doc}");
    for s in steps {
        assert_eq!(s["ok"], true, "{s}");
        assert!(s["command"].as_str().unwrap().starts_with("kavach "), "{s}");
    }
    assert!(doc["kept"].is_null());

    let kept = kavach(&dir, &["--json", "demo", "--keep", "--no-attack"]);
    let doc = json(&kept);
    assert_eq!(kept.status.code(), Some(0), "{doc}");
    assert_eq!(doc["steps"].as_array().unwrap().len(), 8, "no attack step");
    let path = PathBuf::from(doc["kept"].as_str().unwrap());
    assert!(path.join("kavach.toml").is_file(), "{}", path.display());
    assert!(!path.join(".kavach/run.json").exists(), "the stack stopped");
    std::fs::remove_dir_all(path).unwrap();
}

/// `kavach evidence verify`: what is not protected first, then what
/// verified; a changed record fails; keys never come from the bundle.
#[test]
fn evidence_verify_reports_what_is_not_protected_and_fails_a_changed_bundle() {
    let dir = scratch("evidence-verify");
    let keys = vectors().join("bundle-v1.keys.json");
    let verify = |bundle: &Path, extra: &[&str]| {
        let mut args = vec![
            "evidence",
            "verify",
            bundle.to_str().unwrap(),
            "--keys",
            keys.to_str().unwrap(),
        ];
        args.extend_from_slice(extra);
        kavach(&dir, &args)
    };

    let out = verify(&vectors().join("bundle-v1"), &[]);
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    assert_eq!(out.status.code(), Some(2), "{text}");
    let not_protected = text.find("NOT PROTECTED").expect("findings first");
    assert!(not_protected < text.find("VERIFIED:").unwrap(), "{text}");
    assert!(
        !text.contains("development:"),
        "test keys are not dev keys: {text}"
    );

    let out = verify(&vectors().join("bundle-v1"), &["--allow-warnings"]);
    assert_eq!(out.status.code(), Some(0));
    let mut args = vec!["--json"];
    args.extend(["evidence", "verify"]);
    let bundle = vectors().join("bundle-v1");
    args.push(bundle.to_str().unwrap());
    args.extend(["--keys", keys.to_str().unwrap()]);
    let doc = json(&kavach(&dir, &args));
    assert_eq!(doc["command"], "evidence verify");
    assert_eq!(doc["status"], "warnings");
    assert!(
        !doc["not_protected"].as_array().unwrap().is_empty(),
        "{doc}"
    );

    // One changed character in a record: it fails.
    let copy = dir.join("changed");
    std::fs::create_dir_all(&copy).unwrap();
    for file in [
        "manifest.json",
        "records.jsonl",
        "outcomes.jsonl",
        "checkpoints.jsonl",
    ] {
        std::fs::copy(vectors().join("bundle-v1").join(file), copy.join(file)).unwrap();
    }
    let records = std::fs::read_to_string(copy.join("records.jsonl")).unwrap();
    std::fs::write(
        copy.join("records.jsonl"),
        records.replacen("send_reminder", "send_remindex", 1),
    )
    .unwrap();
    let out = verify(&copy, &[]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("RESULT: FAILED"));
}

/// `kavach evidence export` from a dev stack on Postgres, then verify:
/// the exported bundle verifies against the project's auditor keys (dev),
/// and a changed copy fails. Skipped without KAVACH_TEST_DATABASE_URL.
#[test]
fn evidence_export_from_postgres_verifies_and_a_changed_copy_fails() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let Some(url) = runtime.block_on(kavach_storage::testing::isolated_database_url()) else {
        return;
    };
    let dir = scratch("evidence-export");
    assert_eq!(kavach(&dir, &["init"]).status.code(), Some(0));
    use_free_ports(&dir);
    let toml = dir.join("kavach.toml");
    let text = std::fs::read_to_string(&toml).unwrap();
    std::fs::write(&toml, format!("{text}\n[database]\nurl = \"{url}\"\n")).unwrap();

    let stack = dev_up(&dir, &["--at", "11:00"]);
    let called = kavach(
        &dir,
        &["--json", "call", "send_reminder", "--issue-mandate"],
    );
    assert_eq!(called.status.code(), Some(0), "{}", json(&called));

    let bundle = dir.join("export");
    let out = kavach(
        &dir,
        &["--json", "evidence", "export", bundle.to_str().unwrap()],
    );
    let doc = json(&out);
    assert!(matches!(out.status.code(), Some(0 | 2)), "{doc}");
    assert_eq!(doc["signed_with"], "dev-export-1", "{doc}");
    assert!(doc["records"].as_u64().unwrap() >= 1, "{doc}");
    drop(stack);

    // A second export into the same directory is refused, not merged.
    let again = kavach(&dir, &["evidence", "export", bundle.to_str().unwrap()]);
    assert_eq!(again.status.code(), Some(1));

    let out = kavach(
        &dir,
        &["--json", "evidence", "verify", bundle.to_str().unwrap()],
    );
    let doc = json(&out);
    assert!(matches!(out.status.code(), Some(0 | 2)), "{doc}");
    assert_eq!(doc["development"], true, "{doc}");
    assert_eq!(doc["verified"]["signed_with"], "dev-export-1", "{doc}");

    let records = std::fs::read_to_string(bundle.join("records.jsonl")).unwrap();
    std::fs::write(
        bundle.join("records.jsonl"),
        records.replacen("send_reminder", "send_remindex", 1),
    )
    .unwrap();
    let out = kavach(&dir, &["evidence", "verify", bundle.to_str().unwrap()]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
}

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

//! The binary keeps its name and its `verify` command after moving out of
//! the `kavach-evidence` library crate: existing pilot runbooks call
//! `kavach-evidence verify --file <export>`.

mod common;

use std::process::Command;

use chrono::Utc;
use kavach_domain::{Decision, GovernanceMode, ModelOrigin};
use kavach_evidence::{AppendDecisionEvent, MemoryChain};

/// A v1 `decision_events` export (NDJSON) of `n` events.
fn export(n: usize) -> String {
    let mut chain = MemoryChain::new();
    for i in 0..n {
        chain
            .append(AppendDecisionEvent {
                pack_id: "finance-v0".into(),
                pack_version: "0.1.0".into(),
                sector: "finance".into(),
                model_id: "credit-underwriting".into(),
                model_version: "1".into(),
                model_origin: ModelOrigin::InHouse,
                governance_mode: GovernanceMode::Enforce,
                policy_decision: Decision::Pass,
                returned_decision: Decision::Pass,
                reason_codes: vec![],
                policy_hits: vec![],
                pii_tokens: vec![],
                input_digest: format!("sha256:{i:064x}"),
                latency_ms: 1,
                decision_time: Utc::now(),
                evaluated_at: Utc::now(),
                service_identity_id: "svc-test".into(),
                correlation_id: format!("corr-{i}"),
                idempotency_key: None,
            })
            .expect("append");
    }
    chain
        .events()
        .iter()
        .map(|event| serde_json::to_string(event).unwrap() + "\n")
        .collect()
}

fn verify(file: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_kavach-evidence"))
        .args(["verify", "--file"])
        .arg(file)
        .output()
        .expect("run kavach-evidence")
}

#[test]
fn kavach_evidence_verify_still_checks_a_v1_export() {
    let good = common::scratch("v1-export.ndjson");
    std::fs::write(&good, export(3)).unwrap();
    let output = verify(&good);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{output:?}");
    assert!(
        stdout.starts_with("OK: verified 3 event(s); head_hash="),
        "{stdout}"
    );

    // An edited export fails, with a non-zero exit status.
    let tampered = common::scratch("v1-tampered.ndjson");
    std::fs::write(&tampered, export(3).replacen("corr-1", "corr-9", 1)).unwrap();
    let output = verify(&tampered);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).starts_with("FAIL: "));

    std::fs::remove_file(&good).unwrap();
    std::fs::remove_file(&tampered).unwrap();
}

#[test]
fn the_binary_is_named_kavach_evidence() {
    let path = std::path::Path::new(env!("CARGO_BIN_EXE_kavach-evidence"));
    assert_eq!(
        path.file_stem().and_then(|s| s.to_str()),
        Some("kavach-evidence")
    );
    let output = Command::new(path).arg("--help").output().unwrap();
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success() && help.contains("verify"), "{help}");
}

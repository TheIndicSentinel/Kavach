//! The outcome the reconciler writes for an allow whose own outcome could not
//! be recorded (F7) is an ordinary signed outcome row: `unknown`, with the
//! reason `outcome_not_recorded`, written minutes after its record. Both
//! verifiers must accept a bundle that holds one, say the same about it, and
//! refuse it when it is changed: no new field, no new format.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use chrono::Duration;
use kavach_evidence_cli::verify::{verify_dir, VerifyRequest};
use kavach_evidence_cli::writer::BundleWriter;
use kavach_ports::agent_evidence::{sign_outcome, Outcome, SegmentStart};

use common::*;

fn vectors() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

/// A bundle in which record 1 was delivered and record 3's outcome was lost
/// and recovered as `unknown` ten minutes later.
fn bundle(name: &str) -> PathBuf {
    bundle_with(name, true)
}

/// As [`bundle`]; with `with_outcome` false record 3 has no outcome at all.
fn bundle_with(name: &str, with_outcome: bool) -> PathBuf {
    let out = scratch(name);
    let chain = chain_v3();
    let decisions = records();
    let key = evidence_key();
    let recovered = |index: usize| {
        let record = &decisions[index];
        sign_outcome(
            TENANT,
            record.payload.credential_id.as_deref().unwrap(),
            &record.hash,
            Outcome::Unknown,
            "outcome_not_recorded",
            record.payload.ts + Duration::minutes(10),
            &key,
        )
        .unwrap()
    };
    let mut writer = BundleWriter::create(&out, SCOPE, SegmentStart::GENESIS).unwrap();
    for record in &chain {
        writer.record(record).unwrap();
    }
    let delivered = outcomes(&decisions).remove(0);
    writer.outcome(&delivered).unwrap();
    if with_outcome {
        writer.outcome(&recovered(2)).unwrap();
    }
    for checkpoint in checkpoints_v2(&chain) {
        writer.checkpoint(&checkpoint).unwrap();
    }
    writer
        .finish(exported_at(), exporter(), Some(&export_key()))
        .unwrap();
    out
}

fn rust_kinds(dir: &Path) -> Result<Vec<String>, String> {
    rust_kinds_at(dir, exported_at() + Duration::days(1))
}

fn rust_kinds_at(dir: &Path, at: chrono::DateTime<chrono::Utc>) -> Result<Vec<String>, String> {
    let keys = vectors().join("bundle-v2.keys.json");
    verify_dir(&VerifyRequest {
        bundle: dir,
        keys: &keys,
        expect_checkpoint: None,
        dev: false,
        now: at,
    })
    .map(|report| {
        let mut kinds: Vec<String> = report
            .not_protected()
            .iter()
            .map(|f| f.kind.to_string())
            .collect();
        kinds.sort();
        kinds
    })
    .map_err(|e| e.to_string())
}

/// The Python verifier's JSON; `None` without `python3` (CI must have it).
fn python(dir: &Path) -> Option<serde_json::Value> {
    python_at(dir, exported_at() + Duration::days(1))
}

fn python_at(dir: &Path, at: chrono::DateTime<chrono::Utc>) -> Option<serde_json::Value> {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance/kavach_verify.py");
    let now = at.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let output = Command::new("python3")
        .args(["-I"])
        .arg(script)
        .args(["bundle", "--keys"])
        .arg(vectors().join("bundle-v2.keys.json"))
        .args(["--allow-warnings", "--now", &now])
        .arg(dir)
        .output();
    let Ok(output) = output else {
        assert!(
            std::env::var_os("CI").is_none(),
            "python3 is required in CI for the verifier-agreement tests"
        );
        eprintln!("skipping: no python3");
        return None;
    };
    Some(serde_json::from_slice(&output.stdout).expect("the Python verifier prints JSON"))
}

#[test]
fn both_verifiers_accept_a_recovered_outcome_and_report_it_as_unknown() {
    let dir = bundle("f7-recovered");
    let rust = rust_kinds(&dir).expect("the Rust verifier accepts it");
    assert!(rust.contains(&"outcome_unknown".to_string()), "{rust:?}");
    let Some(py) = python(&dir) else { return };
    assert_ne!(py["result"], "fail", "{py}");
    let mut kinds: Vec<String> = py["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w["kind"].as_str().unwrap().to_string())
        .collect();
    kinds.sort();
    assert_eq!(kinds, rust, "the verifiers say the same about it");
}

#[test]
fn both_verifiers_refuse_a_recovered_outcome_that_was_changed() {
    let dir = bundle("f7-changed");
    let path = dir.join("outcomes.jsonl");
    let text = std::fs::read_to_string(&path).unwrap();
    // Say it was delivered: the manifest's digest and the row's signature
    // both catch it; the verifiers agree on which class of failure it is.
    std::fs::write(
        &path,
        text.replace("outcome_not_recorded", "provider_202")
            .replace("\"unknown\"", "\"delivered\""),
    )
    .unwrap();
    let rust = verify_dir(&VerifyRequest {
        bundle: &dir,
        keys: &vectors().join("bundle-v2.keys.json"),
        expect_checkpoint: None,
        dev: false,
        now: exported_at() + Duration::days(1),
    })
    .expect_err("the Rust verifier refuses it");
    assert_eq!(rust.class(), "digest");
    let Some(py) = python(&dir) else { return };
    assert_eq!(py["result"], "fail", "{py}");
    assert_eq!(py["class"], "digest", "{py}");
}

/// An allow that never got an outcome is reported as missing by both
/// verifiers however old it is: the reconciler stops looking after seven days
/// (`kavach_allows_without_outcome_beyond_lookback` counts what it leaves),
/// but the verifier has no such bound, so nothing disappears from an audit.
#[test]
fn an_allow_without_an_outcome_is_missing_however_old() {
    let dir = bundle_with("f7-old-missing", false);
    for days in [1, 8, 400] {
        let at = exported_at() + Duration::days(days);
        let rust = rust_kinds_at(&dir, at).expect("accepted, with a warning");
        assert!(
            rust.contains(&"outcome_missing".to_string()),
            "{days} days: {rust:?}"
        );
        let Some(py) = python_at(&dir, at) else {
            return;
        };
        let kinds: Vec<&str> = py["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|w| w["kind"].as_str().unwrap())
            .collect();
        assert!(kinds.contains(&"outcome_missing"), "{days} days: {py}");
    }
}

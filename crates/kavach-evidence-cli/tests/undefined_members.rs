//! A member a line does not define is refused (spec section 10.2, `read`).
//!
//! The members of a record, an outcome or a checkpoint are fixed by the
//! specification. A record's extra member is inside its hash, but an outcome's
//! or a checkpoint's is not, and a verifier that reads only the members it
//! knows would pass bytes nothing vouches for. Someone holding the export key
//! can reseal the manifest around such a line, so the test does: it adds a
//! member to every line of the `bundle-v4` vector (all three record kinds,
//! outcomes and checkpoints; one member at a time, also inside `time_sync`,
//! `actor` and `policy_versions`), reseals, and requires both verifiers to
//! refuse with the same class. The first run of the generated-history test
//! (the agreement generator) found that the Rust verifier accepted these.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use chrono::Duration;
use kavach_evidence_cli::verify::{verify_dir, VerifyRequest};
use kavach_ports::bundle::{
    seal_manifest, FileEntry, Files, Manifest, ManifestDraft, Segment, CHECKPOINTS_FILE,
    MANIFEST_FILE, OUTCOMES_FILE, RECORDS_FILE, RESOLUTIONS_FILE,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use common::*;

fn vectors() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

fn now() -> chrono::DateTime<chrono::Utc> {
    exported_at() + Duration::days(1)
}

fn rust(dir: &Path) -> Result<(), String> {
    verify_dir(&VerifyRequest {
        bundle: dir,
        keys: &vectors().join("bundle-v2.keys.json"),
        expect_checkpoint: None,
        dev: false,
        now: now(),
    })
    .map(|_| ())
    .map_err(|e| e.class().to_string())
}

fn python(dir: &Path) -> Result<(), String> {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance/kavach_verify.py");
    let output = Command::new("python3")
        .arg("-I")
        .arg(script)
        .args(["bundle", "--keys"])
        .arg(vectors().join("bundle-v2.keys.json"))
        .args(["--allow-warnings", "--now"])
        .arg(now().format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .arg(dir)
        .output()
        .expect("python3 is required for the verifier-agreement tests");
    let doc: Value =
        serde_json::from_slice(&output.stdout).expect("the Python verifier prints JSON");
    if doc["result"] == "fail" {
        Err(doc["class"].as_str().unwrap_or("?").to_string())
    } else {
        Ok(())
    }
}

fn entry(dir: &Path, file: &str) -> FileEntry {
    let bytes = fs::read(dir.join(file)).unwrap();
    FileEntry {
        sha256: format!("{:x}", Sha256::digest(&bytes)),
        count: u64::try_from(String::from_utf8_lossy(&bytes).lines().count()).unwrap(),
    }
}

/// The manifest, rewritten to match the files as they now are and signed with
/// the export key: what an exporter, or anyone holding that key, can do.
fn reseal(dir: &Path) {
    let old: Manifest =
        serde_json::from_slice(&fs::read(dir.join(MANIFEST_FILE)).unwrap()).unwrap();
    let manifest = seal_manifest(
        ManifestDraft {
            scope: SCOPE,
            segment: Segment {
                ..old.payload.segment
            },
            files: Files {
                records: entry(dir, RECORDS_FILE),
                outcomes: entry(dir, OUTCOMES_FILE),
                checkpoints: entry(dir, CHECKPOINTS_FILE),
                resolutions: Some(entry(dir, RESOLUTIONS_FILE)),
            },
            exported_at: exported_at(),
            exporter: exporter(),
        },
        Some(&export_key()),
    )
    .unwrap();
    fs::write(
        dir.join(MANIFEST_FILE),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
}

fn copy_v4(name: &str) -> PathBuf {
    let dir = scratch(name);
    fs::create_dir_all(&dir).unwrap();
    for file in fs::read_dir(vectors().join("bundle-v4")).unwrap() {
        let file = file.unwrap();
        fs::copy(file.path(), dir.join(file.file_name())).unwrap();
    }
    dir
}

fn lines(dir: &Path, file: &str) -> Vec<Value> {
    fs::read_to_string(dir.join(file))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

#[test]
fn the_unmodified_vector_still_verifies_in_both() {
    let dir = copy_v4("undefined-members-baseline");
    assert_eq!(rust(&dir), Ok(()));
    assert_eq!(python(&dir), Ok(()));
    // Resealing a bundle nobody changed must not change the verdict, so the
    // refusals below are down to the added member and nothing else.
    reseal(&dir);
    assert_eq!(rust(&dir), Ok(()));
    assert_eq!(python(&dir), Ok(()));
}

#[test]
fn an_undefined_member_on_any_line_is_refused_by_both_in_class_read() {
    let mut tried = 0;
    let mut kinds = std::collections::BTreeSet::new();
    for file in [RECORDS_FILE, OUTCOMES_FILE, CHECKPOINTS_FILE] {
        let count = lines(&copy_v4("undefined-members-count"), file).len();
        for at in 0..count {
            for nested in [
                None,
                Some("time_sync"),
                Some("actor"),
                Some("policy_versions"),
            ] {
                let dir = copy_v4("undefined-members");
                let mut all = lines(&dir, file);
                let target = match nested {
                    None => &mut all[at],
                    Some(name) => match all[at].get_mut(name) {
                        Some(inner) if inner.is_object() => inner,
                        _ => continue,
                    },
                };
                target["x_unsigned_note"] = json!("rides along");
                if file == RECORDS_FILE && nested.is_none() {
                    kinds.insert(all[at]["kind"].as_str().unwrap().to_string());
                }
                let text = all
                    .iter()
                    .map(Value::to_string)
                    .collect::<Vec<_>>()
                    .join("\n")
                    + "\n";
                fs::write(dir.join(file), text).unwrap();
                reseal(&dir);
                let what = format!("{file} line {} {nested:?}", at + 1);
                assert_eq!(rust(&dir), Err("read".into()), "Rust, {what}");
                assert_eq!(python(&dir), Err("read".into()), "Python, {what}");
                tried += 1;
            }
        }
    }
    assert!(tried >= 20, "only {tried} cases ran");
    assert_eq!(
        kinds.into_iter().collect::<Vec<_>>(),
        ["agent_decision", "agent_state", "mandate_revocation"],
        "the vector must hold every record kind"
    );
}

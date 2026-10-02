//! Known-answer vector for the evidence bundle format (v1).
//!
//! `tests/vectors/bundle-v1/` is a bundle written once from a fixed run
//! with test-only keys; `tests/vectors/bundle-v1.keys.json` holds the
//! public keys an operator would supply (they are **not** in the bundle).
//! Both are checked in, so a change to the bundle layout, the manifest or
//! any of the formats inside it shows up as a failure here. It is also
//! what an independent verifier is written against
//! (`docs/EVIDENCE_BUNDLE.md`).
//!
//! Regenerate only on a deliberate format change:
//! `cargo test -p kavach-evidence-cli --test vector -- --ignored generate`.

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use kavach_evidence_cli::writer::BundleWriter;
use kavach_ports::agent_evidence::{
    verify_segment, AgentDecisionRecord, DevKeys, OutcomeRecord, SegmentStart,
};
use kavach_ports::bundle::{
    verify_manifest, Manifest, ManifestSignature, CHECKPOINTS_FILE, MANIFEST_FILE, OUTCOMES_FILE,
    RECORDS_FILE,
};
use kavach_ports::checkpoint::{verify_checkpoints, ChainSegment, Checkpoint};
use kavach_ports::{KeyAlgorithm, PublicKey};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use common::*;

fn vectors() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

fn write_bundle(out: &Path) {
    let records = records();
    let mut writer = BundleWriter::create(out, SCOPE, SegmentStart::GENESIS).unwrap();
    for record in &records {
        writer.record(record).unwrap();
    }
    for outcome in outcomes(&records) {
        writer.outcome(&outcome).unwrap();
    }
    for checkpoint in checkpoints(&records) {
        writer.checkpoint(&checkpoint).unwrap();
    }
    writer
        .finish(exported_at(), exporter(), Some(&export_key()))
        .unwrap();
}

#[test]
#[ignore = "regenerates the checked-in vector; run only on a deliberate format change"]
fn generate() {
    let bundle = vectors().join("bundle-v1");
    let _ = fs::remove_dir_all(&bundle);
    fs::create_dir_all(vectors()).unwrap();
    write_bundle(&bundle);
    let keys: Vec<Value> = public_keys()
        .values()
        .map(
            |key| json!({ "kid": key.kid, "alg": "Ed25519", "public_key": hex::encode(key.bytes) }),
        )
        .collect();
    let file = json!({
        "description": "Public keys for tests/vectors/bundle-v1 (test keys only). A verifier is given keys like these by the operator; a bundle never contains them.",
        "keys": keys,
    });
    fs::write(
        vectors().join("bundle-v1.keys.json"),
        serde_json::to_string_pretty(&file).unwrap() + "\n",
    )
    .unwrap();
}

fn json_lines<T: DeserializeOwned>(path: &Path) -> Vec<T> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

/// The operator's keys file, read without any help from the fixture.
fn keys_from_file() -> BTreeMap<String, PublicKey> {
    let file: Value =
        serde_json::from_slice(&fs::read(vectors().join("bundle-v1.keys.json")).unwrap()).unwrap();
    file["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|key| {
            let kid = key["kid"].as_str().unwrap().to_string();
            let bytes = hex::decode(key["public_key"].as_str().unwrap()).unwrap();
            let public = PublicKey {
                kid: kid.clone(),
                algorithm: KeyAlgorithm::Ed25519,
                bytes: bytes.try_into().unwrap(),
            };
            (kid, public)
        })
        .collect()
}

#[test]
fn the_writer_reproduces_the_checked_in_bundle_byte_for_byte() {
    let out = scratch("vector");
    write_bundle(&out);
    for name in [MANIFEST_FILE, RECORDS_FILE, OUTCOMES_FILE, CHECKPOINTS_FILE] {
        assert_eq!(
            fs::read(out.join(name)).unwrap(),
            fs::read(vectors().join("bundle-v1").join(name)).unwrap(),
            "{name}: the bundle format changed (see the module docs)"
        );
    }
    fs::remove_dir_all(&out).unwrap();
}

/// What a verifier does, from the checked-in files and the operator's keys
/// alone (the steps of `docs/EVIDENCE_BUNDLE.md`).
#[test]
fn the_checked_in_bundle_verifies_from_its_files_and_the_operators_keys() {
    let bundle = vectors().join("bundle-v1");
    let keys = keys_from_file();

    let manifest: Manifest =
        serde_json::from_slice(&fs::read(bundle.join(MANIFEST_FILE)).unwrap()).unwrap();
    assert_eq!(
        verify_manifest(&manifest, &keys, DevKeys::Refuse),
        Ok(ManifestSignature::Signed {
            key_id: "export-kat-1".into()
        })
    );
    let p = &manifest.payload;
    assert_eq!(
        (p.format.as_str(), p.version),
        ("kavach-evidence-bundle", 1)
    );

    for (name, entry) in [
        (RECORDS_FILE, &p.files.records),
        (OUTCOMES_FILE, &p.files.outcomes),
        (CHECKPOINTS_FILE, &p.files.checkpoints),
    ] {
        let bytes = fs::read(bundle.join(name)).unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(&bytes)),
            entry.sha256,
            "{name}"
        );
        let count = String::from_utf8(bytes).unwrap().lines().count() as u64;
        assert_eq!(count, entry.count, "{name}");
    }

    let records: Vec<AgentDecisionRecord> = json_lines(&bundle.join(RECORDS_FILE));
    let outcomes: Vec<OutcomeRecord> = json_lines(&bundle.join(OUTCOMES_FILE));
    let checkpoints: Vec<Checkpoint> = json_lines(&bundle.join(CHECKPOINTS_FILE));
    let start = SegmentStart {
        seq: p.segment.after_seq,
        hash: &p.segment.after_hash,
    };
    // Well after every credential in the run has expired.
    let now = exported_at();
    let chain = verify_segment(
        &records,
        start,
        &keys,
        Some((p.segment.last_seq, &p.segment.head_hash)),
        &outcomes,
        now,
        DevKeys::Refuse,
    )
    .expect("records verify");
    assert_eq!((chain.records, chain.head_seq), (4, 4));
    // Record 4 was allowed and nothing says what happened; record 3's
    // outcome is recorded as unknown.
    assert_eq!(chain.outcome_missing, vec!["cred-4".to_string()]);
    assert_eq!(chain.outcome_unknown, vec!["cred-3".to_string()]);

    let segment = ChainSegment::of_records(start, &records);
    let report = verify_checkpoints(&checkpoints, SCOPE, &segment, &keys, DevKeys::Refuse)
        .expect("checkpoints verify");
    assert_eq!(report.last.map(|l| l.0), Some(3));
    assert_eq!(report.records_after_last, 1);

    // The bundle holds no key material: no file for it, no field for it.
    for name in [MANIFEST_FILE, RECORDS_FILE, OUTCOMES_FILE, CHECKPOINTS_FILE] {
        let text = fs::read_to_string(bundle.join(name)).unwrap();
        assert!(!text.contains("public_key"), "{name}");
        for key in keys.values() {
            assert!(!text.contains(&hex::encode(key.bytes)), "{name}");
        }
    }
}

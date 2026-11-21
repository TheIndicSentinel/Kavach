//! Known-answer vectors for the evidence bundle format.
//!
//! - `tests/vectors/bundle-v5/` is the current model-evidence bundle; older
//!   version fixtures remain fixed and are never rewritten.
//! - `tests/vectors/bundle-v1/` (format 1, decisions only) is kept
//!   byte-identical and is never regenerated: it shows that a bundle
//!   written before format 2 still verifies.
//!
//! Both are checked in, so a change to the bundle layout, the manifest or
//! any of the formats inside it shows up as a failure here. They are also
//! what an independent verifier is written against
//! (`docs/EVIDENCE_BUNDLE.md`).
//!
//! Regenerate a versioned fixture only on a deliberate format change with
//! its matching ignored `generate_vN` test.

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use kavach_evidence_cli::writer::BundleWriter;
use kavach_ports::agent_evidence::{
    verify_segment, AgentDecisionRecord, DevKeys, EvidenceSigner, OutcomeRecord, SegmentStart,
    TimeSync,
};
use kavach_ports::bundle::{
    manifest_signing_message, verify_manifest, Manifest, ManifestSignature, CHECKPOINTS_FILE,
    MANIFEST_FILE, OUTCOMES_FILE, RECORDS_FILE, RESOLUTIONS_FILE,
};
use kavach_ports::chain_record::ChainRecord;
use kavach_ports::checkpoint::{
    sign_checkpoint, verify_checkpoints, ChainSegment, Checkpoint, Head,
};
use kavach_ports::outcome_resolution::{
    resolution_message, ResolutionRecord, ResolutionSource, ResolutionState,
};
use kavach_ports::{KeyAlgorithm, PublicKey, SyncStatus, TrustedNow};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use common::*;

fn vectors() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

fn write_bundle(out: &Path) {
    write_chain(out, &chain_v2());
}

fn write_chain(out: &Path, chain: &[ChainRecord]) {
    let mut writer = BundleWriter::create(out, SCOPE, SegmentStart::GENESIS).unwrap();
    for record in chain {
        writer.record(record).unwrap();
    }
    for outcome in outcomes(&records()) {
        writer.outcome(&outcome).unwrap();
    }
    for checkpoint in checkpoints_v2(chain) {
        writer.checkpoint(&checkpoint).unwrap();
    }
    writer
        .finish(exported_at(), exporter(), Some(&export_key()))
        .unwrap();
    set_bundle_version(out, 4);
}

fn set_bundle_version(out: &Path, version: u32) {
    let path = out.join(MANIFEST_FILE);
    let mut manifest: Manifest = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    manifest.payload.version = version;
    if version < 4 {
        manifest.payload.files.resolutions = None;
        fs::remove_file(out.join(RESOLUTIONS_FILE)).unwrap();
    }
    manifest.hash = kavach_ports::bundle::manifest_hash(&manifest.payload).unwrap();
    manifest.sig = Some(hex::encode(
        export_key()
            .sign(&manifest_signing_message(&manifest.hash))
            .unwrap(),
    ));
    fs::write(path, serde_json::to_vec(&manifest).unwrap()).unwrap();
}

/// The format 4 run (`bundle-v4`): the format 3 chain with two unknown
/// outcomes and their resolutions.
fn write_v4(out: &Path) {
    let chain = chain_v3();
    let decisions = records();
    let outcomes = outcomes_v4(&decisions);
    let mut writer = BundleWriter::create(out, SCOPE, SegmentStart::GENESIS).unwrap();
    for record in &chain {
        writer.record(record).unwrap();
    }
    for outcome in &outcomes {
        writer.outcome(outcome).unwrap();
    }
    for checkpoint in checkpoints_v2(&chain) {
        writer.checkpoint(&checkpoint).unwrap();
    }
    for resolution in resolutions_v4(&outcomes) {
        writer.resolution(&resolution).unwrap();
    }
    writer
        .finish(exported_at(), exporter(), Some(&export_key()))
        .unwrap();
}

fn write_v5(out: &Path) {
    write_v5_chain(out, &chain_v5_model());
}

fn write_v5_chain(out: &Path, chain: &[ChainRecord]) {
    use kavach_ports::agent_evidence::ChainEntry as _;
    let mut writer = BundleWriter::create(out, SCOPE, SegmentStart::GENESIS).unwrap();
    for record in chain {
        writer.record(record).unwrap();
    }
    let last = chain.last().unwrap();
    let checkpoint = sign_checkpoint(
        Head {
            scope: SCOPE,
            seq: last.seq(),
            hash: last.hash(),
        },
        None,
        last.ts() + chrono::Duration::seconds(5),
        TimeSync {
            status: "synced".into(),
            max_error_ms: Some(12),
        },
        &checkpoint_key(),
    )
    .unwrap();
    writer.checkpoint(&checkpoint).unwrap();
    writer
        .finish(exported_at(), exporter(), Some(&export_key()))
        .unwrap();
}

fn model_chain_with_mismatched_outcome_link() -> Vec<ChainRecord> {
    use kavach_ports::chain_record::{seal_model_outcome, ModelOutcomeDraft, ModelOutcomeStatus};

    let mut chain = chain_v5_model();
    chain.truncate(1);
    let ChainRecord::ModelInvocation(invocation) = &chain[0] else {
        unreachable!("fixture begins with an invocation")
    };
    let mut wrong_reference = invocation.clone();
    wrong_reference.hash = "d".repeat(64);
    let now = TrustedNow {
        utc: t0() + chrono::Duration::seconds(10),
        sync: SyncStatus::Synced { max_error_ms: 12 },
    };
    let outcome = seal_model_outcome(
        ModelOutcomeDraft {
            invocation: wrong_reference,
            status: ModelOutcomeStatus::Completed,
            response_digest: Some("c".repeat(64)),
            duration_ms: 1_250,
        }
        .complete(2, &invocation.hash, evidence_key().0, now),
        &evidence_key(),
    )
    .unwrap();
    chain.push(ChainRecord::ModelOutcome(outcome));
    chain
}

#[test]
#[ignore = "regenerates the checked-in vector; run only on a deliberate format change"]
fn generate_v4() {
    let bundle = vectors().join("bundle-v4");
    let _ = fs::remove_dir_all(&bundle);
    write_v4(&bundle);
}

#[test]
#[ignore = "regenerates the checked-in vector; run only on a deliberate format change"]
fn generate_v5() {
    let bundle = vectors().join("bundle-v5");
    let _ = fs::remove_dir_all(&bundle);
    write_v5(&bundle);
}

#[test]
#[ignore = "regenerates the checked-in vector; run only on a deliberate format change"]
fn generate() {
    // The keys file only: historical bundle fixtures are never rewritten.
    fs::create_dir_all(vectors()).unwrap();
    let keys: Vec<Value> = public_keys()
        .values()
        .map(
            |key| json!({ "kid": key.kid, "alg": "Ed25519", "public_key": hex::encode(key.bytes) }),
        )
        .collect();
    let file = json!({
        "description": "Public keys for tests/vectors/bundle-v2 (test keys only). A verifier is given keys like these by the operator; a bundle never contains them.",
        "keys": keys,
    });
    fs::write(
        vectors().join("bundle-v2.keys.json"),
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

/// The operator's keys file for a vector, read without any help from the
/// fixture.
fn keys_from_file(vector: &str) -> BTreeMap<String, PublicKey> {
    let file: Value =
        serde_json::from_slice(&fs::read(vectors().join(format!("{vector}.keys.json"))).unwrap())
            .unwrap();
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

/// The current writer emits version 5. Historical vectors stay unchanged.
#[test]
fn the_writer_reproduces_the_checked_in_model_bundle_byte_for_byte() {
    let out = scratch("vector");
    write_v5(&out);
    for name in [
        MANIFEST_FILE,
        RECORDS_FILE,
        OUTCOMES_FILE,
        CHECKPOINTS_FILE,
        RESOLUTIONS_FILE,
    ] {
        assert_eq!(
            fs::read(out.join(name)).unwrap(),
            fs::read(vectors().join("bundle-v5").join(name)).unwrap(),
            "{name}: the bundle format changed (see the module docs)"
        );
    }
    fs::remove_dir_all(&out).unwrap();
}

/// What a verifier does, from the checked-in files and the operator's keys
/// alone (the steps of `docs/EVIDENCE_BUNDLE.md`): the format 1 bundle,
/// written before format 2 and never rewritten, still verifies.
#[test]
fn the_checked_in_bundle_verifies_from_its_files_and_the_operators_keys() {
    let bundle = vectors().join("bundle-v1");
    let keys = keys_from_file("bundle-v1");

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

/// Format 2 from its files and the operator's keys alone: decisions and a
/// revocation verify as one chain, the revocation names its event and the
/// mandates it revoked and no loan reference, and the third checkpoint
/// covers it.
#[test]
fn the_format_2_bundle_verifies_with_its_revocation() {
    let bundle = vectors().join("bundle-v2");
    let manifest: Manifest =
        serde_json::from_slice(&fs::read(bundle.join(MANIFEST_FILE)).unwrap()).unwrap();
    assert_eq!(manifest.payload.version, 2);
    let report =
        kavach_evidence_cli::verify::verify_dir(&kavach_evidence_cli::verify::VerifyRequest {
            bundle: &bundle,
            keys: &vectors().join("bundle-v2.keys.json"),
            expect_checkpoint: None,
            dev: false,
            now: exported_at(),
        })
        .expect("the bundle verifies");
    assert_eq!((report.records, report.last_seq), (5, 5));
    assert_eq!(
        (report.last_checkpoint, report.uncovered_records),
        (Some(5), 0)
    );

    let lines: Vec<ChainRecord> = json_lines(&bundle.join(RECORDS_FILE));
    let ChainRecord::Revocation(revocation) = &lines[4] else {
        panic!("record 5 is the revocation");
    };
    let p = &revocation.payload;
    assert_eq!(
        (p.kind.as_str(), p.event_id.as_str(), p.revoked.as_slice()),
        (
            "mandate_revocation",
            "pay-kat-1",
            &["ma-kat-root".to_string()][..]
        )
    );
    let text = fs::read_to_string(bundle.join(RECORDS_FILE)).unwrap();
    assert!(
        !text.contains("lms:loan") && !text.contains("record_ref"),
        "no loan reference"
    );
}

/// A record of a kind this verifier does not know fails the bundle, by
/// file and line, rather than being skipped; and a format 1 bundle may hold
/// decisions only.
#[test]
fn an_unknown_kind_or_a_revocation_in_format_1_is_refused() {
    let keys = vectors().join("bundle-v2.keys.json");
    let verify = |dir: &Path| {
        kavach_evidence_cli::verify::verify_dir(&kavach_evidence_cli::verify::VerifyRequest {
            bundle: dir,
            keys: &keys,
            expect_checkpoint: None,
            dev: false,
            now: exported_at(),
        })
    };
    let copy = |name: &str, edit: &dyn Fn(&mut Value)| {
        let out = scratch(name);
        let chain = chain_v2();
        let mut writer = BundleWriter::create(&out, SCOPE, SegmentStart::GENESIS).unwrap();
        for record in &chain {
            writer.record(record).unwrap();
        }
        for outcome in outcomes(&records()) {
            writer.outcome(&outcome).unwrap();
        }
        for checkpoint in checkpoints_v2(&chain) {
            writer.checkpoint(&checkpoint).unwrap();
        }
        writer.finish(exported_at(), exporter(), None).unwrap();
        // Rewrite the records file and re-seal the manifest over it, so only
        // the edit itself is wrong.
        let path = out.join(RECORDS_FILE);
        let mut lines: Vec<Value> = json_lines(&path);
        edit(&mut lines[4]);
        let text: String = lines.iter().map(|l| l.to_string() + "\n").collect();
        fs::write(&path, &text).unwrap();
        let mut manifest: Manifest =
            serde_json::from_slice(&fs::read(out.join(MANIFEST_FILE)).unwrap()).unwrap();
        manifest.payload.files.records.sha256 = format!("{:x}", Sha256::digest(text.as_bytes()));
        (out, manifest)
    };
    let seal = |out: &Path, mut manifest: Manifest, version: u32| {
        manifest.payload.version = version;
        // A bundle before version 4 has no resolutions file.
        manifest.payload.files.resolutions = None;
        let _ = fs::remove_file(out.join(RESOLUTIONS_FILE));
        manifest.hash = kavach_ports::bundle::manifest_hash(&manifest.payload).unwrap();
        manifest.sig = None;
        fs::write(
            out.join(MANIFEST_FILE),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
    };

    let (out, manifest) = copy("kind-unknown", &|record| {
        record["kind"] = "agent_taint".into();
    });
    seal(&out, manifest, 2);
    let err = verify(&out).unwrap_err().to_string();
    assert!(
        err.contains("records.jsonl") && err.contains("line 5"),
        "{err}"
    );
    assert!(err.contains("does not know"), "{err}");

    let (out, manifest) = copy("kind-in-v1", &|_| {});
    seal(&out, manifest, 1);
    let err = verify(&out).unwrap_err().to_string();
    assert!(
        err.contains("version 1 bundle holds decisions only"),
        "{err}"
    );
}

/// A member name used twice in one object is refused, even when both values
/// agree (docs/specs/evidence-bundle.md section 2.1): serde would keep the
/// last one, and an independent reader might keep the first.
#[test]
fn a_repeated_member_name_is_refused() {
    let out = scratch("duplicate-name");
    write_bundle(&out);
    let path = out.join(RECORDS_FILE);
    let text = fs::read_to_string(&path).unwrap();
    let (first, rest) = text.split_once('\n').unwrap();
    let first = format!("{},\"seq\":1}}", first.strip_suffix('}').unwrap());
    let text = format!("{first}\n{rest}");
    fs::write(&path, &text).unwrap();
    let mut manifest: Manifest =
        serde_json::from_slice(&fs::read(out.join(MANIFEST_FILE)).unwrap()).unwrap();
    manifest.payload.files.records.sha256 = format!("{:x}", Sha256::digest(text.as_bytes()));
    manifest.sig = None;
    manifest.payload.key_id = None;
    manifest.hash = kavach_ports::bundle::manifest_hash(&manifest.payload).unwrap();
    fs::write(
        out.join(MANIFEST_FILE),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
    let err =
        kavach_evidence_cli::verify::verify_dir(&kavach_evidence_cli::verify::VerifyRequest {
            bundle: &out,
            keys: &vectors().join("bundle-v2.keys.json"),
            expect_checkpoint: None,
            dev: false,
            now: exported_at(),
        })
        .unwrap_err()
        .to_string();
    assert!(err.contains("duplicate member name"), "{err}");
}

/// `bundle-v2-digest`: format 2 with the revocation stating its event by a
/// tagged digest, the form written now. `bundle-v2` (the legacy
/// `event_sha256`) is untouched. Same keys file.
#[test]
#[ignore = "regenerates the checked-in vector; run only on a deliberate format change"]
fn generate_digest() {
    let bundle = vectors().join("bundle-v2-digest");
    let _ = fs::remove_dir_all(&bundle);
    write_chain(&bundle, &chain_v2_digest());
}

#[test]
fn a_revocation_with_a_tagged_event_digest_verifies() {
    let bundle = vectors().join("bundle-v2-digest");
    let report =
        kavach_evidence_cli::verify::verify_dir(&kavach_evidence_cli::verify::VerifyRequest {
            bundle: &bundle,
            keys: &vectors().join("bundle-v2.keys.json"),
            expect_checkpoint: None,
            dev: false,
            now: exported_at(),
        })
        .expect("the bundle verifies");
    assert_eq!((report.records, report.last_seq), (5, 5));
    let text = fs::read_to_string(bundle.join(RECORDS_FILE)).unwrap();
    let last: Value = serde_json::from_str(text.lines().last().unwrap()).unwrap();
    assert!(last["event_digest"]
        .as_str()
        .unwrap()
        .starts_with("sha256-jcs-v1:"));
    assert!(last.get("event_sha256").is_none());
    // The legacy vector keeps its legacy member and is still byte-identical.
    let old = fs::read_to_string(vectors().join("bundle-v2").join(RECORDS_FILE)).unwrap();
    let old_last: Value = serde_json::from_str(old.lines().last().unwrap()).unwrap();
    assert!(old_last.get("event_sha256").is_some() && old_last.get("event_digest").is_none());
}

/// `bundle-v3`: format 3, the revocation by tagged digest, then a quarantine
/// and an approved reinstatement (`agent_state` records, ADR-013 §4). Same
/// keys file. The earlier vectors are untouched.
#[test]
#[ignore = "regenerates the checked-in vector; run only on a deliberate format change"]
fn generate_v3() {
    let bundle = vectors().join("bundle-v3");
    let _ = fs::remove_dir_all(&bundle);
    write_chain(&bundle, &chain_v3());
    set_bundle_version(&bundle, 3);
}

#[test]
fn the_format_3_bundle_verifies_with_its_agent_state_records() {
    let bundle = vectors().join("bundle-v3");
    let manifest: Manifest =
        serde_json::from_slice(&fs::read(bundle.join(MANIFEST_FILE)).unwrap()).unwrap();
    assert_eq!(manifest.payload.version, 3);
    let report =
        kavach_evidence_cli::verify::verify_dir(&kavach_evidence_cli::verify::VerifyRequest {
            bundle: &bundle,
            keys: &vectors().join("bundle-v2.keys.json"),
            expect_checkpoint: None,
            dev: false,
            now: exported_at(),
        })
        .expect("the bundle verifies");
    assert_eq!((report.records, report.last_seq), (7, 7));
    assert_eq!(
        (report.last_checkpoint, report.uncovered_records),
        (Some(7), 0)
    );
    let lines: Vec<ChainRecord> = json_lines(&bundle.join(RECORDS_FILE));
    let kinds: Vec<&str> = lines
        .iter()
        .map(kavach_ports::agent_evidence::ChainEntry::kind)
        .collect();
    assert_eq!(
        kinds[4..],
        ["mandate_revocation", "agent_state", "agent_state"]
    );
    let text = fs::read_to_string(bundle.join(RECORDS_FILE)).unwrap();
    assert!(
        text.contains("\"reason_code\":\"rogue_behaviour\"") && !text.contains("\"note\""),
        "a closed reason code, never free text"
    );
}

/// A version 2 bundle holds no agent-state record: its verifier refuses one.
#[test]
fn a_version_2_bundle_refuses_an_agent_state_record() {
    let out = scratch("v2-with-state");
    write_chain(&out, &chain_v3());
    let mut manifest: Manifest =
        serde_json::from_slice(&fs::read(out.join(MANIFEST_FILE)).unwrap()).unwrap();
    manifest.payload.version = 2;
    // A bundle before version 4 has no resolutions file.
    manifest.payload.files.resolutions = None;
    fs::remove_file(out.join(RESOLUTIONS_FILE)).unwrap();
    manifest.payload.key_id = None;
    manifest.sig = None;
    manifest.hash = kavach_ports::bundle::manifest_hash(&manifest.payload).unwrap();
    fs::write(
        out.join(MANIFEST_FILE),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
    let err =
        kavach_evidence_cli::verify::verify_dir(&kavach_evidence_cli::verify::VerifyRequest {
            bundle: &out,
            keys: &vectors().join("bundle-v2.keys.json"),
            expect_checkpoint: None,
            dev: false,
            now: exported_at(),
        })
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("a version 2 bundle holds decisions and revocations only"),
        "{err}"
    );
}

// ------------------------------------------------------------------ version 4

fn verify_dir(dir: &Path) -> Result<kavach_ports::bundle_verify::BundleReport, String> {
    kavach_evidence_cli::verify::verify_dir(&kavach_evidence_cli::verify::VerifyRequest {
        bundle: dir,
        keys: &vectors().join("bundle-v2.keys.json"),
        expect_checkpoint: None,
        dev: false,
        now: exported_at(),
    })
    .map_err(|e| e.to_string())
}

#[test]
fn version_5_exports_and_verifies_model_records_while_version_4_refuses_them() {
    let out = scratch("bundle-v5-model");
    write_v5(&out);
    let manifest: Manifest =
        serde_json::from_slice(&fs::read(out.join(MANIFEST_FILE)).unwrap()).unwrap();
    assert_eq!(manifest.payload.version, 5);
    assert_eq!(manifest.payload.files.records.count, 2);
    let report = verify_dir(&out).expect("version 5 model bundle verifies");
    assert_eq!((report.records, report.last_seq), (2, 2));

    let mut old_manifest = manifest;
    old_manifest.payload.version = 4;
    old_manifest.hash = kavach_ports::bundle::manifest_hash(&old_manifest.payload).unwrap();
    old_manifest.sig = Some(hex::encode(
        export_key()
            .sign(&manifest_signing_message(&old_manifest.hash))
            .unwrap(),
    ));
    fs::write(
        out.join(MANIFEST_FILE),
        serde_json::to_vec(&old_manifest).unwrap(),
    )
    .unwrap();
    let error = verify_dir(&out).expect_err("version 4 must refuse model records");
    assert!(
        error.contains("bundle version 4 does not support this record kind"),
        "{error}"
    );
    fs::remove_dir_all(out).unwrap();
}

#[test]
fn version_5_refuses_an_outcome_link_to_another_invocation_hash() {
    let out = scratch("bundle-v5-bad-model-link");
    write_v5_chain(&out, &model_chain_with_mismatched_outcome_link());
    let error = verify_dir(&out).expect_err("mismatched invocation link must fail");
    assert!(
        error.contains("does not link to its model invocation"),
        "{error}"
    );
    fs::remove_dir_all(out).unwrap();
}

#[test]
fn the_format_4_bundle_verifies_and_reports_the_governing_states() {
    let bundle = vectors().join("bundle-v4");
    let manifest: Manifest =
        serde_json::from_slice(&fs::read(bundle.join(MANIFEST_FILE)).unwrap()).unwrap();
    assert_eq!(manifest.payload.version, 4);
    assert_eq!(
        manifest.payload.files.resolutions.as_ref().unwrap().count,
        3
    );
    let report = verify_dir(&bundle).expect("the bundle verifies");
    assert_eq!((report.records, report.last_seq), (7, 7));
    assert_eq!((report.outcomes, report.resolutions), (3, 3));
    // Record 3's result is confirmed delivered by the provider (settled, so
    // not a warning); record 4's has two different confirmed answers and
    // nothing closes the conflict.
    assert_eq!(
        report.outcome_resolved.count, 1,
        "{:?}",
        report.outcome_resolved
    );
    assert!(report.outcome_resolved.first[0].contains("confirmed_delivered by provider_status"));
    assert_eq!(report.outcome_conflicted.count, 1);
    assert_eq!(report.outcome_unknown.count, 0);
    let kinds: Vec<&str> = report.not_protected().iter().map(|f| f.kind).collect();
    assert_eq!(kinds, ["no_kept_checkpoint", "outcome_conflicted"]);
}

/// A bundle of version 4 whose resolutions are `resolutions` and whose
/// outcomes are the format 4 run's.
fn v4_with(name: &str, resolutions: &[ResolutionRecord]) -> PathBuf {
    let out = scratch(name);
    let chain = chain_v3();
    let outcomes = outcomes_v4(&records());
    let mut writer = BundleWriter::create(&out, SCOPE, SegmentStart::GENESIS).unwrap();
    for record in &chain {
        writer.record(record).unwrap();
    }
    for outcome in &outcomes {
        writer.outcome(outcome).unwrap();
    }
    for checkpoint in checkpoints_v2(&chain) {
        writer.checkpoint(&checkpoint).unwrap();
    }
    for resolution in resolutions {
        writer.resolution(resolution).unwrap();
    }
    writer
        .finish(exported_at(), exporter(), Some(&export_key()))
        .unwrap();
    out
}

/// Re-signs `record` as written (the form is whatever was set), so that only
/// the form or the reference is what is wrong, never the signature.
fn resigned(mut record: ResolutionRecord, key: &Key) -> ResolutionRecord {
    use ed25519_dalek::Signer as _;
    record.key_id = key.0.to_string();
    record.sig = hex::encode(key.1.sign(&resolution_message(&record)).to_bytes());
    record
}

/// Resolutions that break a rule of the format, each with the reason the
/// verifier must give (the cases of docs/specs/evidence-bundle.md section 10.1).
fn rule_breaking_resolutions() -> Vec<(&'static str, ResolutionRecord, &'static str)> {
    use ResolutionSource::{ConflictResolution, OperatorAttested, ProviderStatus, Reconciler};
    use ResolutionState::{
        Ambiguous, ConfirmedDelivered as Delivered, ConfirmedNotDelivered as Not,
    };
    let outcomes = outcomes_v4(&records());
    let (settled, unknown) = (&outcomes[0], &outcomes[1]);
    let key = evidence_key();
    let valid = resolution_of(
        unknown,
        (Delivered, ProviderStatus),
        Some("answer"),
        (None, None),
        5,
    );
    let with = |change: &dyn Fn(&mut ResolutionRecord)| {
        let mut r = valid.clone();
        change(&mut r);
        resigned(r, &key)
    };
    let people = |by: Option<&str>, approver: Option<&str>| {
        let by = by.map(str::to_string);
        let approver = approver.map(str::to_string);
        move |r: &mut ResolutionRecord| {
            r.source = OperatorAttested;
            r.state = Not;
            r.resolved_by.clone_from(&by);
            r.approved_by.clone_from(&approver);
        }
    };
    vec![
        (
            "settled",
            resigned(
                resolution_of(
                    settled,
                    (Delivered, ProviderStatus),
                    Some("answer"),
                    (None, None),
                    5,
                ),
                &key,
            ),
            "no unknown outcome of this bundle",
        ),
        (
            "other-row",
            with(&|r| r.outcome_ref = "00".repeat(32)),
            "another outcome row",
        ),
        (
            "no-outcome",
            with(&|r| r.credential_id = "cred-none".into()),
            "no unknown outcome of this bundle",
        ),
        (
            "one-person-not-delivered",
            with(&|r| people(Some("alice"), None)(r)),
            "second, different person",
        ),
        (
            "same-person",
            with(&|r| people(Some("alice"), Some("alice"))(r)),
            "second, different person",
        ),
        (
            "reconciler-confirming",
            with(&|r| {
                r.source = Reconciler;
                r.evidence_digest = None;
            }),
            "only says ambiguous",
        ),
        (
            "closure-by-one",
            with(&|r| {
                r.source = ConflictResolution;
                r.resolved_by = Some("carol".into());
                r.approved_by = None;
            }),
            "two different people",
        ),
        (
            "ambiguous-closure",
            with(&|r| {
                r.source = ConflictResolution;
                r.state = Ambiguous;
                r.resolved_by = Some("carol".into());
                r.approved_by = Some("dave".into());
            }),
            "closed by a confirmed state",
        ),
    ]
}

/// Resolutions that are wrong in time or in their signature.
fn untrustworthy_resolutions() -> Vec<(&'static str, ResolutionRecord, &'static str)> {
    use ResolutionSource::ProviderStatus;
    use ResolutionState::ConfirmedDelivered as Delivered;
    let outcomes = outcomes_v4(&records());
    let unknown = &outcomes[1];
    let key = evidence_key();
    let valid = resolution_of(
        unknown,
        (Delivered, ProviderStatus),
        Some("answer"),
        (None, None),
        5,
    );
    vec![
        (
            "before-its-outcome",
            resigned(
                resolution_of(
                    unknown,
                    (Delivered, ProviderStatus),
                    Some("answer"),
                    (None, None),
                    -5,
                ),
                &key,
            ),
            "before the outcome",
        ),
        (
            "forged",
            {
                let mut r = valid.clone();
                r.sig = "00".repeat(64);
                r
            },
            "does not verify",
        ),
        (
            "development-key",
            resigned(
                valid.clone(),
                &Key(
                    "dev-evidence-kat",
                    ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]),
                ),
            ),
            "development key",
        ),
    ]
}

/// "Nobody could say" is the reconciler's statement and nobody else's.
fn ambiguity_from_the_wrong_source() -> Vec<(&'static str, ResolutionRecord, &'static str)> {
    use ResolutionSource::{OperatorAttested, ProviderStatus};
    use ResolutionState::{Ambiguous, ConfirmedDelivered as Delivered};
    let outcomes = outcomes_v4(&records());
    let unknown = &outcomes[1];
    let key = evidence_key();
    // Built as a valid confirmed line, then changed to say ambiguous and
    // signed again: only the rule is wrong, never the signature.
    let said_ambiguous = |source, people: (Option<&str>, Option<&str>)| {
        let mut row = resolution_of(unknown, (Delivered, source), Some("answer"), people, 5);
        row.state = Ambiguous;
        resigned(row, &key)
    };
    vec![
        (
            "provider-says-ambiguous",
            said_ambiguous(ProviderStatus, (None, None)),
            "only the reconciler says ambiguous",
        ),
        (
            "person-says-ambiguous",
            said_ambiguous(OperatorAttested, (Some("alice"), None)),
            "only the reconciler says ambiguous",
        ),
    ]
}

/// Every resolution a verifier must refuse, with the reason.
fn every_refused_resolution() -> Vec<(&'static str, ResolutionRecord, &'static str)> {
    let mut all = rule_breaking_resolutions();
    all.extend(untrustworthy_resolutions());
    all.extend(ambiguity_from_the_wrong_source());
    all
}

/// The independent Python verifier agrees on every one of them: it refuses the
/// same bundle, and says the same class of reason (the resolution), so the two
/// cannot both refuse and disagree about why.
#[test]
fn the_python_verifier_refuses_every_refused_resolution_in_the_same_class() {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance/kavach_verify.py");
    for (name, resolution, _) in every_refused_resolution() {
        let out = v4_with(&format!("v4-py-{name}"), &[resolution]);
        let output = std::process::Command::new("python3")
            .arg("-I")
            .arg(&script)
            .args(["bundle", "--keys"])
            .arg(vectors().join("bundle-v2.keys.json"))
            .args(["--allow-warnings", "--now", "2026-10-02T07:00:00Z"])
            .arg(&out)
            .output();
        let Ok(output) = output else {
            assert!(
                std::env::var_os("CI").is_none(),
                "python3 is required in CI for the verifier-agreement tests"
            );
            eprintln!("skipping: no python3");
            return;
        };
        let text = String::from_utf8_lossy(&output.stdout);
        let python: Value =
            serde_json::from_str(&text).unwrap_or_else(|e| panic!("{name}: {e}: {text}"));
        assert_eq!(python["result"], "fail", "{name}: {python}");
        assert_eq!(python["class"], "resolution", "{name}: {python}");
    }
}

/// Every way a resolution can be wrong is refused by the verifier, for its
/// own reason (docs/specs/evidence-bundle.md section 10.1).
#[test]
fn a_version_4_bundle_refuses_a_resolution_that_breaks_the_rules() {
    let valid = resolutions_v4(&outcomes_v4(&records())).remove(0);
    for (name, resolution, expected) in every_refused_resolution() {
        let out = v4_with(&format!("v4-{name}"), &[resolution]);
        let err = verify_dir(&out).expect_err(name);
        assert!(
            err.contains("resolutions.jsonl line 1") && err.contains(expected),
            "{name}: {err}"
        );
    }
    // A repeat of (credential, source, state) is refused at its second line.
    let out = v4_with("v4-repeat", &[valid.clone(), valid]);
    let err = verify_dir(&out).unwrap_err();
    assert!(err.contains("line 2") && err.contains("repeats"), "{err}");
}

/// A member the format does not define is refused: nothing unsigned rides
/// along with a signed resolution.
#[test]
fn a_resolution_with_an_unknown_member_is_refused() {
    let outcomes = outcomes_v4(&records());
    let valid = resolutions_v4(&outcomes).remove(0);
    let out = v4_with("v4-extra-member", &[]);
    let mut line: Value = serde_json::to_value(&valid).unwrap();
    line["note"] = "unsigned words".into();
    let text = line.to_string() + "\n";
    fs::write(out.join(RESOLUTIONS_FILE), &text).unwrap();
    let mut manifest: Manifest =
        serde_json::from_slice(&fs::read(out.join(MANIFEST_FILE)).unwrap()).unwrap();
    let entry = manifest.payload.files.resolutions.as_mut().unwrap();
    entry.sha256 = format!("{:x}", Sha256::digest(text.as_bytes()));
    entry.count = 1;
    manifest.payload.key_id = None;
    manifest.sig = None;
    manifest.hash = kavach_ports::bundle::manifest_hash(&manifest.payload).unwrap();
    fs::write(
        out.join(MANIFEST_FILE),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
    let err = verify_dir(&out).unwrap_err();
    assert!(
        err.contains("resolutions.jsonl") && err.contains("unknown field"),
        "{err}"
    );
}

/// A resolution is never accepted inside a format that did not define it, and
/// never missing from one that did.
#[test]
fn the_resolutions_file_is_required_from_version_4_onward() {
    // A resolutions file inside a version 3 bundle.
    let out = scratch("v3-with-resolutions");
    for name in [MANIFEST_FILE, RECORDS_FILE, OUTCOMES_FILE, CHECKPOINTS_FILE] {
        fs::copy(vectors().join("bundle-v3").join(name), out.join(name)).unwrap_or_else(|_| {
            fs::create_dir_all(&out).unwrap();
            fs::copy(vectors().join("bundle-v3").join(name), out.join(name)).unwrap()
        });
    }
    verify_dir(&out).expect("the untouched version 3 bundle verifies");
    fs::write(out.join(RESOLUTIONS_FILE), "").unwrap();
    let err = verify_dir(&out).unwrap_err();
    assert!(err.contains("unexpected entry resolutions.jsonl"), "{err}");

    // A version 4 bundle without its resolutions file.
    let v4 = v4_with("v4-missing-file", &[]);
    fs::remove_file(v4.join(RESOLUTIONS_FILE)).unwrap();
    let err = verify_dir(&v4).unwrap_err();
    assert!(err.contains("resolutions.jsonl is missing"), "{err}");

    // A version 4 manifest that does not list the file.
    let v4 = v4_with("v4-unlisted", &[]);
    let mut manifest: Manifest =
        serde_json::from_slice(&fs::read(v4.join(MANIFEST_FILE)).unwrap()).unwrap();
    manifest.payload.files.resolutions = None;
    manifest.payload.key_id = None;
    manifest.sig = None;
    manifest.hash = kavach_ports::bundle::manifest_hash(&manifest.payload).unwrap();
    fs::write(
        v4.join(MANIFEST_FILE),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
    let err = verify_dir(&v4).unwrap_err();
    assert!(err.contains("lists its resolutions file"), "{err}");

    // Version 5 also requires the file.
    let v5 = scratch("v5-missing-resolutions");
    write_v5(&v5);
    fs::remove_file(v5.join(RESOLUTIONS_FILE)).unwrap();
    let err = verify_dir(&v5).unwrap_err();
    assert!(err.contains("resolutions.jsonl is missing"), "{err}");
    fs::remove_dir_all(v5).unwrap();
}

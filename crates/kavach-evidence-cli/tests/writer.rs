//! The bundle writer: a whole bundle or nothing, never over anything, and
//! only what forms one segment of one chain.

mod common;

use std::fs;
use std::path::Path;

use kavach_evidence_cli::writer::{BundleError, BundleWriter};
use kavach_ports::agent_evidence::{DevKeys, SegmentStart};
use kavach_ports::bundle::{
    verify_manifest, Manifest, ManifestSignature, CHECKPOINTS_FILE, MANIFEST_FILE, OUTCOMES_FILE,
    RECORDS_FILE,
};
use kavach_ports::checkpoint::Scope;
use sha2::{Digest, Sha256};

use common::*;

const FILES: [&str; 4] = [MANIFEST_FILE, RECORDS_FILE, OUTCOMES_FILE, CHECKPOINTS_FILE];

fn partial(out: &Path) -> std::path::PathBuf {
    out.with_file_name(format!(
        "{}.partial",
        out.file_name().unwrap().to_str().unwrap()
    ))
}

fn sha256(path: &Path) -> String {
    format!("{:x}", Sha256::digest(fs::read(path).unwrap()))
}

fn lines(path: &Path) -> u64 {
    fs::read_to_string(path).unwrap().lines().count() as u64
}

/// Writes the whole fixture run to `out`, signed with the export key.
fn write_all(out: &Path) -> Manifest {
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
        .unwrap()
}

#[test]
fn a_finished_bundle_is_whole_owner_only_and_matches_its_manifest() {
    let out = scratch("bundle");
    let manifest = write_all(&out);

    let mut names: Vec<_> = fs::read_dir(&out)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    let mut expected = FILES.map(String::from).to_vec();
    expected.sort();
    assert_eq!(
        names, expected,
        "exactly the four files, and no public keys"
    );
    assert!(!partial(&out).exists());

    // The manifest on disk is the one returned, and it verifies.
    let stored: Manifest =
        serde_json::from_slice(&fs::read(out.join(MANIFEST_FILE)).unwrap()).unwrap();
    assert_eq!(stored, manifest);
    assert_eq!(
        verify_manifest(&stored, &public_keys(), DevKeys::Refuse),
        Ok(ManifestSignature::Signed {
            key_id: "export-kat-1".into()
        })
    );
    // It describes the files as they are.
    let p = &manifest.payload;
    for (name, entry, count) in [
        (RECORDS_FILE, &p.files.records, 4),
        (OUTCOMES_FILE, &p.files.outcomes, 2),
        (CHECKPOINTS_FILE, &p.files.checkpoints, 2),
    ] {
        assert_eq!(entry.sha256, sha256(&out.join(name)), "{name}");
        assert_eq!(
            (entry.count, lines(&out.join(name))),
            (count, count),
            "{name}"
        );
    }
    let records = records();
    assert_eq!((p.segment.after_seq, p.segment.last_seq), (0, 4));
    assert_eq!(p.segment.head_hash, records[3].hash);
    assert_eq!((p.tenant_id.as_str(), p.partition_id), (TENANT, 0));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&out), 0o700);
        for name in FILES {
            assert_eq!(mode(&out.join(name)), 0o600, "{name}");
        }
    }
    fs::remove_dir_all(&out).unwrap();
}

#[test]
fn a_bundle_is_never_written_over_anything() {
    // An existing directory (even an empty one), a file, a leftover partial.
    let dir = scratch("exists-dir");
    fs::create_dir(&dir).unwrap();
    let file = scratch("exists-file");
    fs::write(&file, "keep me").unwrap();
    let leftover = scratch("exists-partial");
    fs::create_dir(partial(&leftover)).unwrap();

    for out in [&dir, &file, &leftover] {
        let refused = BundleWriter::create(out, SCOPE, SegmentStart::GENESIS)
            .err()
            .expect("refused");
        assert!(matches!(refused, BundleError::Exists(_)), "{refused}");
    }
    assert!(fs::read_dir(&dir).unwrap().next().is_none());
    assert_eq!(fs::read_to_string(&file).unwrap(), "keep me");
    assert!(
        partial(&leftover).exists(),
        "a leftover is the caller's to remove"
    );
    assert!(!leftover.exists());

    fs::remove_dir(&dir).unwrap();
    fs::remove_file(&file).unwrap();
    fs::remove_dir(partial(&leftover)).unwrap();
}

#[test]
fn an_unfinished_or_failed_bundle_leaves_nothing_behind() {
    let records = records();

    // Dropped part-way.
    let out = scratch("dropped");
    let mut writer = BundleWriter::create(&out, SCOPE, SegmentStart::GENESIS).unwrap();
    writer.record(&records[0]).unwrap();
    assert!(partial(&out).exists() && !out.exists());
    drop(writer);
    assert!(!partial(&out).exists() && !out.exists());

    // Signing refused at the end: a key that is not an export key.
    let out = scratch("wrong-key");
    let mut writer = BundleWriter::create(&out, SCOPE, SegmentStart::GENESIS).unwrap();
    writer.record(&records[0]).unwrap();
    let refused = writer
        .finish(exported_at(), exporter(), Some(&checkpoint_key()))
        .expect_err("refused");
    assert!(matches!(refused, BundleError::Manifest(_)), "{refused}");
    assert!(
        refused.to_string().contains("not an export key"),
        "{refused}"
    );
    assert!(!partial(&out).exists() && !out.exists());
}

#[test]
fn only_one_segment_of_one_chain_is_accepted() {
    let records = records();
    let checkpoints = checkpoints(&records);
    let outcomes = outcomes(&records);
    let out = scratch("inconsistent");
    let refuse = |result: Result<(), BundleError>, what: &str| {
        let err = result.expect_err(what);
        assert!(matches!(err, BundleError::Inconsistent(_)), "{what}: {err}");
    };

    let mut writer = BundleWriter::create(&out, SCOPE, SegmentStart::GENESIS).unwrap();
    refuse(writer.record(&records[1]), "a record that skips one");
    writer.record(&records[0]).unwrap();
    refuse(writer.record(&records[0]), "the same record twice");
    let mut unlinked = records[1].clone();
    unlinked.payload.prev_hash = "ee".repeat(32);
    refuse(writer.record(&unlinked), "a record that does not link");
    let mut foreign = records[1].clone();
    foreign.payload.tenant_id = "other".into();
    refuse(writer.record(&foreign), "another tenant's record");
    writer.record(&records[1]).unwrap();

    let mut foreign = outcomes[0].clone();
    foreign.tenant_id = "other".into();
    refuse(writer.outcome(&foreign), "another tenant's outcome");
    writer.outcome(&outcomes[0]).unwrap();
    refuse(writer.record(&records[2]), "a record after the outcomes");

    writer.checkpoint(&checkpoints[1]).unwrap();
    refuse(
        writer.checkpoint(&checkpoints[0]),
        "a checkpoint out of order",
    );
    let mut foreign = checkpoints[1].clone();
    foreign.payload.chain = "decision_events".into();
    refuse(writer.checkpoint(&foreign), "another chain's checkpoint");
    drop(writer);

    // Another partition is another chain.
    let elsewhere = Scope {
        partition_id: 1,
        ..SCOPE
    };
    let mut writer = BundleWriter::create(&out, elsewhere, SegmentStart::GENESIS).unwrap();
    refuse(writer.record(&records[0]), "another partition's record");
}

#[test]
fn a_segment_an_empty_segment_and_an_unsigned_bundle() {
    let records = records();

    // Records 3 and 4, following record 2.
    let out = scratch("segment");
    let start = SegmentStart {
        seq: 2,
        hash: &records[1].hash,
    };
    let mut writer = BundleWriter::create(&out, SCOPE, start).unwrap();
    assert!(
        writer.record(&records[0]).is_err(),
        "not part of the segment"
    );
    writer.record(&records[2]).unwrap();
    writer.record(&records[3]).unwrap();
    let manifest = writer
        .finish(exported_at(), exporter(), Some(&export_key()))
        .unwrap();
    let segment = &manifest.payload.segment;
    assert_eq!((segment.after_seq, segment.last_seq), (2, 4));
    assert_eq!(segment.after_hash, records[1].hash);
    assert_eq!(manifest.payload.files.records.count, 2);
    fs::remove_dir_all(&out).unwrap();

    // Nothing after record 4 yet: an empty segment is still a bundle.
    let out = scratch("empty");
    let start = SegmentStart {
        seq: 4,
        hash: &records[3].hash,
    };
    let manifest = BundleWriter::create(&out, SCOPE, start)
        .unwrap()
        .finish(exported_at(), exporter(), Some(&export_key()))
        .unwrap();
    let segment = &manifest.payload.segment;
    assert_eq!((segment.after_seq, segment.last_seq), (4, 4));
    assert_eq!(segment.head_hash, segment.after_hash);
    assert_eq!(fs::read(out.join(RECORDS_FILE)).unwrap(), b"");
    fs::remove_dir_all(&out).unwrap();

    // Unsigned only when asked for, and it says so.
    let out = scratch("unsigned");
    let mut writer = BundleWriter::create(&out, SCOPE, SegmentStart::GENESIS).unwrap();
    writer.record(&records[0]).unwrap();
    let manifest = writer.finish(exported_at(), exporter(), None).unwrap();
    assert_eq!(
        verify_manifest(&manifest, &public_keys(), DevKeys::Refuse),
        Ok(ManifestSignature::Unsigned)
    );
    let text = fs::read_to_string(out.join(MANIFEST_FILE)).unwrap();
    assert!(
        !text.contains("\"sig\"") && !text.contains("\"key_id\""),
        "{text}"
    );
    fs::remove_dir_all(&out).unwrap();
}

//! The bundle verifier (E4a): what it accepts, what it refuses, and what it
//! reports as not protected. The logic is exercised in memory; the
//! directory checks and the command run on real files.

mod common;

use kavach_ports::chain_record::ChainRecord;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use kavach_evidence_cli::verify::{
    verify_dir, Verdict, VerifyError, VerifyRequest, EXIT_FAILED, EXIT_VERIFIED, EXIT_WARNINGS,
};
use kavach_evidence_cli::writer::BundleWriter;
use kavach_ports::agent_evidence::{
    sign_outcome, AgentDecisionRecord, ChainError, DevKeys, Outcome, OutcomeRecord, SegmentStart,
};
use kavach_ports::bundle::{
    manifest_hash, seal_manifest, FileEntry, Files, Manifest, ManifestDraft, ManifestError,
    ManifestSignature, Segment, CHECKPOINTS_FILE, MANIFEST_FILE, OUTCOMES_FILE, RECORDS_FILE,
};
use kavach_ports::bundle_verify::{
    verify_bundle, BundleFailure, BundleReport, KeyValidity, VerifyOptions,
};
use kavach_ports::checkpoint::{Checkpoint, CheckpointError};

use common::*;

// ---------------------------------------------------------------- in memory

/// A manifest for `records` following `start` (file digests are not what
/// these tests are about).
fn manifest(start: SegmentStart<'_>, records: &[AgentDecisionRecord], signed: bool) -> Manifest {
    let entry = |count| FileEntry {
        sha256: "00".repeat(32),
        count,
    };
    let key = export_key();
    seal_manifest(
        ManifestDraft {
            scope: SCOPE,
            segment: Segment {
                after_seq: start.seq,
                after_hash: start.hash.into(),
                last_seq: records.last().map_or(start.seq, |r| r.payload.seq),
                head_hash: records
                    .last()
                    .map_or_else(|| start.hash.into(), |r| r.hash.clone()),
            },
            files: Files {
                records: entry(records.len() as u64),
                outcomes: entry(0),
                checkpoints: entry(0),
            },
            exported_at: exported_at(),
            exporter: exporter(),
        },
        signed.then_some(&key as &dyn kavach_ports::agent_evidence::EvidenceSigner),
    )
    .unwrap()
}

struct Case<'a> {
    start: SegmentStart<'a>,
    records: &'a [AgentDecisionRecord],
    outcomes: &'a [OutcomeRecord],
    checkpoints: &'a [Checkpoint],
    kept: Option<&'a Checkpoint>,
    signed: bool,
}

impl Case<'_> {
    fn verify(&self) -> Result<BundleReport, BundleFailure> {
        let keys = public_keys();
        verify_bundle(
            &manifest(self.start, self.records, self.signed),
            self.records
                .iter()
                .cloned()
                .map(ChainRecord::Decision)
                .map(Ok),
            self.outcomes.iter().cloned().map(Ok),
            self.checkpoints.iter().cloned().map(Ok),
            &VerifyOptions {
                validity: &std::collections::BTreeMap::new(),
                keys: &keys,
                dev_keys: DevKeys::Refuse,
                now: exported_at(),
                kept: self.kept,
            },
        )
    }
}

/// As [`Case::verify`], with the operator's limits on keys.
fn verify_limited(
    case: &Case<'_>,
    validity: &std::collections::BTreeMap<String, KeyValidity>,
) -> Result<BundleReport, BundleFailure> {
    let keys = public_keys();
    verify_bundle(
        &manifest(case.start, case.records, case.signed),
        case.records
            .iter()
            .cloned()
            .map(ChainRecord::Decision)
            .map(Ok),
        case.outcomes.iter().cloned().map(Ok),
        case.checkpoints.iter().cloned().map(Ok),
        &VerifyOptions {
            validity,
            keys: &keys,
            dev_keys: DevKeys::Refuse,
            now: exported_at(),
            kept: case.kept,
        },
    )
}

fn kinds(report: &BundleReport) -> Vec<&'static str> {
    report.not_protected().iter().map(|f| f.kind).collect()
}

#[test]
fn a_bundle_verifies_and_says_what_it_does_not_protect() {
    let records = records();
    let outcomes = outcomes(&records);
    let checkpoints = checkpoints(&records);
    let report = Case {
        start: SegmentStart::GENESIS,
        records: &records,
        outcomes: &outcomes,
        checkpoints: &checkpoints,
        kept: None,
        signed: true,
    }
    .verify()
    .unwrap();
    assert_eq!(
        (report.records, report.outcomes, report.checkpoints),
        (4, 2, 2)
    );
    assert_eq!((report.after_seq, report.last_seq), (0, 4));
    assert_eq!(
        (report.last_checkpoint, report.uncovered_records),
        (Some(3), 1)
    );
    assert_eq!(report.outcome_missing.first, ["cred-4"]);
    assert_eq!(report.outcome_unknown.first, ["cred-3"]);
    assert_eq!(
        kinds(&report),
        [
            "no_kept_checkpoint",
            "uncovered_records",
            "outcome_missing",
            "outcome_unknown"
        ]
    );

    // Unsigned, and without any checkpoint: both are said.
    let report = Case {
        start: SegmentStart::GENESIS,
        records: &records,
        outcomes: &outcomes,
        checkpoints: &[],
        kept: None,
        signed: false,
    }
    .verify()
    .unwrap();
    assert_eq!(report.signature, ManifestSignature::Unsigned);
    assert_eq!(
        (report.last_checkpoint, report.uncovered_records),
        (None, 4)
    );
    assert_eq!(
        kinds(&report)[..3],
        ["unsigned", "no_kept_checkpoint", "uncovered_records"]
    );
    let detail = &report.not_protected()[2].detail;
    assert!(
        detail.contains("4 record(s)") && detail.contains("no checkpoint"),
        "{detail}"
    );

    // Signed, every record under a checkpoint, compared with a kept one,
    // every allow with a final outcome: nothing to report.
    let report = Case {
        start: SegmentStart::GENESIS,
        records: &records[..2],
        outcomes: &outcomes[..1],
        checkpoints: &checkpoints[..1],
        kept: Some(&checkpoints[0]),
        signed: true,
    }
    .verify()
    .unwrap();
    assert_eq!(report.kept_checkpoint, Some(2));
    assert!(
        report.not_protected().is_empty(),
        "{:?}",
        report.not_protected()
    );

    // An allow whose credential has not expired yet is not "missing".
    let keys = public_keys();
    let early = verify_bundle(
        &manifest(SegmentStart::GENESIS, &records, true),
        records.iter().cloned().map(ChainRecord::Decision).map(Ok),
        outcomes.iter().cloned().map(Ok),
        checkpoints.iter().cloned().map(Ok),
        &VerifyOptions {
            validity: &std::collections::BTreeMap::new(),
            keys: &keys,
            dev_keys: DevKeys::Refuse,
            now: records[3].payload.ts,
            kept: None,
        },
    )
    .unwrap();
    assert_eq!(early.outcome_missing.count, 0);
}

#[test]
fn a_kept_checkpoint_catches_what_the_key_holder_could_hide() {
    let records = records();
    let outcomes = outcomes(&records);
    let checkpoints = checkpoints(&records);
    let kept = &checkpoints[1]; // record 3, kept off-host
    let case = |records, outcomes, checkpoints| Case {
        start: SegmentStart::GENESIS,
        records,
        outcomes,
        checkpoints,
        kept: Some(kept),
        signed: true,
    };

    let report = case(&records, &outcomes, &checkpoints).verify().unwrap();
    assert_eq!(report.kept_checkpoint, Some(3));
    assert!(!kinds(&report).contains(&"no_kept_checkpoint"));

    // Cut to two records, with the checkpoint of record 3 dropped: what is
    // left is consistent on its own.
    let cut = case(&records[..2], &outcomes[..1], &checkpoints[..1]);
    let unkept = Case { kept: None, ..cut };
    assert!(unkept.verify().is_ok());
    let cut = case(&records[..2], &outcomes[..1], &checkpoints[..1]);
    assert_eq!(
        cut.verify(),
        Err(CheckpointError::Ahead {
            seq: 3,
            head_seq: 2
        }
        .into())
    );

    // Records 3 and 4 rewritten and re-signed, with matching new checkpoints.
    let rewritten = rewritten(&records);
    let new_checkpoints = common::checkpoints(&rewritten);
    let forged = case(&rewritten, &outcomes[..1], &new_checkpoints);
    let unkept = Case {
        kept: None,
        ..forged
    };
    assert!(unkept.verify().is_ok());
    let forged = case(&rewritten, &outcomes[..1], &new_checkpoints);
    assert_eq!(
        forged.verify(),
        Err(CheckpointError::Mismatch { seq: 3 }.into())
    );

    // The records intact, but the checkpoint history replaced.
    let replaced = [
        checkpoints[0].clone(),
        checkpoint_at(&records, 4, Some(&checkpoints[0])),
    ];
    assert_eq!(
        case(&records, &outcomes, &replaced).verify(),
        Err(CheckpointError::KeptAbsent { seq: 3 }.into())
    );

    // A kept checkpoint that does not itself verify proves nothing.
    let mut edited = kept.clone();
    edited.payload.seq = 2;
    let bad = Case {
        kept: Some(&edited),
        ..case(&records, &outcomes, &checkpoints)
    };
    assert_eq!(bad.verify(), Err(CheckpointError::Hash { seq: 2 }.into()));
}

#[test]
fn a_segment_start_is_never_trusted_on_its_own() {
    let records = records();
    let outcomes = outcomes(&records);
    let checkpoints = checkpoints(&records);
    let start = SegmentStart {
        seq: 2,
        hash: &records[1].hash,
    };
    let segment = |checkpoints, kept| Case {
        start,
        records: &records[2..],
        outcomes: &outcomes[1..],
        checkpoints,
        kept,
        signed: true,
    };

    // The checkpoint of record 2 is in the bundle: it vouches for the start.
    let report = segment(&checkpoints, None).verify().unwrap();
    assert_eq!(
        (report.after_seq, report.last_seq, report.records),
        (2, 4, 2)
    );
    assert_eq!(
        (report.last_checkpoint, report.uncovered_records),
        (Some(3), 1)
    );

    // No checkpoint at the start: refused…
    assert_eq!(
        segment(&checkpoints[1..], None).verify(),
        Err(BundleFailure::UnvouchedStart { after_seq: 2 })
    );
    assert_eq!(
        segment(&[], None).verify(),
        Err(BundleFailure::UnvouchedStart { after_seq: 2 })
    );
    // …unless the operator's kept checkpoint is that one.
    let report = segment(&[], Some(&checkpoints[0])).verify().unwrap();
    assert_eq!(report.kept_checkpoint, Some(2));

    // A start that claims another hash for record 2.
    let wrong = "ee".repeat(32);
    let moved = Case {
        start: SegmentStart {
            seq: 2,
            hash: &wrong,
        },
        ..segment(&checkpoints, None)
    };
    assert_eq!(
        moved.verify(),
        Err(CheckpointError::Mismatch { seq: 2 }.into())
    );
    // A kept checkpoint older than the segment cannot be compared with it.
    let first = checkpoint_at(&records, 1, None);
    assert_eq!(
        segment(&checkpoints, Some(&first)).verify(),
        Err(CheckpointError::KeptBeforeSegment {
            seq: 1,
            start_seq: 2
        }
        .into())
    );
}

#[test]
fn records_outcomes_and_checkpoints_that_do_not_belong_are_refused() {
    let records = records();
    let outcomes = outcomes(&records);
    let checkpoints = checkpoints(&records);
    let case = |records, outcomes, checkpoints| Case {
        start: SegmentStart::GENESIS,
        records,
        outcomes,
        checkpoints,
        kept: None,
        signed: true,
    };
    let fails = |case: Case<'_>| case.verify().unwrap_err();

    // A record edited after signing.
    let mut edited = records.clone();
    edited[1].payload.action = "place_call".into();
    assert_eq!(
        fails(case(&edited, &outcomes, &checkpoints)),
        ChainError::Hash { seq: 2 }.into()
    );
    // Fewer records than the manifest says (the manifest is built from the
    // full list here; the stream stops early).
    let keys = public_keys();
    let short = verify_bundle(
        &manifest(SegmentStart::GENESIS, &records, true),
        records[..3]
            .iter()
            .cloned()
            .map(ChainRecord::Decision)
            .map(Ok),
        outcomes.iter().cloned().map(Ok),
        checkpoints.iter().cloned().map(Ok),
        &VerifyOptions {
            validity: &std::collections::BTreeMap::new(),
            keys: &keys,
            dev_keys: DevKeys::Refuse,
            now: exported_at(),
            kept: None,
        },
    );
    assert!(matches!(short, Err(BundleFailure::Segment(_))), "{short:?}");

    // Outcomes out of order, repeated, or of no record here.
    let swapped = [outcomes[1].clone(), outcomes[0].clone()];
    let repeated = [outcomes[0].clone(), outcomes[0].clone()];
    for bad in [&swapped[..], &repeated[..]] {
        let failure = fails(case(&records, bad, &checkpoints));
        assert!(
            matches!(failure, BundleFailure::Outcome { .. }),
            "{failure}"
        );
        assert!(
            failure.to_string().contains("belongs to no record"),
            "{failure}"
        );
    }
    // An outcome edited after signing.
    let mut forged = outcomes.clone();
    forged[0].outcome = Outcome::Failed;
    let failure = fails(case(&records, &forged, &checkpoints));
    assert!(
        failure.to_string().contains("cred-1 does not verify"),
        "{failure}"
    );
    // A validly signed outcome for record 1's credential that names record 3.
    let mut misplaced = outcomes.clone();
    misplaced[0] = sign_outcome(
        TENANT,
        "cred-1",
        &records[2].hash,
        Outcome::Delivered,
        "provider_202",
        t0(),
        &evidence_key(),
    )
    .unwrap();
    let failure = fails(case(&records, &misplaced, &checkpoints));
    assert!(
        failure.to_string().contains("names another record"),
        "{failure}"
    );
}

#[test]
fn checkpoints_that_do_not_fit_the_records_and_unreadable_lines_are_refused() {
    let records = records();
    let outcomes = outcomes(&records);
    let checkpoints = checkpoints(&records);
    let keys = public_keys();
    let case = |records, outcomes, checkpoints| Case {
        start: SegmentStart::GENESIS,
        records,
        outcomes,
        checkpoints,
        kept: None,
        signed: true,
    };
    let fails = |case: Case<'_>| case.verify().unwrap_err();

    // A checkpoint newer than the newest record: records were removed.
    assert_eq!(
        fails(case(&records[..2], &outcomes[..1], &checkpoints)),
        CheckpointError::Ahead {
            seq: 3,
            head_seq: 2
        }
        .into()
    );
    // Checkpoints out of order, or one dropped from the middle.
    let reversed = [checkpoints[1].clone(), checkpoints[0].clone()];
    assert!(matches!(
        fails(case(&records, &outcomes, &reversed)),
        BundleFailure::Checkpoint(_)
    ));
    let fourth = checkpoint_at(&records, 4, Some(&checkpoints[1]));
    let gap = [checkpoints[0].clone(), fourth];
    assert_eq!(
        fails(case(&records, &outcomes, &gap)),
        CheckpointError::Link { seq: 4 }.into()
    );

    // A line that cannot be read names its file and line.
    let unreadable = verify_bundle(
        &manifest(SegmentStart::GENESIS, &records, true),
        records
            .iter()
            .cloned()
            .map(ChainRecord::Decision)
            .map(Ok)
            .take(2)
            .chain([Err("expected value at line 1 column 1".to_string())]),
        outcomes.iter().cloned().map(Ok),
        checkpoints.iter().cloned().map(Ok),
        &VerifyOptions {
            validity: &std::collections::BTreeMap::new(),
            keys: &keys,
            dev_keys: DevKeys::Refuse,
            now: exported_at(),
            kept: None,
        },
    )
    .unwrap_err();
    assert_eq!(
        unreadable.to_string(),
        "records.jsonl line 3: expected value at line 1 column 1"
    );
}

// ------------------------------------------------------------------ on disk

fn vectors() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

fn keys_file() -> PathBuf {
    vectors().join("bundle-v1.keys.json")
}

/// A private copy of the checked-in bundle.
fn vector_copy(name: &str) -> PathBuf {
    let out = scratch(name);
    fs::create_dir(&out).unwrap();
    for file in [MANIFEST_FILE, RECORDS_FILE, OUTCOMES_FILE, CHECKPOINTS_FILE] {
        fs::copy(vectors().join("bundle-v1").join(file), out.join(file)).unwrap();
    }
    out
}

fn verify_at(bundle: &Path, kept: Option<&Path>) -> Result<BundleReport, VerifyError> {
    verify_dir(&VerifyRequest {
        bundle,
        keys: &keys_file(),
        expect_checkpoint: kept,
        dev: false,
        now: exported_at(),
    })
}

/// Rewrites a manifest's entry for the outcomes file to match the file,
/// as someone without the export key could.
fn refit_manifest(bundle: &Path, strip_signature: bool) {
    let path = bundle.join(MANIFEST_FILE);
    let mut manifest: Manifest = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let bytes = fs::read(bundle.join(OUTCOMES_FILE)).unwrap();
    manifest.payload.files.outcomes = FileEntry {
        sha256: format!("{:x}", <sha2::Sha256 as sha2::Digest>::digest(&bytes)),
        count: String::from_utf8(bytes).unwrap().lines().count() as u64,
    };
    if strip_signature {
        manifest.payload.key_id = None;
        manifest.sig = None;
    }
    manifest.hash = manifest_hash(&manifest.payload).unwrap();
    fs::write(&path, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
}

#[test]
fn the_checked_in_bundle_verifies_from_its_directory() {
    let bundle = vectors().join("bundle-v1");
    let report = verify_at(&bundle, None).unwrap();
    assert_eq!(
        (report.records, report.outcomes, report.checkpoints),
        (4, 2, 2)
    );
    assert_eq!(
        report.signature,
        ManifestSignature::Signed {
            key_id: "export-kat-1".into()
        }
    );

    // The report leads with what is not protected, and warnings fail.
    let verdict = Verdict {
        result: Ok(report),
        allow_warnings: false,
        bundle: bundle.clone(),
    };
    assert_eq!(verdict.exit_code(), EXIT_WARNINGS);
    let text = verdict.text();
    assert!(text.starts_with("NOT PROTECTED (4):\n"), "{text}");
    assert!(text.find("NOT PROTECTED").unwrap() < text.find("VERIFIED:").unwrap());
    assert!(
        text.contains("1 record(s) are not covered by any checkpoint"),
        "{text}"
    );
    assert!(text.contains("cred-4") && text.contains("cred-3"), "{text}");
    assert!(
        text.trim_end().ends_with("--allow-warnings accepts this)"),
        "{text}"
    );
    let allowed = Verdict {
        allow_warnings: true,
        ..verdict
    };
    assert_eq!(allowed.exit_code(), EXIT_VERIFIED);
    assert!(allowed.text().contains("allowed by --allow-warnings"));
    assert_eq!(allowed.json()["result"], "warnings");

    // With a kept checkpoint file (several lines: the last one counts).
    let kept = scratch("kept.jsonl");
    let checkpoints = fs::read_to_string(bundle.join(CHECKPOINTS_FILE)).unwrap();
    fs::write(&kept, &checkpoints).unwrap();
    let report = verify_at(&bundle, Some(&kept)).unwrap();
    assert_eq!(report.kept_checkpoint, Some(3));
    fs::remove_file(&kept).unwrap();
}

#[test]
fn a_bundle_changed_after_export_fails() {
    let mismatch = |result: Result<BundleReport, VerifyError>, file: &str| {
        let err = result.unwrap_err();
        assert!(
            matches!(&err, VerifyError::FileMismatch { file: f, .. } if *f == file),
            "{err}"
        );
    };

    // One character of one record.
    let bundle = vector_copy("edited-record");
    let records = fs::read_to_string(bundle.join(RECORDS_FILE)).unwrap();
    fs::write(
        bundle.join(RECORDS_FILE),
        records.replacen("send_reminder", "send_remindex", 1),
    )
    .unwrap();
    mismatch(verify_at(&bundle, None), RECORDS_FILE);
    fs::remove_dir_all(&bundle).unwrap();

    // An outcome removed.
    let bundle = vector_copy("dropped-outcome");
    let outcomes = fs::read_to_string(bundle.join(OUTCOMES_FILE)).unwrap();
    let first_line = outcomes.lines().next().unwrap().to_string() + "\n";
    fs::write(bundle.join(OUTCOMES_FILE), &first_line).unwrap();
    mismatch(verify_at(&bundle, None), OUTCOMES_FILE);
    // …and the manifest refitted to match, without the export key: the
    // signature no longer verifies.
    refit_manifest(&bundle, false);
    let err = verify_at(&bundle, None).unwrap_err();
    assert!(
        matches!(
            err,
            VerifyError::Bundle(BundleFailure::Manifest(ManifestError::Signature(_)))
        ),
        "{err}"
    );
    // Had the bundle been unsigned, the removal would pass as a missing
    // outcome. This is what the manifest signature is for.
    refit_manifest(&bundle, true);
    let report = verify_at(&bundle, None).unwrap();
    assert_eq!(report.signature, ManifestSignature::Unsigned);
    assert_eq!(report.outcome_missing.count, 2);
    assert_eq!(report.not_protected()[0].kind, "unsigned");
    fs::remove_dir_all(&bundle).unwrap();

    // A checkpoint removed (the last one).
    let bundle = vector_copy("dropped-checkpoint");
    let checkpoints = fs::read_to_string(bundle.join(CHECKPOINTS_FILE)).unwrap();
    let first_line = checkpoints.lines().next().unwrap().to_string() + "\n";
    fs::write(bundle.join(CHECKPOINTS_FILE), first_line).unwrap();
    mismatch(verify_at(&bundle, None), CHECKPOINTS_FILE);
    fs::remove_dir_all(&bundle).unwrap();
}

#[test]
fn only_a_bundle_and_only_the_operators_keys_are_accepted() {
    let layout = |result: Result<BundleReport, VerifyError>, what: &str| {
        let err = result.unwrap_err();
        assert!(matches!(err, VerifyError::Layout(_)), "{what}: {err}");
        assert!(err.to_string().contains(what), "{err}");
    };

    // An extra file, a missing file.
    let bundle = vector_copy("extra");
    fs::write(bundle.join("notes.txt"), "hello").unwrap();
    layout(verify_at(&bundle, None), "unexpected entry notes.txt");
    fs::remove_file(bundle.join("notes.txt")).unwrap();
    fs::remove_file(bundle.join(OUTCOMES_FILE)).unwrap();
    layout(verify_at(&bundle, None), "outcomes.jsonl is missing");
    fs::remove_dir_all(&bundle).unwrap();

    // Keys offered from inside the bundle are refused, even if they are
    // the right ones.
    let bundle = vector_copy("keys-inside");
    let inside = bundle.join("keys.json");
    fs::copy(keys_file(), &inside).unwrap();
    let err = verify_dir(&VerifyRequest {
        bundle: &bundle,
        keys: &inside,
        expect_checkpoint: None,
        dev: false,
        now: exported_at(),
    })
    .unwrap_err();
    assert!(
        err.to_string().contains("unexpected entry keys.json"),
        "{err}"
    );
    fs::remove_file(&inside).unwrap();
    let nested = bundle.join(MANIFEST_FILE);
    let err = verify_dir(&VerifyRequest {
        bundle: &bundle,
        keys: &nested,
        expect_checkpoint: None,
        dev: false,
        now: exported_at(),
    })
    .unwrap_err();
    assert!(matches!(err, VerifyError::Keys(_)), "{err}");
    assert!(err.to_string().contains("never from the bundle"), "{err}");
    fs::remove_dir_all(&bundle).unwrap();

    // A keys file without the checkpoint key: those signatures are unknown.
    let partial = scratch("partial-keys.json");
    let all: serde_json::Value = serde_json::from_slice(&fs::read(keys_file()).unwrap()).unwrap();
    let kept: Vec<_> = all["keys"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|k| k["kid"] != "kavach-checkpoint-kat")
        .cloned()
        .collect();
    fs::write(&partial, serde_json::json!({ "keys": kept }).to_string()).unwrap();
    let err = verify_dir(&VerifyRequest {
        bundle: &vectors().join("bundle-v1"),
        keys: &partial,
        expect_checkpoint: None,
        dev: false,
        now: exported_at(),
    })
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("unknown key kavach-checkpoint-kat"),
        "{err}"
    );
    // Malformed keys files.
    for bad in [
        r#"{"keys":[]}"#,
        r#"{"keys":[{"kid":"k","alg":"RSA","public_key":"00"}]}"#,
        r#"{"keys":[{"kid":"k","alg":"Ed25519","public_key":"abcd"}]}"#,
        r#"{"keys":[],"trust_bundle_keys":true}"#,
    ] {
        fs::write(&partial, bad).unwrap();
        let err = verify_dir(&VerifyRequest {
            bundle: &vectors().join("bundle-v1"),
            keys: &partial,
            expect_checkpoint: None,
            dev: false,
            now: exported_at(),
        })
        .unwrap_err();
        assert!(matches!(err, VerifyError::Keys(_)), "{bad}: {err}");
    }
    fs::remove_file(&partial).unwrap();
}

#[test]
fn a_development_bundle_needs_the_dev_flag() {
    // An empty bundle signed with a development export key.
    let out = scratch("dev-bundle");
    let dev = Key(
        "dev-export-1",
        ed25519_dalek::SigningKey::from_bytes(&[44u8; 32]),
    );
    BundleWriter::create(&out, SCOPE, SegmentStart::GENESIS)
        .unwrap()
        .finish(exported_at(), exporter(), Some(&dev))
        .unwrap();
    let keys = scratch("dev-keys.json");
    fs::write(
        &keys,
        serde_json::json!({ "keys": [{ "kid": "dev-export-1", "alg": "Ed25519",
            "public_key": hex::encode(dev.1.verifying_key().to_bytes()) }] })
        .to_string(),
    )
    .unwrap();
    let verify = |dev| {
        verify_dir(&VerifyRequest {
            bundle: &out,
            keys: &keys,
            expect_checkpoint: None,
            dev,
            now: exported_at(),
        })
    };
    let err = verify(false).unwrap_err();
    assert!(
        matches!(
            err,
            VerifyError::Bundle(BundleFailure::Manifest(ManifestError::DevKey { .. }))
        ),
        "{err}"
    );
    let report = verify(true).unwrap();
    assert_eq!((report.records, report.uncovered_records), (0, 0));
    // Nothing in it, so nothing uncovered; still not compared with a kept one.
    assert_eq!(kinds(&report), ["no_kept_checkpoint"]);
    fs::remove_dir_all(&out).unwrap();
    fs::remove_file(&keys).unwrap();
}

// ------------------------------------------------------------- the command

fn run(args: &[&str]) -> (Option<i32>, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_kavach-evidence"))
        .arg("verify-bundle")
        .args(args)
        .output()
        .expect("run kavach-evidence");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
    )
}

#[test]
fn the_command_fails_closed_and_tells_the_three_results_apart() {
    let bundle = vectors().join("bundle-v1");
    let bundle = bundle.to_str().unwrap();
    let keys = keys_file();
    let keys = keys.to_str().unwrap();
    let at = exported_at().to_rfc3339();

    // Verifies, but not fully protected: a warning is a failure by default.
    let (code, text) = run(&[bundle, "--keys", keys, "--at", &at]);
    assert_eq!(code, Some(EXIT_WARNINGS), "{text}");
    assert!(text.starts_with("NOT PROTECTED (4):"), "{text}");
    assert!(text.contains("RESULT: WARNINGS"), "{text}");
    // …and allowed only when asked for.
    let (code, text) = run(&[bundle, "--keys", keys, "--at", &at, "--allow-warnings"]);
    assert_eq!(code, Some(EXIT_VERIFIED), "{text}");
    assert!(
        text.starts_with("NOT PROTECTED (4):"),
        "still said first: {text}"
    );

    // JSON for programs.
    let (code, text) = run(&[bundle, "--keys", keys, "--at", &at, "--json"]);
    assert_eq!(code, Some(EXIT_WARNINGS));
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        (&json["result"], &json["exit_code"]),
        (&"warnings".into(), &2.into())
    );
    assert_eq!(json["not_protected"][0]["kind"], "no_kept_checkpoint");
    assert_eq!(json["verified"]["records"], 4);
    assert_eq!(json["verified"]["signed_with"], "export-kat-1");
    assert_eq!(json["failure"], serde_json::Value::Null);

    // A changed bundle fails, whatever is allowed.
    let tampered = vector_copy("cli-tampered");
    let records = fs::read_to_string(tampered.join(RECORDS_FILE)).unwrap();
    fs::write(
        tampered.join(RECORDS_FILE),
        records.replacen("cred-1", "cred-9", 1),
    )
    .unwrap();
    let (code, text) = run(&[
        tampered.to_str().unwrap(),
        "--keys",
        keys,
        "--allow-warnings",
    ]);
    assert_eq!(code, Some(EXIT_FAILED), "{text}");
    assert!(
        text.starts_with("FAIL: records.jsonl does not match the manifest"),
        "{text}"
    );
    assert!(text.contains("RESULT: FAILED"), "{text}");
    let (code, text) = run(&[tampered.to_str().unwrap(), "--keys", keys, "--json"]);
    assert_eq!(code, Some(EXIT_FAILED));
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(json["result"], "failed");
    assert!(json["failure"].as_str().unwrap().contains("records.jsonl"));
    fs::remove_dir_all(&tampered).unwrap();
}

/// The evidence key is stolen after record 2. The operator kept the
/// checkpoint of record 2 from before. The thief re-signs records 3 and 4
/// and backdates them to before the compromise (the checkpoint key was not
/// stolen). A time limit alone lets the forgery through; a limit anchored
/// to the kept checkpoint (`valid_until_seq`) refuses it.
#[test]
fn a_compromised_key_cannot_vouch_for_backdated_records() {
    let records = records();
    let checkpoints = checkpoints(&records);
    let compromised_at = records[2].payload.ts;
    let evidence = evidence_key();
    let mut forged = records[..2].to_vec();
    let mut prev = records[1].hash.clone();
    for record in &records[2..] {
        let mut payload = record.payload.clone();
        payload.prev_hash.clone_from(&prev);
        payload.purpose = "forged".into();
        payload.ts = records[0].payload.ts; // backdated, before the compromise
        let record = kavach_ports::agent_evidence::seal(payload, &evidence).unwrap();
        prev.clone_from(&record.hash);
        forged.push(record);
    }
    let case = Case {
        start: SegmentStart::GENESIS,
        records: &forged,
        outcomes: &[],
        checkpoints: &checkpoints[..1],
        kept: Some(&checkpoints[0]),
        signed: true,
    };
    let limit = |validity: KeyValidity| {
        std::collections::BTreeMap::from([(evidence.0.to_string(), validity)])
    };

    // No limits: the forgery verifies (its records are merely uncovered).
    assert!(case.verify().is_ok());
    // A time limit alone: the backdated forgery still verifies.
    let by_time = limit(KeyValidity {
        not_after: Some(compromised_at),
        ..KeyValidity::default()
    });
    assert!(verify_limited(&case, &by_time).is_ok());
    // Anchored to the kept checkpoint: refused at the first forged record.
    let by_seq = limit(KeyValidity {
        valid_until_seq: Some(2),
        not_after: Some(compromised_at),
        ..KeyValidity::default()
    });
    match verify_limited(&case, &by_seq) {
        Err(BundleFailure::KeyNotValid { what, reason }) => {
            assert_eq!(what, "record 3");
            assert!(reason.contains("after its limit"), "{reason}");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }

    // An honest record past the limit is accepted when a checkpoint the
    // operator kept covers it, and refused beyond that checkpoint.
    let honest = |records| Case {
        start: SegmentStart::GENESIS,
        records,
        outcomes: &[],
        checkpoints: &checkpoints,
        kept: Some(&checkpoints[1]),
        signed: true,
    };
    let seq_only = limit(KeyValidity {
        valid_until_seq: Some(2),
        ..KeyValidity::default()
    });
    assert!(verify_limited(&honest(&records[..3]), &seq_only).is_ok());
    assert!(matches!(
        verify_limited(&honest(&records), &seq_only),
        Err(BundleFailure::KeyNotValid { what, .. }) if what == "record 4"
    ));

    // The same rule for the checkpoint key.
    let checkpoint_limit = std::collections::BTreeMap::from([(
        checkpoint_key().0.to_string(),
        KeyValidity {
            valid_until_seq: Some(2),
            ..KeyValidity::default()
        },
    )]);
    let unkept = Case {
        kept: None,
        ..honest(&records)
    };
    assert!(matches!(
        verify_limited(&unkept, &checkpoint_limit),
        Err(BundleFailure::KeyNotValid { what, .. }) if what == "checkpoint 3"
    ));
}

/// The keys file carries the limits; a time window that ends before it
/// starts is refused.
#[test]
fn the_trusted_keys_file_carries_key_limits() {
    let dir = scratch("keys-limits");
    let bundle = scratch("keys-limits-bundle");
    fs::create_dir_all(&dir).unwrap();
    fs::create_dir_all(&bundle).unwrap();
    let path = dir.join("keys.json");
    let key = hex::encode(evidence_key().1.verifying_key().to_bytes());
    fs::write(
        &path,
        serde_json::json!({ "keys": [{
            "kid": "kavach-evidence-kat", "alg": "Ed25519", "public_key": key,
            "valid_until_seq": 2, "not_after": "2026-10-02T06:00:00Z"
        }]})
        .to_string(),
    )
    .unwrap();
    let trusted = kavach_evidence_cli::verify::load_trusted_keys(&path, &bundle).unwrap();
    let limits = &trusted.validity["kavach-evidence-kat"];
    assert_eq!(limits.valid_until_seq, Some(2));
    assert!(limits.not_after.is_some() && limits.not_before.is_none());

    fs::write(
        &path,
        serde_json::json!({ "keys": [{
            "kid": "kavach-evidence-kat", "alg": "Ed25519", "public_key": key,
            "not_before": "2026-10-02T06:00:00Z", "not_after": "2026-10-02T05:00:00Z"
        }]})
        .to_string(),
    )
    .unwrap();
    assert!(kavach_evidence_cli::verify::load_trusted_keys(&path, &bundle).is_err());
}

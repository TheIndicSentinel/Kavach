//! The two verifiers, on generated histories.
//!
//! The Rust verifier and the independent Python one (`conformance/`, written
//! from the specification alone) are the audit claim: that two implementations
//! agree. The fixed vectors and the real-stack test show it on a few bundles;
//! this shows it on many.
//!
//! - **Random histories**, exported: decisions (allowed or blocked), outcomes
//!   of every kind (or none), resolutions of the unknown ones, a revocation,
//!   and checkpoints at random places. Both must accept every one, with the
//!   same counts and the same things reported as not protected.
//! - **Damage without the export key** (a record, outcome, checkpoint or
//!   resolution dropped, two swapped, or one edited, the manifest untouched):
//!   both must refuse, for the same class of reason (the file no longer
//!   matches the manifest).
//! - **Damage by someone who holds the export key** (the same, then the
//!   manifest rewritten and signed to match): both must refuse, and for the
//!   same class: a broken chain for a record, the checkpoint, the outcome or
//!   the resolution that was touched. Some such damage is invisible to a
//!   signed manifest by design (the last record cut off, an outcome or a
//!   resolution removed); there the two must still say the same thing.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use chrono::Duration;
use kavach_domain::Decision;
use kavach_evidence_cli::verify::{verify_dir, VerifyRequest};
use kavach_evidence_cli::writer::BundleWriter;
use kavach_ports::agent_evidence::{sign_outcome, Outcome, OutcomeRecord, SegmentStart, GENESIS};
use kavach_ports::bundle::{
    seal_manifest, FileEntry, Files, ManifestDraft, Segment, CHECKPOINTS_FILE, MANIFEST_FILE,
    OUTCOMES_FILE, RECORDS_FILE, RESOLUTIONS_FILE,
};
use kavach_ports::chain_record::ChainRecord;
use kavach_ports::checkpoint::Checkpoint;
use kavach_ports::outcome_resolution::{ResolutionRecord, ResolutionSource, ResolutionState};
use proptest::prelude::*;
use serde_json::Value;
use sha2::{Digest, Sha256};

use common::*;

fn vectors() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

fn now() -> chrono::DateTime<chrono::Utc> {
    exported_at() + Duration::days(1)
}

// ---------------------------------------------------------------- histories

/// What a generated history is made of.
#[derive(Debug, Clone)]
struct History {
    /// Each record: allowed or blocked.
    allows: Vec<bool>,
    /// For each allow, what became of its send (0: no outcome).
    outcomes: Vec<u8>,
    /// For each unknown outcome, which of the resolutions the form allows.
    resolutions: Vec<u8>,
    revocation: bool,
    /// Which records are covered by a checkpoint.
    checkpoints: Vec<bool>,
}

fn history() -> impl Strategy<Value = History> {
    (1usize..8).prop_flat_map(|n| {
        (
            prop::collection::vec(any::<bool>(), n),
            prop::collection::vec(0u8..8, n),
            prop::collection::vec(any::<u8>(), n),
            any::<bool>(),
            prop::collection::vec(any::<bool>(), n + 1),
        )
            .prop_map(
                |(allows, outcomes, resolutions, revocation, checkpoints)| History {
                    allows,
                    outcomes,
                    resolutions,
                    revocation,
                    checkpoints,
                },
            )
    })
}

/// The resolutions the form allows for an unknown outcome (all distinct).
fn valid_resolutions(mask: u8, outcome: &OutcomeRecord) -> Vec<ResolutionRecord> {
    use ResolutionSource::{ConflictResolution, OperatorAttested, ProviderStatus, Reconciler};
    use ResolutionState::{Ambiguous, ConfirmedDelivered as D, ConfirmedNotDelivered as N};
    const A: Option<&str> = Some("oidc:https://idp#alice");
    const B: Option<&str> = Some("oidc:https://idp#bob");
    let shapes = [
        (D, ProviderStatus, None, None, Some("answer")),
        (N, ProviderStatus, None, None, Some("answer")),
        (D, OperatorAttested, A, None, Some("console")),
        (N, OperatorAttested, A, B, Some("console")),
        (N, ConflictResolution, B, A, Some("review")),
        (Ambiguous, Reconciler, None, None, None),
    ];
    let mut rows: Vec<ResolutionRecord> = shapes
        .iter()
        .enumerate()
        .filter(|(i, _)| mask & (1 << i) != 0)
        .map(|(i, (state, source, by, approver, evidence))| {
            resolution_of(
                outcome,
                (*state, *source),
                *evidence,
                (*by, *approver),
                10 + i64::try_from(i).unwrap(),
            )
        })
        .collect();
    rows.sort_by_key(|r| (r.ts, r.source.as_str(), r.state.as_str()));
    rows
}

struct Built {
    dir: PathBuf,
    /// Lines of each file, as written.
    records: usize,
    outcomes: usize,
    resolutions: usize,
    checkpoints: usize,
}

fn build(history: &History, name: &str) -> Built {
    let decisions: Vec<Decision> = history
        .allows
        .iter()
        .map(|a| if *a { Decision::Pass } else { Decision::Block })
        .collect();
    let decided = decisions_of(&decisions);
    let mut chain: Vec<ChainRecord> = decided.iter().cloned().map(ChainRecord::Decision).collect();
    if history.revocation {
        chain.push(ChainRecord::Revocation(revocation(&decided)));
    }
    let key = evidence_key();
    let mut outcomes: Vec<OutcomeRecord> = Vec::new();
    let mut resolutions: Vec<ResolutionRecord> = Vec::new();
    for (record, shape) in decided.iter().zip(&history.outcomes) {
        let Some(credential) = record.payload.credential_id.as_deref() else {
            continue;
        };
        let (outcome, reason) = match shape {
            0 => continue,
            1 => (Outcome::Delivered, "provider_202"),
            2 => (Outcome::Failed, "connect_failed"),
            3 => (Outcome::Refused, "provider_422"),
            4 => (Outcome::NotExecuted, "no_destination"),
            _ => (Outcome::Unknown, "timeout_after_send"),
        };
        let row = sign_outcome(
            TENANT,
            credential,
            &record.hash,
            outcome,
            reason,
            record.payload.ts + Duration::seconds(2),
            &key,
        )
        .unwrap();
        if outcome == Outcome::Unknown {
            let mask = history.resolutions[usize::try_from(record.payload.seq - 1).unwrap()];
            resolutions.extend(valid_resolutions(mask, &row));
        }
        outcomes.push(row);
    }
    let mut checkpoints: Vec<Checkpoint> = Vec::new();
    for (i, covered) in history.checkpoints.iter().enumerate() {
        if *covered && i < chain.len() {
            let next = checkpoint_of_chain(&chain, i + 1, checkpoints.last());
            checkpoints.push(next);
        }
    }

    let dir = scratch(name);
    let mut writer = BundleWriter::create(&dir, SCOPE, SegmentStart::GENESIS).unwrap();
    for record in &chain {
        writer.record(record).unwrap();
    }
    for outcome in &outcomes {
        writer.outcome(outcome).unwrap();
    }
    for checkpoint in &checkpoints {
        writer.checkpoint(checkpoint).unwrap();
    }
    for resolution in &resolutions {
        writer.resolution(resolution).unwrap();
    }
    writer
        .finish(exported_at(), exporter(), Some(&export_key()))
        .unwrap();
    Built {
        dir,
        records: chain.len(),
        outcomes: outcomes.len(),
        resolutions: resolutions.len(),
        checkpoints: checkpoints.len(),
    }
}

// ---------------------------------------------------------------- verifiers

struct Verdict {
    accepted: bool,
    class: Option<String>,
    /// How many times each kind of finding was reported: the number of
    /// credentials for the three about credentials, 1 for the others.
    kinds: std::collections::BTreeMap<String, u64>,
    counts: Option<[u64; 4]>,
}

fn rust(dir: &Path) -> Verdict {
    match verify_dir(&VerifyRequest {
        bundle: dir,
        keys: &vectors().join("bundle-v2.keys.json"),
        expect_checkpoint: None,
        dev: false,
        now: now(),
    }) {
        Ok(report) => {
            // The Rust verifier reports each of the three per-credential
            // findings once, with the exact count (spec 9.1).
            let per_credential = [
                ("outcome_missing", report.outcome_missing.count),
                ("outcome_unknown", report.outcome_unknown.count),
                ("outcome_conflicted", report.outcome_conflicted.count),
            ];
            let kinds = report
                .not_protected()
                .iter()
                .map(|f| {
                    let kind = f.kind.to_string();
                    let n = per_credential
                        .iter()
                        .find(|(k, _)| *k == kind)
                        .map_or(1, |(_, n)| *n);
                    (kind, n)
                })
                .collect();
            Verdict {
                accepted: true,
                class: None,
                kinds,
                counts: Some([
                    report.records,
                    report.outcomes,
                    report.resolutions,
                    report.checkpoints,
                ]),
            }
        }
        Err(e) => Verdict {
            accepted: false,
            class: Some(e.class().to_string()),
            kinds: std::collections::BTreeMap::new(),
            counts: None,
        },
    }
}

/// `None` without python3 (CI must have it).
fn python(dir: &Path) -> Option<Verdict> {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance/kavach_verify.py");
    let output = Command::new("python3")
        .args(["-I"])
        .arg(script)
        .args(["bundle", "--keys"])
        .arg(vectors().join("bundle-v2.keys.json"))
        .args(["--allow-warnings", "--now"])
        .arg(now().format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .arg(dir)
        .output();
    let Ok(output) = output else {
        assert!(
            std::env::var_os("CI").is_none(),
            "python3 is required in CI for the verifier-agreement tests"
        );
        return None;
    };
    let doc: Value =
        serde_json::from_slice(&output.stdout).expect("the Python verifier prints JSON");
    if doc["result"] == "fail" {
        return Some(Verdict {
            accepted: false,
            class: doc["class"].as_str().map(str::to_string),
            kinds: std::collections::BTreeMap::new(),
            counts: None,
        });
    }
    // The Python verifier reports one finding per credential.
    let mut kinds = std::collections::BTreeMap::new();
    for warning in doc["warnings"].as_array().unwrap() {
        *kinds
            .entry(warning["kind"].as_str().unwrap().to_string())
            .or_insert(0u64) += 1;
    }
    let n = |key: &str| doc[key].as_u64().unwrap();
    Some(Verdict {
        accepted: true,
        class: None,
        kinds,
        counts: Some([
            n("records"),
            n("outcomes"),
            n("resolutions"),
            n("checkpoints"),
        ]),
    })
}

/// Both verifiers say the same: accept with the same counts and findings, or
/// refuse for the same class. Returns what they said.
fn agree(dir: &Path, context: &str) -> Result<Verdict, TestCaseError> {
    let r = rust(dir);
    let Some(p) = python(dir) else {
        return Ok(r);
    };
    prop_assert_eq!(
        r.accepted,
        p.accepted,
        "{}: Rust accepted={}, Python accepted={}",
        context,
        r.accepted,
        p.accepted
    );
    prop_assert_eq!(&r.class, &p.class, "{}: the failure class", context);
    prop_assert_eq!(
        &r.kinds,
        &p.kinds,
        "{}: what is not protected, and how many credentials",
        context
    );
    prop_assert_eq!(r.counts, p.counts, "{}: what the bundle holds", context);
    Ok(r)
}

// ---------------------------------------------------------------- damage

#[derive(Debug, Clone, Copy)]
enum File {
    Records,
    Outcomes,
    Checkpoints,
    Resolutions,
}

impl File {
    fn name(self) -> &'static str {
        match self {
            Self::Records => RECORDS_FILE,
            Self::Outcomes => OUTCOMES_FILE,
            Self::Checkpoints => CHECKPOINTS_FILE,
            Self::Resolutions => RESOLUTIONS_FILE,
        }
    }

    /// The class of failure that damage to this file ends in when the manifest
    /// has been rewritten to match.
    fn class(self) -> &'static str {
        match self {
            Self::Records => "chain",
            Self::Outcomes => "outcome",
            Self::Checkpoints => "checkpoint",
            Self::Resolutions => "resolution",
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Damage {
    Drop,
    Swap,
    Edit,
}

fn lines(dir: &Path, file: File) -> Vec<String> {
    fs::read_to_string(dir.join(file.name()))
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect()
}

fn write_lines(dir: &Path, file: File, lines: &[String]) {
    let mut text = lines.join("\n");
    if !lines.is_empty() {
        text.push('\n');
    }
    fs::write(dir.join(file.name()), text).unwrap();
}

/// Damages `file` at `at` (a line index, taken modulo the number of lines).
/// `false` when there is nothing there to damage.
fn damage(dir: &Path, file: File, how: Damage, at: usize) -> bool {
    let mut all = lines(dir, file);
    if all.is_empty() || (matches!(how, Damage::Swap) && all.len() < 2) {
        return false;
    }
    let i = at % all.len();
    match how {
        Damage::Drop => {
            all.remove(i);
        }
        Damage::Swap => {
            let j = (i + 1) % all.len();
            all.swap(i, j);
        }
        Damage::Edit => {
            let mut value: Value = serde_json::from_str(&all[i]).unwrap();
            let member = match file {
                // A member the record has, whatever its kind: editing one is
                // damage; adding one that the format does not define is a
                // different question (below).
                File::Records if value.get("purpose").is_some() => "purpose",
                File::Records => "source_system",
                File::Outcomes | File::Resolutions => "reason",
                File::Checkpoints => "ts",
            };
            value[member] = match file {
                File::Checkpoints => "2031-01-01T00:00:00Z".into(),
                _ => "edited_by_an_attacker".into(),
            };
            all[i] = serde_json::to_string(&value).unwrap();
        }
    }
    write_lines(dir, file, &all);
    true
}

fn entry(dir: &Path, file: &str) -> FileEntry {
    let bytes = fs::read(dir.join(file)).unwrap();
    FileEntry {
        sha256: format!("{:x}", Sha256::digest(&bytes)),
        count: u64::try_from(String::from_utf8_lossy(&bytes).lines().count()).unwrap(),
    }
}

/// What someone holding the export key can do: rewrite the manifest to match
/// the files as they now are (the segment from the records as they now are)
/// and sign it.
fn reseal(dir: &Path) {
    let records = lines(dir, File::Records);
    let head_hash = records.last().map_or_else(
        || GENESIS.to_string(),
        |line| {
            let value: Value = serde_json::from_str(line).unwrap();
            value["hash"].as_str().unwrap().to_string()
        },
    );
    let manifest = seal_manifest(
        ManifestDraft {
            scope: SCOPE,
            segment: Segment {
                after_seq: 0,
                after_hash: GENESIS.to_string(),
                last_seq: i64::try_from(records.len()).unwrap(),
                head_hash,
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

fn damage_kind() -> impl Strategy<Value = (File, Damage, usize)> {
    (
        prop::sample::select(vec![
            File::Records,
            File::Outcomes,
            File::Checkpoints,
            File::Resolutions,
        ]),
        prop::sample::select(vec![Damage::Drop, Damage::Swap, Damage::Edit]),
        any::<usize>(),
    )
}

// ---------------------------------------------------------------- the tests

fn config(cases: u32) -> ProptestConfig {
    ProptestConfig {
        cases,
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(config(40))]

    /// Every generated history is accepted by both, and they say the same.
    #[test]
    fn both_verifiers_accept_every_generated_history(history in history()) {
        let built = build(&history, "gen-ok");
        let verdict = agree(&built.dir, "a generated history")?;
        prop_assert!(verdict.accepted, "a bundle the exporter wrote was refused");
        prop_assert_eq!(
            verdict.counts,
            Some([built.records as u64, built.outcomes as u64, built.resolutions as u64, built.checkpoints as u64])
        );
    }

    /// Damage to a file with the manifest untouched: both refuse, and say the
    /// file no longer matches the manifest.
    #[test]
    fn damage_without_the_export_key_is_a_digest_failure_for_both(
        history in history(),
        (file, how, at) in damage_kind()
    ) {
        let built = build(&history, "gen-damage");
        if !damage(&built.dir, file, how, at) {
            return Ok(());
        }
        // A swap of two identical lines changes nothing.
        let verdict = agree(&built.dir, &format!("{how:?} {file:?}"))?;
        if !verdict.accepted {
            prop_assert_eq!(verdict.class.as_deref(), Some("digest"));
        }
    }
}

/// What the resealed damage came to, by (file, damage, verdict): the test
/// shows it did not run on cases that were mostly nothing.
static TALLY: std::sync::Mutex<std::collections::BTreeMap<String, u32>> =
    std::sync::Mutex::new(std::collections::BTreeMap::new());

/// Damage by someone who can sign the manifest: the two verifiers still say
/// the same, and for the damage that must be seen they refuse with the class
/// of the file that was touched.
#[test]
fn damage_with_the_export_key_is_refused_in_the_same_class() {
    use proptest::test_runner::{Config, TestRunner};
    let mut runner = TestRunner::new(Config {
        cases: 150,
        failure_persistence: None,
        ..Config::default()
    });
    runner
        .run(&(history(), damage_kind()), |(history, (file, how, at))| {
            let built = build(&history, "gen-resealed");
            if !damage(&built.dir, file, how, at) {
                return Ok(());
            }
            reseal(&built.dir);
            let verdict = agree(&built.dir, &format!("{how:?} {file:?} (resealed)"))?;
            let seen = match &verdict.class {
                Some(class) => class.clone(),
                None => "accepted".to_string(),
            };
            *TALLY
                .lock()
                .unwrap()
                .entry(format!("{file:?} {how:?} -> {seen}"))
                .or_insert(0) += 1;
            // What cannot be seen once the manifest is signed to match: nothing
            // ties an outcome, a resolution or a checkpoint to the rest but the
            // manifest, so removing one is not an error; and the last record cut
            // off leaves a consistent, shorter chain.
            let last_record_cut = matches!((file, how), (File::Records, Damage::Drop))
                && at % built.records == built.records - 1;
            let unseen = matches!(
                (file, how),
                (
                    File::Outcomes | File::Resolutions | File::Checkpoints,
                    Damage::Drop
                )
            ) || last_record_cut;
            if unseen {
                return Ok(());
            }
            // Everything else is refused in the class of the file touched. The
            // one exception is a swap of two identical lines, which changes
            // nothing: then both accept.
            if verdict.accepted {
                prop_assert!(
                    matches!(how, Damage::Swap),
                    "{how:?} {file:?} was accepted by both"
                );
            } else {
                let expected: &[&str] = match file {
                    // Records out of order, edited or dropped from the middle:
                    // the chain, or a checkpoint that no longer matches the
                    // record at its position.
                    File::Records => &["chain", "checkpoint"],
                    _ => &[file.class()],
                };
                prop_assert!(
                    expected.contains(&verdict.class.as_deref().unwrap_or("")),
                    "{how:?} {file:?}: refused as {:?}, expected one of {expected:?}",
                    verdict.class
                );
            }
            Ok(())
        })
        .unwrap_or_else(|e| panic!("{e}"));

    let tally = TALLY.lock().unwrap();
    println!("{tally:#?}");
    let count = |prefix: &str| -> u32 {
        tally
            .iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .map(|(_, n)| n)
            .sum()
    };
    for (prefix, at_least) in [
        ("Records Edit -> chain", 3),
        ("Records Swap -> chain", 2),
        ("Outcomes Edit -> outcome", 3),
        ("Checkpoints Edit -> checkpoint", 3),
        ("Resolutions Edit -> resolution", 2),
        ("Outcomes Drop -> accepted", 2),
    ] {
        assert!(
            count(prefix) >= at_least,
            "{prefix}: {} < {at_least}\n{tally:#?}",
            count(prefix)
        );
    }
}

/// A member the format does not define, added to a line by someone who can
/// sign the manifest, is not covered by any hash or signature, so it would be
/// unsigned data riding through the audit chain. The format's rule (spec 5.3
/// for resolutions, and the principle for the rest) is that nothing unsigned
/// rides along, so both verifiers must refuse it, and in the same class.
/// (This is the shrunk case the generator first found; the verifiers
/// disagreed until the explicit member lists, see `undefined_members.rs`.)
#[test]
fn an_unsigned_member_added_to_any_line_is_refused_by_both() {
    let history = History {
        allows: vec![true, true, false],
        outcomes: vec![5, 1, 0],
        resolutions: vec![0b0000_0001, 0, 0],
        revocation: true,
        checkpoints: vec![false, true, false, true],
    };
    let mut report = Vec::new();
    let mut disagreements = Vec::new();
    for file in [
        File::Records,
        File::Outcomes,
        File::Checkpoints,
        File::Resolutions,
    ] {
        let n = {
            let built = build(&history, "extra-count");
            lines(&built.dir, file).len()
        };
        for at in 0..n {
            let built = build(&history, "extra-member");
            let mut all = lines(&built.dir, file);
            let mut value: Value = serde_json::from_str(&all[at]).unwrap();
            value["x_unsigned_note"] = "rides along".into();
            all[at] = serde_json::to_string(&value).unwrap();
            write_lines(&built.dir, file, &all);
            reseal(&built.dir);
            let (r, p) = (rust(&built.dir), python(&built.dir).expect("python3"));
            let kind = if file.name() == RECORDS_FILE {
                value["kind"].as_str().unwrap_or("?").to_string()
            } else {
                "-".to_string()
            };
            report.push(format!(
                "{} line {} {kind}: Rust {} {:?}, Python {} {:?}",
                file.name(),
                at + 1,
                if r.accepted { "accepts" } else { "refuses" },
                r.class,
                if p.accepted { "accepts" } else { "refuses" },
                p.class
            ));
            if r.accepted != p.accepted || r.class != p.class || r.accepted {
                disagreements.push(report.last().unwrap().clone());
            }
        }
    }
    println!("{}", report.join("\n"));
    assert!(
        disagreements.is_empty(),
        "the verifiers disagree, or accept unsigned data:\n{}",
        disagreements.join("\n")
    );
}

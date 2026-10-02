//! `kavach-evidence export` and `checkpoints` against Postgres, as the
//! read-only `kavach_auditor` role (E3b). Runs where a test database is
//! configured (always in CI).
#![cfg(feature = "export")]

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use chrono::{Duration, Utc};
use kavach_evidence_cli::export::{export, ExportRequest};
use kavach_evidence_cli::postgres::{
    run_checkpoints, run_export, CommandError, Signing, Target, Which,
};
use kavach_keys::LocalFileKeyProvider;
use kavach_ports::agent_evidence::{
    sign_outcome, verify_segment, AgentDecisionRecord, AgentEvidenceStore, CommitResult, DevKeys,
    Outcome, OutcomeRecord, SegmentStart, TimeSync,
};
use kavach_ports::bundle::{
    verify_manifest, Manifest, ManifestSignature, CHECKPOINTS_FILE, MANIFEST_FILE, OUTCOMES_FILE,
    RECORDS_FILE,
};
use kavach_ports::checkpoint::{
    sign_checkpoint, verify_checkpoints, Appended, ChainSegment, Checkpoint, CheckpointStore, Head,
    Scope, CHAIN_AGENT_DECISIONS,
};
use kavach_ports::PublicKey;
use kavach_ports_testkit::agent_evidence::{request, TestSigner};
use kavach_ports_testkit::FakeClock;
use kavach_storage::testing::{auditor_url, isolated_database_urls};
use kavach_storage::{EvidenceSnapshot, PostgresAgentEvidenceStore, StoragePool};
use serde::de::DeserializeOwned;

const TENANT: &str = "default";
const SCOPE: Scope<'static> = Scope {
    tenant_id: TENANT,
    partition_id: 0,
    chain: CHAIN_AGENT_DECISIONS,
};
const EXPORT_KID: &str = "export-test-1";

fn evidence_key() -> TestSigner {
    TestSigner::new("evidence-test", 9)
}

fn checkpoint_key() -> TestSigner {
    TestSigner::new("checkpoint-test", 11)
}

/// A deployment with some history, and the roles to read it.
struct World {
    store: PostgresAgentEvidenceStore,
    clock: FakeClock,
    owner: String,
    runtime: String,
    auditor: String,
    key_dir: PathBuf,
    keys: BTreeMap<String, PublicKey>,
    committed: usize,
}

impl World {
    /// Five records; outcomes for records 1 and 3; checkpoints at 2 and 4.
    async fn new() -> Option<Self> {
        let (owner, runtime) = isolated_database_urls().await?;
        let pool = StoragePool::connect_with_roles(&runtime, Some(&owner))
            .await
            .expect("migrate and connect");
        let key_dir = common::scratch("export-keys");
        let export_public = LocalFileKeyProvider::new(&key_dir)
            .create_key(EXPORT_KID)
            .expect("export key");
        let mut keys = evidence_key().keys();
        keys.extend(checkpoint_key().keys());
        keys.insert(EXPORT_KID.into(), export_public);
        let mut world = Self {
            store: pool.agent_evidence_store(),
            clock: FakeClock::synced_at(Utc::now() - Duration::hours(1)),
            auditor: auditor_url(&owner),
            owner,
            runtime,
            key_dir,
            keys,
            committed: 0,
        };
        let mut records = Vec::new();
        for _ in 0..5 {
            records.push(world.commit().await);
        }
        for index in [0, 2] {
            let outcome = sign_outcome(
                TENANT,
                records[index].payload.credential_id.as_deref().unwrap(),
                &records[index].hash,
                Outcome::Delivered,
                "provider_202",
                records[index].payload.ts,
                &evidence_key(),
            )
            .unwrap();
            world.store.record_outcome(outcome).await.unwrap();
        }
        let mut previous: Option<Checkpoint> = None;
        for seq in [2usize, 4] {
            let checkpoint = sign_checkpoint(
                Head {
                    scope: SCOPE,
                    seq: i64::try_from(seq).unwrap(),
                    hash: &records[seq - 1].hash,
                },
                previous.as_ref(),
                records[seq - 1].payload.ts,
                TimeSync {
                    status: "synced".into(),
                    max_error_ms: Some(10),
                },
                &checkpoint_key(),
            )
            .unwrap();
            assert_eq!(
                world.store.append(&checkpoint).await.unwrap(),
                Appended::Written
            );
            previous = Some(checkpoint);
        }
        Some(world)
    }

    async fn commit(&mut self) -> AgentDecisionRecord {
        self.committed += 1;
        let mut req = request(TENANT, &format!("export-{}", self.committed), 1);
        req.contact = None;
        req.draft.send_by = None;
        match self
            .store
            .commit(req, &self.clock, &evidence_key())
            .await
            .unwrap()
        {
            CommitResult::Committed(record) => *record,
            other => panic!("expected a new record, got {other:?}"),
        }
    }

    fn signing(&self) -> Signing {
        Signing::Key {
            key_dir: self.key_dir.clone(),
            key_id: EXPORT_KID.into(),
        }
    }
}

fn target(url: &str) -> Target {
    Target {
        database_url: url.into(),
        tenant_id: TENANT.into(),
        partition_id: 0,
        allow_write_role: false,
    }
}

fn lines<T: DeserializeOwned>(path: &Path) -> Vec<T> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

/// Verifies a bundle on disk with the operator's keys; returns its manifest.
fn verify_bundle(out: &Path, keys: &BTreeMap<String, PublicKey>) -> Manifest {
    let manifest: Manifest =
        serde_json::from_slice(&fs::read(out.join(MANIFEST_FILE)).unwrap()).unwrap();
    assert!(matches!(
        verify_manifest(&manifest, keys, DevKeys::Refuse),
        Ok(ManifestSignature::Signed { .. })
    ));
    let p = &manifest.payload;
    let records: Vec<AgentDecisionRecord> = lines(&out.join(RECORDS_FILE));
    let outcomes: Vec<OutcomeRecord> = lines(&out.join(OUTCOMES_FILE));
    let checkpoints: Vec<Checkpoint> = lines(&out.join(CHECKPOINTS_FILE));
    let start = SegmentStart {
        seq: p.segment.after_seq,
        hash: &p.segment.after_hash,
    };
    verify_segment(
        &records,
        start,
        keys,
        Some((p.segment.last_seq, &p.segment.head_hash)),
        &outcomes,
        Utc::now(),
        DevKeys::Refuse,
    )
    .expect("records and outcomes verify");
    let segment = ChainSegment::of_records(start, &records);
    verify_checkpoints(&checkpoints, SCOPE, &segment, keys, DevKeys::Refuse)
        .expect("checkpoints verify");
    manifest
}

#[tokio::test(flavor = "multi_thread")]
async fn the_auditor_exports_a_bundle_that_verifies() {
    let Some(world) = World::new().await else {
        return;
    };
    let out = common::scratch("pg-export");
    let summary = run_export(&target(&world.auditor), None, &out, &world.signing())
        .await
        .expect("export as kavach_auditor");
    let manifest = verify_bundle(&out, &world.keys);
    assert_eq!(manifest, summary.manifest);
    let p = &manifest.payload;
    assert_eq!((p.segment.after_seq, p.segment.last_seq), (0, 5));
    assert_eq!(
        (
            p.files.records.count,
            p.files.outcomes.count,
            p.files.checkpoints.count
        ),
        (5, 2, 2)
    );
    assert_eq!(
        (summary.last_checkpoint, summary.uncovered_records),
        (Some(4), 1)
    );
    assert_eq!(p.key_id.as_deref(), Some(EXPORT_KID));

    // A segment after the first checkpoint.
    let segment_out = common::scratch("pg-export-segment");
    let summary = run_export(
        &target(&world.auditor),
        Some(2),
        &segment_out,
        &world.signing(),
    )
    .await
    .unwrap();
    let p = &verify_bundle(&segment_out, &world.keys).payload;
    assert_eq!((p.segment.after_seq, p.segment.last_seq), (2, 5));
    assert_eq!(
        (
            p.files.records.count,
            p.files.outcomes.count,
            p.files.checkpoints.count
        ),
        (3, 1, 2)
    );
    assert_eq!(summary.last_checkpoint, Some(4));

    fs::remove_dir_all(&out).unwrap();
    fs::remove_dir_all(&segment_out).unwrap();
    fs::remove_dir_all(&world.key_dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn an_export_is_one_snapshot_whatever_is_written_meanwhile() {
    let Some(mut world) = World::new().await else {
        return;
    };
    let mut snapshot = EvidenceSnapshot::open(&world.auditor, TENANT, 0)
        .await
        .expect("open as kavach_auditor");
    assert!(!snapshot.can_write());

    // The deployment keeps working while the export runs.
    world.commit().await;
    world.commit().await;

    let out = common::scratch("pg-snapshot");
    let key = common::export_key();
    let summary = export(
        &mut snapshot,
        ExportRequest {
            scope: SCOPE,
            after_checkpoint: None,
            out: &out,
            signer: Some(&key),
            exported_at: Utc::now(),
            exporter: common::exporter(),
            page: 2,
        },
    )
    .await
    .unwrap();
    assert_eq!(
        summary.manifest.payload.segment.last_seq, 5,
        "as of the snapshot"
    );
    drop(snapshot);

    // A new export sees the new records.
    let later = common::scratch("pg-later");
    let summary = run_export(&target(&world.auditor), None, &later, &world.signing())
        .await
        .unwrap();
    assert_eq!(summary.manifest.payload.segment.last_seq, 7);
    assert_eq!(summary.uncovered_records, 3);

    fs::remove_dir_all(&out).unwrap();
    fs::remove_dir_all(&later).unwrap();
    fs::remove_dir_all(&world.key_dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_role_that_can_write_and_a_key_that_is_not_an_export_key_are_refused() {
    let Some(world) = World::new().await else {
        return;
    };
    // The API's own role and the owner can change evidence: refused.
    for url in [&world.runtime, &world.owner] {
        let out = common::scratch("pg-write-role");
        let err = run_export(&target(url), None, &out, &world.signing())
            .await
            .unwrap_err();
        assert!(matches!(err, CommandError::WriteRole), "{err}");
        assert!(!out.exists());
        let err = run_checkpoints(&target(url), Which::Latest)
            .await
            .unwrap_err();
        assert!(matches!(err, CommandError::WriteRole), "{err}");
    }
    // …unless a development stack says so.
    let out = common::scratch("pg-allowed");
    let mut development = target(&world.runtime);
    development.allow_write_role = true;
    run_export(&development, None, &out, &world.signing())
        .await
        .unwrap();
    fs::remove_dir_all(&out).unwrap();

    // Only an export key signs, checked before the database is touched.
    let out = common::scratch("pg-wrong-key");
    let wrong = Signing::Key {
        key_dir: world.key_dir.clone(),
        key_id: "kavach-checkpoint-1".into(),
    };
    let unreachable = target("postgres://nobody@127.0.0.1:9/none");
    let err = run_export(&unreachable, None, &out, &wrong)
        .await
        .unwrap_err();
    assert!(matches!(err, CommandError::Key(_)), "{err}");
    assert!(err.to_string().contains("not an export key"), "{err}");
    // An export key that is not there.
    let missing = Signing::Key {
        key_dir: world.key_dir.clone(),
        key_id: "export-missing-1".into(),
    };
    let err = run_export(&target(&world.auditor), None, &out, &missing)
        .await
        .unwrap_err();
    assert!(matches!(err, CommandError::Key(_)), "{err}");
    assert!(!out.exists());

    fs::remove_dir_all(&world.key_dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn checkpoints_are_listed_for_copying_off_host() {
    let Some(world) = World::new().await else {
        return;
    };
    let target = target(&world.auditor);
    let seqs = |checkpoints: Vec<Checkpoint>| -> Vec<i64> {
        checkpoints.iter().map(|c| c.payload.seq).collect()
    };
    assert_eq!(
        seqs(run_checkpoints(&target, Which::Latest).await.unwrap()),
        [4]
    );
    assert_eq!(
        seqs(run_checkpoints(&target, Which::After(0)).await.unwrap()),
        [2, 4]
    );
    assert_eq!(
        seqs(run_checkpoints(&target, Which::After(2)).await.unwrap()),
        [4]
    );
    assert!(run_checkpoints(&target, Which::After(4))
        .await
        .unwrap()
        .is_empty());
    fs::remove_dir_all(&world.key_dir).unwrap();
}

/// Runs the real binary as the auditor.
fn cli(world: &World, args: &[&str]) -> (Option<i32>, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_kavach-evidence"))
        .args(args)
        .env("KAVACH_AUDITOR_DATABASE_URL", &world.auditor)
        .output()
        .expect("run kavach-evidence");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    // The database password never reaches the output.
    assert!(!stdout.contains("kavach-auditor-test"), "{stdout}");
    assert!(!stderr.contains("kavach-auditor-test"), "{stderr}");
    (output.status.code(), stdout, stderr)
}

#[tokio::test(flavor = "multi_thread")]
async fn export_and_checkpoints_work_from_the_command_line() {
    let Some(world) = World::new().await else {
        return;
    };
    let key_dir = world.key_dir.to_str().unwrap();
    let out = common::scratch("pg-cli");
    let export = [
        "export",
        "--out",
        out.to_str().unwrap(),
        "--key-dir",
        key_dir,
        "--key-id",
        EXPORT_KID,
    ];

    let (code, stdout, stderr) = cli(&world, &export);
    assert_eq!(code, Some(0), "{stdout}{stderr}");
    assert!(
        stdout.contains(
            "OK: exported 5 record(s) (after 0 through 5), 2 outcome(s), 2 checkpoint(s)"
        ),
        "{stdout}"
    );
    assert!(
        stdout.contains(&format!("signed with: {EXPORT_KID}")),
        "{stdout}"
    );
    assert!(
        stderr.contains("1 record(s) are newer than the last checkpoint"),
        "{stderr}"
    );
    verify_bundle(&out, &world.keys);

    // The target exists now: refused, and left as it is.
    let (code, _, stderr) = cli(&world, &export);
    assert_eq!(code, Some(1));
    assert!(stderr.starts_with("FAIL: "), "{stderr}");
    verify_bundle(&out, &world.keys);

    // The newest checkpoint, as one JSON line.
    let (code, stdout, stderr) = cli(&world, &["checkpoints", "--latest"]);
    assert_eq!(code, Some(0), "{stderr}");
    let printed: Vec<Checkpoint> = stdout
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(printed.len(), 1);
    assert_eq!(printed[0].payload.seq, 4);
    let (code, _, stderr) = cli(&world, &["checkpoints"]);
    assert_eq!(code, Some(1));
    assert!(stderr.contains("--latest or --after"), "{stderr}");

    fs::remove_dir_all(&out).unwrap();
    fs::remove_dir_all(&world.key_dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unsigned_export_must_be_asked_for_and_says_so() {
    let Some(world) = World::new().await else {
        return;
    };
    let out = common::scratch("pg-cli-unsigned");
    let target = out.to_str().unwrap();

    // Nothing says how to sign: refused, nothing written.
    let (code, _, stderr) = cli(&world, &["export", "--out", target]);
    assert_eq!(code, Some(1));
    assert!(stderr.contains("--unsigned"), "{stderr}");
    assert!(!out.exists());

    let (code, _, stderr) = cli(&world, &["export", "--out", target, "--unsigned"]);
    assert_eq!(code, Some(0), "{stderr}");
    assert!(stderr.contains("UNSIGNED"), "{stderr}");
    let manifest: Manifest =
        serde_json::from_slice(&fs::read(out.join(MANIFEST_FILE)).unwrap()).unwrap();
    assert_eq!(
        verify_manifest(&manifest, &world.keys, DevKeys::Refuse),
        Ok(ManifestSignature::Unsigned)
    );

    // A database that cannot be reached is a plain failure, without the
    // password in it.
    let down = Command::new(env!("CARGO_BIN_EXE_kavach-evidence"))
        .args(["checkpoints", "--latest"])
        .env(
            "KAVACH_AUDITOR_DATABASE_URL",
            "postgres://u:secret-pw@127.0.0.1:9/none",
        )
        .output()
        .unwrap();
    assert_eq!(down.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&down.stderr);
    assert!(
        stderr.starts_with("FAIL: ") && !stderr.contains("secret-pw"),
        "{stderr}"
    );

    fs::remove_dir_all(&out).unwrap();
    fs::remove_dir_all(&world.key_dir).unwrap();
}

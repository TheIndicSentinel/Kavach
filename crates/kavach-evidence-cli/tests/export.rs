//! The export logic against an in-memory snapshot: what it reads in pages
//! becomes the same bundle, a segment starts after a checkpoint, and an
//! inconsistent source writes nothing.

mod common;

use std::fs;
use std::future::{ready, Future};
use std::path::{Path, PathBuf};

use kavach_evidence_cli::export::{export, ExportError, ExportRequest, ExportSource};
use kavach_evidence_cli::writer::BundleError;
use kavach_ports::agent_evidence::ChainEntry as _;
use kavach_ports::agent_evidence::{AgentDecisionRecord, OutcomeRecord};
use kavach_ports::bundle::{CHECKPOINTS_FILE, MANIFEST_FILE, OUTCOMES_FILE, RECORDS_FILE};
use kavach_ports::chain_record::ChainRecord;
use kavach_ports::checkpoint::Checkpoint;
use kavach_ports::PortError;

use common::*;

/// The fixture run as a snapshot. `reads` counts the pages asked for.
struct Memory {
    head: Option<(i64, String)>,
    records: Vec<ChainRecord>,
    outcomes: Vec<(i64, OutcomeRecord)>,
    checkpoints: Vec<Checkpoint>,
    reads: usize,
}

impl Memory {
    /// The four decisions (bundle format 1's run, exported as format 2).
    fn fixture() -> Self {
        let decisions = records();
        Self::of(
            decisions
                .iter()
                .cloned()
                .map(ChainRecord::Decision)
                .collect(),
            checkpoints(&decisions),
        )
    }

    /// The decisions and the revocation: the format 2 vector's run.
    fn fixture_v2() -> Self {
        let chain = chain_v2();
        let checkpoints = checkpoints_v2(&chain);
        Self::of(chain, checkpoints)
    }

    fn of(records: Vec<ChainRecord>, checkpoints: Vec<Checkpoint>) -> Self {
        let decisions: Vec<AgentDecisionRecord> = records
            .iter()
            .filter_map(|r| r.as_decision().cloned())
            .collect();
        let outcomes = outcomes(&decisions)
            .into_iter()
            .map(|outcome| {
                let seq = decisions
                    .iter()
                    .find(|r| r.payload.credential_id.as_deref() == Some(&outcome.credential_id))
                    .unwrap()
                    .payload
                    .seq;
                (seq, outcome)
            })
            .collect();
        Self {
            head: records.last().map(|r| (r.seq(), r.hash().to_string())),
            checkpoints,
            outcomes,
            records,
            reads: 0,
        }
    }
}

fn page<T: Clone>(items: impl Iterator<Item = T>, limit: u32) -> Vec<T> {
    items.take(limit as usize).collect()
}

impl ExportSource for Memory {
    fn head(&mut self) -> impl Future<Output = Result<Option<(i64, String)>, PortError>> {
        ready(Ok(self.head.clone()))
    }
    fn records(
        &mut self,
        after_seq: i64,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<ChainRecord>, PortError>> {
        self.reads += 1;
        let rows = self.records.iter().filter(|r| r.seq() > after_seq);
        ready(Ok(page(rows.cloned(), limit)))
    }
    fn outcomes(
        &mut self,
        after_seq: i64,
        through_seq: i64,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<(i64, OutcomeRecord)>, PortError>> {
        self.reads += 1;
        let rows = self
            .outcomes
            .iter()
            .filter(|(seq, _)| *seq > after_seq && *seq <= through_seq);
        ready(Ok(page(rows.cloned(), limit)))
    }
    fn checkpoints(
        &mut self,
        after_seq: i64,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<Checkpoint>, PortError>> {
        self.reads += 1;
        let rows = self
            .checkpoints
            .iter()
            .filter(|c| c.payload.seq > after_seq);
        ready(Ok(page(rows.cloned(), limit)))
    }
}

fn request<'a>(out: &'a Path, after_checkpoint: Option<i64>, key: &'a Key) -> ExportRequest<'a> {
    ExportRequest {
        scope: SCOPE,
        after_checkpoint,
        out,
        signer: Some(key),
        exported_at: exported_at(),
        exporter: exporter(),
        page: 1,
    }
}

fn vector(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/bundle-v2")
        .join(name)
}

fn nothing_written(out: &Path) {
    let partial = out.with_file_name(format!(
        "{}.partial",
        out.file_name().unwrap().to_str().unwrap()
    ));
    assert!(!out.exists() && !partial.exists(), "{}", out.display());
}

#[tokio::test]
async fn a_paged_export_is_the_checked_in_bundle_byte_for_byte() {
    let key = export_key();
    for page in [1, 2, 3, 1000] {
        let out = scratch("export");
        let mut source = Memory::fixture_v2();
        let summary = export(
            &mut source,
            ExportRequest {
                page,
                ..request(&out, None, &key)
            },
        )
        .await
        .unwrap();
        for name in [MANIFEST_FILE, RECORDS_FILE, OUTCOMES_FILE, CHECKPOINTS_FILE] {
            assert_eq!(
                fs::read(out.join(name)).unwrap(),
                fs::read(vector(name)).unwrap(),
                "{name} with pages of {page}"
            );
        }
        // The third checkpoint covers the revocation, the newest record.
        assert_eq!(summary.last_checkpoint, Some(5));
        assert_eq!(summary.uncovered_records, 0);
        if page == 1 {
            assert!(source.reads > 8, "read in pages: {}", source.reads);
        }
        fs::remove_dir_all(&out).unwrap();
    }
}

#[tokio::test]
async fn a_segment_starts_after_an_existing_checkpoint() {
    let key = export_key();
    let all = Memory::fixture();

    // After the checkpoint at record 2: records 3 and 4, the outcome of
    // record 3, and the checkpoints from that one on.
    let out = scratch("export-segment");
    let summary = export(&mut Memory::fixture(), request(&out, Some(2), &key))
        .await
        .unwrap();
    let p = &summary.manifest.payload;
    assert_eq!((p.segment.after_seq, p.segment.last_seq), (2, 4));
    assert_eq!(p.segment.after_hash, all.records[1].hash());
    assert_eq!(
        (
            p.files.records.count,
            p.files.outcomes.count,
            p.files.checkpoints.count
        ),
        (2, 1, 2)
    );
    let checkpoints = fs::read_to_string(out.join(CHECKPOINTS_FILE)).unwrap();
    assert!(checkpoints
        .lines()
        .next()
        .unwrap()
        .contains(&all.checkpoints[0].hash));
    let outcomes = fs::read_to_string(out.join(OUTCOMES_FILE)).unwrap();
    assert!(
        outcomes.contains("cred-3") && !outcomes.contains("cred-1"),
        "{outcomes}"
    );
    assert_eq!(
        (summary.last_checkpoint, summary.uncovered_records),
        (Some(3), 1)
    );
    fs::remove_dir_all(&out).unwrap();

    // After the newest checkpoint: one record, none of it covered yet.
    let out = scratch("export-tail");
    let summary = export(&mut Memory::fixture(), request(&out, Some(3), &key))
        .await
        .unwrap();
    let p = &summary.manifest.payload;
    assert_eq!((p.files.records.count, p.files.checkpoints.count), (1, 1));
    assert_eq!(summary.uncovered_records, 1);
    fs::remove_dir_all(&out).unwrap();

    // Record 4 has no checkpoint: a segment cannot start there.
    for seq in [1, 4, 9] {
        let out = scratch("export-nowhere");
        let err = export(&mut Memory::fixture(), request(&out, Some(seq), &key))
            .await
            .unwrap_err();
        assert!(
            matches!(err, ExportError::NoCheckpoint(s) if s == seq),
            "{err}"
        );
        nothing_written(&out);
    }
}

#[tokio::test]
async fn an_empty_chain_exports_as_an_empty_bundle() {
    let key = export_key();
    let out = scratch("export-empty");
    let mut source = Memory {
        head: None,
        records: vec![],
        outcomes: vec![],
        checkpoints: vec![],
        reads: 0,
    };
    let summary = export(&mut source, request(&out, None, &key))
        .await
        .unwrap();
    let p = &summary.manifest.payload;
    assert_eq!((p.segment.after_seq, p.segment.last_seq), (0, 0));
    assert_eq!(p.files.records.count, 0);
    assert_eq!(
        (summary.last_checkpoint, summary.uncovered_records),
        (None, 0)
    );
    fs::remove_dir_all(&out).unwrap();
}

#[tokio::test]
async fn an_inconsistent_source_or_an_existing_target_writes_nothing() {
    let key = export_key();
    let inconsistent = |err: ExportError, what: &str| {
        assert!(matches!(err, ExportError::Inconsistent(_)), "{what}: {err}");
    };

    // The head says five records; four exist.
    let out = scratch("export-gap");
    let mut source = Memory::fixture();
    source.head = Some((5, "ab".repeat(32)));
    let err = export(&mut source, request(&out, None, &key))
        .await
        .unwrap_err();
    inconsistent(err, "records end before the head");
    nothing_written(&out);

    // The head's hash is not the last record's.
    let out = scratch("export-head");
    let mut source = Memory::fixture();
    source.head = Some((4, "ab".repeat(32)));
    let err = export(&mut source, request(&out, None, &key))
        .await
        .unwrap_err();
    inconsistent(err, "head hash differs");
    nothing_written(&out);

    // The chain was cut to two records; a checkpoint still covers record 3.
    let out = scratch("export-cut");
    let mut source = Memory::fixture();
    source.records.truncate(2);
    source.head = source
        .records
        .last()
        .map(|r| (r.seq(), r.hash().to_string()));
    let err = export(&mut source, request(&out, None, &key))
        .await
        .unwrap_err();
    inconsistent(err, "a checkpoint ahead of the chain");
    nothing_written(&out);
    // The same when the segment is asked to start at that checkpoint.
    let err = export(&mut source, request(&out, Some(3), &key))
        .await
        .unwrap_err();
    inconsistent(err, "a segment after a checkpoint ahead of the chain");
    nothing_written(&out);

    // A record that does not link (the writer refuses it).
    let out = scratch("export-unlinked");
    let mut source = Memory::fixture();
    if let ChainRecord::Decision(record) = &mut source.records[2] {
        record.payload.prev_hash = "ee".repeat(32);
    }
    let err = export(&mut source, request(&out, None, &key))
        .await
        .unwrap_err();
    assert!(
        matches!(err, ExportError::Bundle(BundleError::Inconsistent(_))),
        "{err}"
    );
    nothing_written(&out);

    // An existing target is left alone.
    let out = scratch("export-exists");
    fs::create_dir(&out).unwrap();
    let err = export(&mut Memory::fixture(), request(&out, None, &key))
        .await
        .unwrap_err();
    assert!(
        matches!(err, ExportError::Bundle(BundleError::Exists(_))),
        "{err}"
    );
    assert!(fs::read_dir(&out).unwrap().next().is_none());
    fs::remove_dir(&out).unwrap();
}

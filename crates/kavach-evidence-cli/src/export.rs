//! Exports one segment of the agent chain as a bundle (ADR-005 §13).
//!
//! The source is one consistent snapshot ([`ExportSource`]); it is read in
//! pages, so a large chain is never held in memory. The export itself does
//! not verify signatures: it copies what is stored, and the bundle is
//! verified afterwards with keys the operator supplies.

use std::future::Future;
use std::path::Path;

use chrono::{DateTime, Utc};
use kavach_ports::agent_evidence::{
    AgentDecisionRecord, EvidenceSigner, OutcomeRecord, SegmentStart, GENESIS,
};
use kavach_ports::bundle::{Exporter, Manifest};
use kavach_ports::checkpoint::{Checkpoint, Scope};
use kavach_ports::PortError;

use crate::writer::{BundleError, BundleWriter};

/// Rows per read.
pub const DEFAULT_PAGE: u32 = 1_000;

/// One consistent snapshot of one chain. Every read sees the same state.
pub trait ExportSource {
    /// The newest record (`seq`, hash); `None` while the chain has none.
    fn head(&mut self) -> impl Future<Output = Result<Option<(i64, String)>, PortError>>;

    /// Records with `seq > after_seq`, in `seq` order, at most `limit`.
    fn records(
        &mut self,
        after_seq: i64,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<AgentDecisionRecord>, PortError>>;

    /// Outcomes of the records with `after_seq < seq <= through_seq`, each
    /// with its record's `seq`, in that order, at most `limit`.
    fn outcomes(
        &mut self,
        after_seq: i64,
        through_seq: i64,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<(i64, OutcomeRecord)>, PortError>>;

    /// Checkpoints with `seq > after_seq`, in `seq` order, at most `limit`.
    fn checkpoints(
        &mut self,
        after_seq: i64,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<Checkpoint>, PortError>>;
}

#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    #[error(transparent)]
    Bundle(#[from] BundleError),
    #[error("reading the evidence: {}", .0.message)]
    Source(#[from] PortError),
    #[error("there is no checkpoint at record {0}; a segment starts after an existing checkpoint")]
    NoCheckpoint(i64),
    /// What was read is not one whole chain segment. Nothing is written.
    #[error("the stored evidence is inconsistent: {0}")]
    Inconsistent(String),
}

/// What to export and how.
pub struct ExportRequest<'a> {
    pub scope: Scope<'a>,
    /// Export only the records after the checkpoint at this `seq`.
    pub after_checkpoint: Option<i64>,
    pub out: &'a Path,
    /// The export key; `None` writes an unsigned bundle.
    pub signer: Option<&'a dyn EvidenceSigner>,
    pub exported_at: DateTime<Utc>,
    pub exporter: Exporter,
    pub page: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportSummary {
    pub manifest: Manifest,
    /// `seq` of the newest checkpoint in the bundle.
    pub last_checkpoint: Option<i64>,
    /// Records newer than that checkpoint (all of them when there is none):
    /// not covered by any checkpoint yet.
    pub uncovered_records: i64,
}

/// Reads the segment from `source` and writes it to `request.out`: a whole
/// bundle, or an error and nothing on disk.
pub async fn export<S: ExportSource>(
    source: &mut S,
    request: ExportRequest<'_>,
) -> Result<ExportSummary, ExportError> {
    let page = request.page.max(1);
    let head = source.head().await?;
    let (head_seq, head_hash) = head.unwrap_or((0, GENESIS.to_string()));

    // Where the segment starts: the first record, or after a checkpoint.
    let start_checkpoint = match request.after_checkpoint {
        None => None,
        Some(seq) => Some(
            source
                .checkpoints(seq - 1, 1)
                .await?
                .into_iter()
                .find(|c| c.payload.seq == seq)
                .ok_or(ExportError::NoCheckpoint(seq))?,
        ),
    };
    let start = start_checkpoint
        .as_ref()
        .map_or(SegmentStart::GENESIS, |c| SegmentStart {
            seq: c.payload.seq,
            hash: &c.payload.head_hash,
        });
    if start.seq > head_seq {
        return Err(ExportError::Inconsistent(format!(
            "the checkpoint at record {} is newer than the chain, which ends at record \
             {head_seq}: records were removed",
            start.seq
        )));
    }

    let mut writer = BundleWriter::create(request.out, request.scope, start)?;
    let mut last = start.seq;
    while last < head_seq {
        let records = source.records(last, page).await?;
        if records.is_empty() {
            break;
        }
        for record in &records {
            writer.record(record)?;
            last = record.payload.seq;
        }
    }
    if last != head_seq {
        return Err(ExportError::Inconsistent(format!(
            "the chain head is record {head_seq} but the records end at record {last}"
        )));
    }

    let mut after = start.seq;
    loop {
        let outcomes = source.outcomes(after, head_seq, page).await?;
        let Some((seq, _)) = outcomes.last() else {
            break;
        };
        after = *seq;
        for (_, outcome) in &outcomes {
            writer.outcome(outcome)?;
        }
    }

    // From the checkpoint the segment follows (so its link to the chain is
    // in the bundle), or from the first checkpoint.
    let mut after = start.seq - 1;
    let mut last_checkpoint = None;
    loop {
        let checkpoints = source.checkpoints(after, page).await?;
        let Some(newest) = checkpoints.last() else {
            break;
        };
        after = newest.payload.seq;
        last_checkpoint = Some(after);
        for checkpoint in &checkpoints {
            writer.checkpoint(checkpoint)?;
        }
    }
    if last_checkpoint.is_some_and(|seq| seq > head_seq) {
        return Err(ExportError::Inconsistent(format!(
            "a checkpoint covers record {after} but the chain ends at record {head_seq}: \
             records were removed"
        )));
    }

    // Before anything is moved into place: the bundle must end exactly at
    // the stored head (for an empty segment, at the checkpoint it follows).
    if writer.head() != (head_seq, head_hash.as_str()) {
        return Err(ExportError::Inconsistent(
            "the last record's hash differs from the stored chain head".into(),
        ));
    }
    let manifest = writer.finish(request.exported_at, request.exporter, request.signer)?;
    Ok(ExportSummary {
        last_checkpoint,
        uncovered_records: head_seq - last_checkpoint.unwrap_or(start.seq),
        manifest,
    })
}

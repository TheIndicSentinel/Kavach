//! Verifies an evidence bundle offline (ADR-005 §13, the steps of
//! `docs/EVIDENCE_BUNDLE.md`), in one pass and in constant memory.
//!
//! The three files are read as streams and merged by `seq`: records in
//! order, the outcome of each record as it goes by, and each checkpoint
//! against the record it names. Nothing but the previous hash, the next
//! outcome and the next checkpoint is kept, so the size of a chain does not
//! matter.
//!
//! The result separates two things a reader must not confuse:
//! - a [`BundleFailure`]: the bundle does not verify;
//! - [`BundleReport::not_protected`]: it verifies, but something was not
//!   protected (unsigned, records no checkpoint covers, no kept checkpoint
//!   to compare with, allows with no outcome). A caller should treat these
//!   as a failure unless told otherwise.
//!
//! Keys come from the operator, never from the bundle. This module is pure:
//! the caller supplies the streams and compares each file with the digest
//! in the manifest.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::iter::Peekable;

use chrono::{DateTime, Utc};

use crate::agent_evidence::{
    check_record, is_dev_key, outcome_verifies, AgentDecisionRecord, ChainEntry, ChainError,
    DevKeys, Outcome, OutcomeRecord, GENESIS,
};
use crate::bundle::{
    verify_manifest, Manifest, ManifestError, ManifestSignature, Segment, CHECKPOINTS_FILE,
    OUTCOMES_FILE, RECORDS_FILE,
};
use crate::chain_record::ChainRecord;
use crate::checkpoint::{check_one, Checkpoint, CheckpointError, Scope};
use crate::keys::PublicKey;

/// At most this many ids or notes are kept per finding; the count is exact.
pub const SAMPLE: usize = 20;

/// Limits on what a trusted key may have signed (for a retired or
/// compromised key). A signature beyond them fails verification.
///
/// `valid_until_seq` is the strong limit: anything the key signed for a
/// record after that sequence number is refused, unless a checkpoint the
/// operator kept covers it. Take it from a checkpoint kept before the key
/// was compromised. Timestamps alone cannot stop forgery, because whoever
/// holds the key can backdate them; `not_before` and `not_after` retire a
/// key in time as well.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyValidity {
    pub valid_until_seq: Option<i64>,
    pub not_before: Option<DateTime<Utc>>,
    pub not_after: Option<DateTime<Utc>>,
}

impl KeyValidity {
    /// Why something signed by `kid` for record `seq` at `ts` is refused,
    /// if it is. `kept_seq` is the operator's kept checkpoint, which covers
    /// records up to it.
    fn refuses(
        &self,
        kid: &str,
        seq: i64,
        ts: DateTime<Utc>,
        kept_seq: Option<i64>,
    ) -> Option<String> {
        if let Some(limit) = self.valid_until_seq {
            if seq > limit && kept_seq.is_none_or(|kept| seq > kept) {
                return Some(format!(
                    "key {kid} signed for record {seq}, after its limit (record {limit}), and no \
                     kept checkpoint covers it"
                ));
            }
        }
        if self.not_before.is_some_and(|t| ts < t) || self.not_after.is_some_and(|t| ts >= t) {
            return Some(format!(
                "key {kid} signed at {ts}, outside its validity period"
            ));
        }
        None
    }
}

pub struct VerifyOptions<'a> {
    /// Trusted keys, from the operator.
    pub keys: &'a BTreeMap<String, PublicKey>,
    /// Limits per key id, from the operator; keys absent here are unlimited.
    pub validity: &'a BTreeMap<String, KeyValidity>,
    pub dev_keys: DevKeys,
    /// The reference time for "this allow's credential has expired".
    pub now: DateTime<Utc>,
    /// A checkpoint the operator kept out of band.
    pub kept: Option<&'a Checkpoint>,
}

/// A count, with the first few items.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tally {
    pub count: u64,
    pub first: Vec<String>,
}

impl Tally {
    fn add(&mut self, item: impl FnOnce() -> String) {
        self.count += 1;
        if self.first.len() < SAMPLE {
            self.first.push(item());
        }
    }
}

/// Why a bundle does not verify.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BundleFailure {
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    #[error("{file} line {line}: {reason}")]
    Read {
        file: &'static str,
        line: u64,
        reason: String,
    },
    #[error(transparent)]
    Record(#[from] ChainError),
    #[error("{RECORDS_FILE}: {0}")]
    Segment(String),
    #[error("{OUTCOMES_FILE} line {line}: {reason}")]
    Outcome { line: u64, reason: String },
    #[error(transparent)]
    Checkpoint(#[from] CheckpointError),
    #[error(
        "the segment claims to follow record {after_seq}, but no checkpoint (in the bundle or \
         kept by the operator) vouches for that record's hash"
    )]
    UnvouchedStart { after_seq: i64 },
    /// Signed by a trusted key beyond the limits the operator set for it.
    #[error("{what}: {reason}")]
    KeyNotValid { what: String, reason: String },
}

impl VerifyOptions<'_> {
    /// Fails when `kid`'s limits refuse what it signed for record `seq`.
    fn within_validity(
        &self,
        what: impl FnOnce() -> String,
        kid: &str,
        seq: i64,
        ts: DateTime<Utc>,
    ) -> Result<(), BundleFailure> {
        let kept_seq = self.kept.map(|kept| kept.payload.seq);
        match self
            .validity
            .get(kid)
            .and_then(|v| v.refuses(kid, seq, ts, kept_seq))
        {
            Some(reason) => Err(BundleFailure::KeyNotValid {
                what: what(),
                reason,
            }),
            None => Ok(()),
        }
    }
}

/// What was verified. See [`BundleReport::not_protected`] for what was not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleReport {
    pub signature: ManifestSignature,
    pub after_seq: i64,
    pub last_seq: i64,
    pub head_hash: String,
    pub records: u64,
    pub outcomes: u64,
    pub checkpoints: u64,
    /// `seq` of the newest checkpoint that covers a record of the bundle
    /// (or the record it follows).
    pub last_checkpoint: Option<i64>,
    /// Records newer than that checkpoint.
    pub uncovered_records: u64,
    /// `seq` of the kept checkpoint the chain was compared with.
    pub kept_checkpoint: Option<i64>,
    /// Allows past their credential's expiry with no outcome.
    pub outcome_missing: Tally,
    /// Outcomes recorded as `unknown` (sent, result not known).
    pub outcome_unknown: Tally,
    /// Checkpoints dated before the one preceding them.
    pub clock_notes: Tally,
}

/// One thing the bundle does not protect. `kind` is a fixed vocabulary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub kind: &'static str,
    pub detail: String,
}

fn sample(tally: &Tally) -> String {
    let more = tally.count.saturating_sub(tally.first.len() as u64);
    let mut text = tally.first.join(", ");
    if more > 0 {
        let _ = write!(text, " and {more} more");
    }
    text
}

impl BundleReport {
    /// What this bundle, though it verifies, does not protect. Empty only
    /// when it is signed, every record is covered by a checkpoint, it was
    /// compared with a kept checkpoint, and every allow has a final outcome.
    #[must_use]
    pub fn not_protected(&self) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut finding = |kind, detail: String| findings.push(Finding { kind, detail });
        if self.signature == ManifestSignature::Unsigned {
            finding(
                "unsigned",
                "the bundle is unsigned: nothing vouches for the set of outcomes, so a removed \
                 outcome would not be noticed"
                    .into(),
            );
        }
        if self.kept_checkpoint.is_none() {
            finding(
                "no_kept_checkpoint",
                "not compared with a kept checkpoint: a chain cut short or rewritten by someone \
                 holding the keys would not be noticed"
                    .into(),
            );
        }
        if self.uncovered_records > 0 {
            let since = match self.last_checkpoint {
                Some(seq) => format!("the last checkpoint is at record {seq}"),
                None => "there is no checkpoint".into(),
            };
            finding(
                "uncovered_records",
                format!(
                    "{} record(s) are not covered by any checkpoint ({since})",
                    self.uncovered_records
                ),
            );
        }
        if self.outcome_missing.count > 0 {
            finding(
                "outcome_missing",
                format!(
                    "{} allowed action(s) have no recorded outcome: {}",
                    self.outcome_missing.count,
                    sample(&self.outcome_missing)
                ),
            );
        }
        if self.outcome_unknown.count > 0 {
            finding(
                "outcome_unknown",
                format!(
                    "{} outcome(s) are recorded as unknown (sent, result not known): {}",
                    self.outcome_unknown.count,
                    sample(&self.outcome_unknown)
                ),
            );
        }
        if self.clock_notes.count > 0 {
            finding(
                "clock_stepped_back",
                format!(
                    "{} checkpoint(s) are dated before the one preceding them: {}",
                    self.clock_notes.count,
                    sample(&self.clock_notes)
                ),
            );
        }
        findings
    }
}

/// A stream of parsed lines; an `Err` is a line that could not be read.
pub trait Lines<T>: Iterator<Item = Result<T, String>> {}
impl<T, I: Iterator<Item = Result<T, String>>> Lines<T> for I {}

struct Numbered<I: Iterator> {
    inner: Peekable<I>,
    file: &'static str,
    line: u64,
}

impl<T, I: Iterator<Item = Result<T, String>>> Numbered<I> {
    fn new(inner: I, file: &'static str) -> Self {
        Self {
            inner: inner.peekable(),
            file,
            line: 0,
        }
    }

    fn read(&self, reason: &str) -> BundleFailure {
        BundleFailure::Read {
            file: self.file,
            line: self.line + 1,
            reason: reason.into(),
        }
    }

    fn peek(&mut self) -> Result<Option<&T>, BundleFailure> {
        // Copy the error out first: `peek` borrows the iterator.
        if let Some(Err(reason)) = self.inner.peek() {
            let reason = reason.clone();
            return Err(self.read(&reason));
        }
        Ok(self.inner.peek().and_then(|item| item.as_ref().ok()))
    }

    fn next(&mut self) -> Result<Option<T>, BundleFailure> {
        match self.inner.next() {
            None => Ok(None),
            Some(Err(reason)) => Err(self.read(&reason)),
            Some(Ok(item)) => {
                self.line += 1;
                Ok(Some(item))
            }
        }
    }
}

/// The checkpoints seen so far.
#[derive(Default)]
struct Checkpoints {
    count: u64,
    previous: Option<(i64, String, DateTime<Utc>)>,
    /// Newest checkpoint compared with a record (or the segment start).
    last_covering: Option<i64>,
    first: Option<(i64, bool)>,
    start_vouched: bool,
    kept_present: bool,
    clock_notes: Tally,
}

struct Run<'a, C: Iterator> {
    scope: Scope<'a>,
    after_seq: i64,
    opts: &'a VerifyOptions<'a>,
    checkpoints: Numbered<C>,
    seen: Checkpoints,
    /// Hash of the record the kept checkpoint names, once it goes by.
    kept_record_hash: Option<String>,
}

impl<C: Iterator<Item = Result<Checkpoint, String>>> Run<'_, C> {
    /// Takes every checkpoint up to record `seq` (whose hash is `hash`):
    /// each is verified and linked to the one before; the one at `seq` must
    /// name `hash`.
    fn checkpoints_through(&mut self, seq: i64, hash: &str) -> Result<(), BundleFailure> {
        if self.opts.kept.is_some_and(|kept| kept.payload.seq == seq) {
            self.kept_record_hash = Some(hash.into());
        }
        while self
            .checkpoints
            .peek()?
            .is_some_and(|next| next.payload.seq <= seq)
        {
            let Some(checkpoint) = self.checkpoints.next()? else {
                break;
            };
            self.link(&checkpoint)?;
            let p = &checkpoint.payload;
            if p.seq == seq {
                if p.head_hash != hash {
                    return Err(CheckpointError::Mismatch { seq }.into());
                }
                self.seen.last_covering = Some(seq);
                if seq == self.after_seq {
                    self.seen.start_vouched = true;
                }
            } else if p.seq > self.after_seq {
                // Its record has gone by without it: out of order.
                return Err(CheckpointError::Order {
                    seq: p.seq,
                    previous: seq,
                }
                .into());
            }
        }
        Ok(())
    }

    /// Signature, order and link of one checkpoint.
    fn link(&mut self, checkpoint: &Checkpoint) -> Result<(), BundleFailure> {
        check_one(checkpoint, self.scope, self.opts.keys, self.opts.dev_keys)?;
        let p = &checkpoint.payload;
        self.opts
            .within_validity(|| format!("checkpoint {}", p.seq), &p.key_id, p.seq, p.ts)?;
        if let Some((previous_seq, previous_hash, previous_ts)) = &self.seen.previous {
            if p.seq <= *previous_seq {
                return Err(CheckpointError::Order {
                    seq: p.seq,
                    previous: *previous_seq,
                }
                .into());
            }
            if p.prev_checkpoint_hash != *previous_hash {
                return Err(CheckpointError::Link { seq: p.seq }.into());
            }
            if p.ts < *previous_ts {
                let (seq, previous_seq) = (p.seq, *previous_seq);
                self.seen
                    .clock_notes
                    .add(|| format!("{seq} (after {previous_seq})"));
            }
        } else {
            let from_first = p.prev_checkpoint_hash == GENESIS;
            if self.after_seq == 0 && !from_first {
                return Err(CheckpointError::Link { seq: p.seq }.into());
            }
            self.seen.first = Some((p.seq, from_first));
        }
        if self
            .opts
            .kept
            .is_some_and(|kept| kept.hash == checkpoint.hash)
        {
            self.seen.kept_present = true;
        }
        self.seen.count += 1;
        self.seen.previous = Some((p.seq, checkpoint.hash.clone(), p.ts));
        Ok(())
    }

    /// The kept checkpoint against what went by.
    fn check_kept(&self, last_seq: i64) -> Result<Option<i64>, BundleFailure> {
        let Some(kept) = self.opts.kept else {
            return Ok(None);
        };
        let seq = kept.payload.seq;
        if seq < self.after_seq {
            return Err(CheckpointError::KeptBeforeSegment {
                seq,
                start_seq: self.after_seq,
            }
            .into());
        }
        match &self.kept_record_hash {
            // The chain ends before a checkpoint the operator kept.
            None => {
                return Err(CheckpointError::Ahead {
                    seq,
                    head_seq: last_seq,
                }
                .into())
            }
            Some(hash) if *hash != kept.payload.head_hash => {
                return Err(CheckpointError::Mismatch { seq }.into())
            }
            Some(_) => {}
        }
        let covered = self
            .seen
            .first
            .is_some_and(|(first_seq, from_first)| first_seq <= seq || from_first);
        if covered && !self.seen.kept_present {
            return Err(CheckpointError::KeptAbsent { seq }.into());
        }
        Ok(Some(seq))
    }

    /// After the last record: no checkpoint may be left over, the kept
    /// checkpoint must match, and a segment's start must be vouched for.
    fn finish(&mut self, segment: &Segment, last_seq: i64) -> Result<Option<i64>, BundleFailure> {
        // A checkpoint newer than the newest record: records were removed.
        if let Some(checkpoint) = self.checkpoints.next()? {
            check_one(&checkpoint, self.scope, self.opts.keys, self.opts.dev_keys)?;
            return Err(CheckpointError::Ahead {
                seq: checkpoint.payload.seq,
                head_seq: last_seq,
            }
            .into());
        }
        let kept_checkpoint = self.check_kept(last_seq)?;
        let kept_vouches = self.opts.kept.is_some_and(|kept| {
            kept.payload.seq == segment.after_seq && kept.payload.head_hash == segment.after_hash
        });
        if segment.after_seq > 0 && !self.seen.start_vouched && !kept_vouches {
            return Err(BundleFailure::UnvouchedStart {
                after_seq: segment.after_seq,
            });
        }
        Ok(kept_checkpoint)
    }
}

/// The outcome of `record`, if it is next in the outcomes stream.
fn take_outcome<O: Lines<OutcomeRecord>>(
    outcomes: &mut Numbered<O>,
    record: &AgentDecisionRecord,
    opts: &VerifyOptions<'_>,
) -> Result<Option<Outcome>, BundleFailure> {
    let Some(credential_id) = record.payload.credential_id.as_deref() else {
        return Ok(None);
    };
    if outcomes
        .peek()?
        .is_none_or(|next| next.credential_id != credential_id)
    {
        return Ok(None);
    }
    let Some(outcome) = outcomes.next()? else {
        return Ok(None);
    };
    let invalid = |reason: &str| BundleFailure::Outcome {
        line: outcomes.line,
        reason: format!("the outcome of {credential_id} {reason}"),
    };
    if outcome.tenant_id != record.payload.tenant_id || outcome.record_hash != record.hash {
        return Err(invalid("names another record"));
    }
    if opts.dev_keys == DevKeys::Refuse && is_dev_key(&outcome.key_id) {
        return Err(invalid("is signed with a development key"));
    }
    if !outcome_verifies(&outcome, opts.keys) {
        return Err(invalid("does not verify"));
    }
    opts.within_validity(
        || format!("the outcome of {credential_id}"),
        &outcome.key_id,
        record.payload.seq,
        outcome.ts,
    )?;
    Ok(Some(outcome.outcome))
}

/// One record of the bundle: of its chain, of a kind its format version
/// holds (version 1: decisions only), next in the chain after `previous`
/// (`seq`, hash), signed by a trusted key within that key's validity.
fn check_bundle_record(
    record: &ChainRecord,
    p: &crate::bundle::ManifestPayload,
    (last_seq, prev): (i64, &str),
    opts: &VerifyOptions<'_>,
) -> Result<(), BundleFailure> {
    let seq = record.seq();
    if record.tenant_id() != p.tenant_id || record.partition_id() != p.partition_id {
        return Err(BundleFailure::Segment(format!(
            "record {seq} is of another chain"
        )));
    }
    if p.version == 1 && record.as_decision().is_none() {
        return Err(BundleFailure::Segment(format!(
            "record {seq} is a {}; a version 1 bundle holds decisions only",
            record.kind()
        )));
    }
    let allow_dev_keys = opts.dev_keys == DevKeys::Accept;
    check_record(record, last_seq + 1, prev, opts.keys, allow_dev_keys)?;
    opts.within_validity(
        || format!("record {seq}"),
        record.key_id(),
        seq,
        record.ts(),
    )
}

/// Verifies a bundle from its manifest and its three streams.
///
/// - `outcomes` must be in the order of their records, and `checkpoints`
///   in `seq` order, as an export writes them.
/// - A segment that does not start at the first record must be vouched for
///   by a checkpoint at its start, in the bundle or kept by the operator.
/// - The caller compares each file's bytes with the manifest's digest and
///   count; this checks what the lines say.
pub fn verify_bundle<R, O, C>(
    manifest: &Manifest,
    records: R,
    outcomes: O,
    checkpoints: C,
    opts: &VerifyOptions<'_>,
) -> Result<BundleReport, BundleFailure>
where
    R: Lines<ChainRecord>,
    O: Lines<OutcomeRecord>,
    C: Lines<Checkpoint>,
{
    let signature = verify_manifest(manifest, opts.keys, opts.dev_keys)?;
    let p = &manifest.payload;
    if let Some(kid) = &p.key_id {
        // The export key vouches for the bundle up to its last record.
        opts.within_validity(
            || "the manifest".into(),
            kid,
            p.segment.last_seq,
            p.exported_at,
        )?;
    }
    let segment = &p.segment;
    let scope = Scope {
        tenant_id: &p.tenant_id,
        partition_id: p.partition_id,
        chain: &p.chain,
    };
    if let Some(kept) = opts.kept {
        check_one(kept, scope, opts.keys, opts.dev_keys)?;
    }
    let mut records = Numbered::new(records, RECORDS_FILE);
    let mut outcomes = Numbered::new(outcomes, OUTCOMES_FILE);
    let mut run = Run {
        scope,
        after_seq: segment.after_seq,
        opts,
        checkpoints: Numbered::new(checkpoints, CHECKPOINTS_FILE),
        seen: Checkpoints::default(),
        kept_record_hash: None,
    };

    let mut last_seq = segment.after_seq;
    let mut prev = segment.after_hash.clone();
    let (mut missing, mut unknown) = (Tally::default(), Tally::default());
    run.checkpoints_through(last_seq, &prev)?;
    while let Some(record) = records.next()? {
        let seq = record.seq();
        check_bundle_record(&record, p, (last_seq, &prev), opts)?;
        if let Some(decision) = record.as_decision() {
            let rp = &decision.payload;
            match take_outcome(&mut outcomes, decision, opts)? {
                Some(Outcome::Unknown) => {
                    unknown.add(|| rp.credential_id.clone().unwrap_or_default());
                }
                Some(_) => {}
                None => {
                    let expired = rp.credential_expires_at.is_none_or(|exp| exp <= opts.now);
                    if let (true, true, Some(id)) =
                        (decision.is_allow(), expired, &rp.credential_id)
                    {
                        missing.add(|| id.clone());
                    }
                }
            }
        }
        last_seq = seq;
        prev = record.hash().to_string();
        run.checkpoints_through(last_seq, &prev)?;
    }

    if last_seq != segment.last_seq || prev != segment.head_hash {
        return Err(BundleFailure::Segment(format!(
            "the records end at record {last_seq}, not at the manifest's record {} and head",
            segment.last_seq
        )));
    }
    let stray = outcomes
        .peek()?
        .map(|outcome| outcome.credential_id.clone());
    if let Some(credential_id) = stray {
        return Err(BundleFailure::Outcome {
            line: outcomes.line + 1,
            reason: format!(
                "the outcome of {credential_id} belongs to no record of this segment, in order"
            ),
        });
    }
    let kept_checkpoint = run.finish(segment, last_seq)?;

    let covered_through = run.seen.last_covering.unwrap_or(segment.after_seq);
    Ok(BundleReport {
        signature,
        after_seq: segment.after_seq,
        last_seq,
        head_hash: prev,
        records: records.line,
        outcomes: outcomes.line,
        checkpoints: run.seen.count,
        last_checkpoint: run.seen.last_covering,
        uncovered_records: u64::try_from(last_seq - covered_through).unwrap_or(0),
        kept_checkpoint,
        outcome_missing: missing,
        outcome_unknown: unknown,
        clock_notes: run.seen.clock_notes,
    })
}

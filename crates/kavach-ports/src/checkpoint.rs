//! Signed evidence checkpoints, format v1 (ADR-005 §5 and §13).
//!
//! A checkpoint is a signed statement that a chain's record `seq` has hash
//! `head_hash`. Checkpoints link to each other through
//! `prev_checkpoint_hash`, and are signed with a dedicated checkpoint key
//! (not the evidence key) over a domain-separated message.
//!
//! **What a checkpoint is worth.** It is written by the same deployment that
//! writes the records, so on its own it proves nothing against someone who
//! holds both the database and the keys. It becomes useful once a copy has
//! left the system: a verifier given a checkpoint the operator kept detects
//! a chain that was cut short or rewritten below it.
//!
//! This module is pure: no I/O, no clock. Writing checkpoints on a schedule
//! and exporting them are separate.

use std::collections::BTreeMap;
use std::future::Future;

use chrono::{DateTime, DurationRound, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::agent_evidence::{
    is_dev_key, AgentDecisionRecord, DevKeys, EvidenceSigner, SegmentStart, TimeSync, GENESIS,
};
use crate::error::PortError;
use crate::keys::{verify_ed25519, PublicKey};

pub const KIND_CHECKPOINT: &str = "evidence_checkpoint";
/// Format version; a verifier refuses versions it does not know.
pub const CHECKPOINT_VERSION: u32 = 1;
/// The chain of Agent Decision Records (`agent_decisions`).
pub const CHAIN_AGENT_DECISIONS: &str = "agent_decisions";
pub const CHECKPOINT_HASH_PREFIX: &[u8] = b"kavach-evidence-checkpoint-v1";
pub const CHECKPOINT_SIG_PREFIX: &[u8] = b"kavach-evidence-checkpoint-v1:";

/// The hashed and signed content of a checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointPayload {
    pub kind: String,
    pub version: u32,
    pub tenant_id: String,
    pub partition_id: i32,
    /// Which chain of the partition this covers.
    pub chain: String,
    /// The newest record covered, and its hash.
    pub seq: i64,
    pub head_hash: String,
    /// Hash of the previous checkpoint of this chain; all zeros for the first.
    pub prev_checkpoint_hash: String,
    /// The checkpoint key; inside the payload so a signature cannot be
    /// paired with another key id.
    pub key_id: String,
    pub time_sync: TimeSync,
    /// Trusted time, to the microsecond.
    pub ts: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    #[serde(flatten)]
    pub payload: CheckpointPayload,
    pub hash: String,
    pub sig: String,
}

/// The chain a set of checkpoints belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scope<'a> {
    pub tenant_id: &'a str,
    pub partition_id: i32,
    pub chain: &'a str,
}

/// The head a checkpoint is taken at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Head<'a> {
    pub scope: Scope<'a>,
    pub seq: i64,
    pub hash: &'a str,
}

fn is_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// RFC 8785 (JCS) bytes of a payload: what is hashed.
pub fn canonical_payload(payload: &CheckpointPayload) -> Result<Vec<u8>, PortError> {
    crate::jcs::to_vec(payload)
}

/// SHA-256 over the hash prefix and the canonical payload, as lowercase hex.
pub fn checkpoint_hash(payload: &CheckpointPayload) -> Result<String, PortError> {
    let mut hasher = Sha256::new();
    hasher.update(CHECKPOINT_HASH_PREFIX);
    hasher.update(canonical_payload(payload)?);
    Ok(format!("{:x}", hasher.finalize()))
}

#[must_use]
pub fn checkpoint_signing_message(hash: &str) -> Vec<u8> {
    let mut message = CHECKPOINT_SIG_PREFIX.to_vec();
    message.extend_from_slice(hash.as_bytes());
    message
}

/// Builds and signs the checkpoint for `head`, following `previous`.
///
/// `signer` must hold the checkpoint key, which signs nothing else. The
/// caller supplies trusted time; a checkpoint is never signed with a guess.
pub fn sign_checkpoint(
    head: Head<'_>,
    previous: Option<&Checkpoint>,
    ts: DateTime<Utc>,
    time_sync: TimeSync,
    signer: &dyn EvidenceSigner,
) -> Result<Checkpoint, PortError> {
    if head.seq < 1 || !is_hash(head.hash) {
        return Err(PortError::invalid(
            "a checkpoint needs a head: seq >= 1 and a 64-hex hash",
        ));
    }
    if let Some(previous) = previous {
        let p = &previous.payload;
        if p.tenant_id != head.scope.tenant_id
            || p.partition_id != head.scope.partition_id
            || p.chain != head.scope.chain
        {
            return Err(PortError::invalid(
                "the previous checkpoint is of another chain",
            ));
        }
        if p.seq >= head.seq {
            return Err(PortError::invalid(format!(
                "checkpoint seq {} does not advance past {}",
                head.seq, p.seq
            )));
        }
    }
    let ts = ts
        .duration_trunc(TimeDelta::microseconds(1))
        .map_err(|e| PortError::invalid(format!("checkpoint time: {e}")))?;
    let payload = CheckpointPayload {
        kind: KIND_CHECKPOINT.into(),
        version: CHECKPOINT_VERSION,
        tenant_id: head.scope.tenant_id.into(),
        partition_id: head.scope.partition_id,
        chain: head.scope.chain.into(),
        seq: head.seq,
        head_hash: head.hash.into(),
        prev_checkpoint_hash: previous.map_or_else(|| GENESIS.into(), |p| p.hash.clone()),
        key_id: signer.key_id().into(),
        time_sync,
        ts,
    };
    let hash = checkpoint_hash(&payload)?;
    let sig = hex::encode(signer.sign(&checkpoint_signing_message(&hash))?);
    Ok(Checkpoint { payload, hash, sig })
}

/// What became of an [`CheckpointStore::append`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Appended {
    Written,
    /// Another writer checkpointed this chain first. Nothing was stored;
    /// read the latest checkpoint again before the next attempt.
    Superseded,
}

/// Checkpoint persistence (ADR-005 §13). Append-only.
///
/// The stored checkpoints of a chain form **one line**: each links to the
/// one before it and at most one checkpoint follows any other, also when
/// several writers run. A store does not verify signatures (it holds no
/// keys); it refuses what it can check.
pub trait CheckpointStore: Send + Sync {
    /// The newest record of the chain (`seq`, hash); `None` while it has
    /// none. Read without taking the commit lock.
    fn head(
        &self,
        scope: Scope<'_>,
    ) -> impl Future<Output = Result<Option<(i64, String)>, PortError>> + Send;

    /// The newest checkpoint of the chain.
    fn latest(
        &self,
        scope: Scope<'_>,
    ) -> impl Future<Output = Result<Option<Checkpoint>, PortError>> + Send;

    /// Stores a checkpoint.
    /// - `Rejected` when its hash does not match its content, when the
    ///   record at its `seq` does not have its `head_hash`, or when it does
    ///   not advance past the latest checkpoint.
    /// - [`Appended::Superseded`] when it does not follow the latest
    ///   checkpoint because another writer got there first.
    fn append(
        &self,
        checkpoint: &Checkpoint,
    ) -> impl Future<Output = Result<Appended, PortError>> + Send;

    /// Checkpoints with `seq > after_seq`, oldest first, at most `limit`.
    fn list(
        &self,
        scope: Scope<'_>,
        after_seq: i64,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<Checkpoint>, PortError>> + Send;
}

/// What a store checks before it writes: the checkpoint is well formed, of
/// a chain the store holds, and hashes to its content.
pub fn check_storable(checkpoint: &Checkpoint) -> Result<(), PortError> {
    let p = &checkpoint.payload;
    if p.kind != KIND_CHECKPOINT || p.version != CHECKPOINT_VERSION {
        return Err(PortError::rejected("not a version 1 evidence checkpoint"));
    }
    if p.chain != CHAIN_AGENT_DECISIONS {
        return Err(PortError::rejected(format!("unknown chain {}", p.chain)));
    }
    if p.seq < 1 || !is_hash(&p.head_hash) || !is_hash(&p.prev_checkpoint_hash) {
        return Err(PortError::rejected(
            "checkpoint seq must be >= 1 and hashes 64 lowercase hex",
        ));
    }
    if checkpoint_hash(p)? != checkpoint.hash {
        return Err(PortError::rejected(
            "checkpoint hash does not match its content",
        ));
    }
    Ok(())
}

/// Where a storable checkpoint stands against the latest stored one.
/// `Ok(Appended::Written)` means it may be written.
pub fn check_follows(
    checkpoint: &Checkpoint,
    latest: Option<&Checkpoint>,
) -> Result<Appended, PortError> {
    let expected_prev = latest.map_or(GENESIS, |c| c.hash.as_str());
    if checkpoint.payload.prev_checkpoint_hash != expected_prev {
        return Ok(Appended::Superseded);
    }
    if latest.is_some_and(|c| checkpoint.payload.seq <= c.payload.seq) {
        return Err(PortError::rejected(
            "checkpoint does not advance past the latest checkpoint",
        ));
    }
    Ok(Appended::Written)
}

/// The record hashes a set of checkpoints is checked against: a contiguous
/// run that follows `start` (already verified by `verify_segment`).
#[derive(Debug, Clone)]
pub struct ChainSegment<'a> {
    start: SegmentStart<'a>,
    hashes: Vec<&'a str>,
}

enum Lookup<'a> {
    /// Older than the segment: cannot be checked here.
    Before,
    At(&'a str),
    /// Newer than the newest record present.
    Ahead,
}

impl<'a> ChainSegment<'a> {
    /// `hashes[i]` is the hash of record `start.seq + 1 + i`.
    #[must_use]
    pub fn new(start: SegmentStart<'a>, hashes: Vec<&'a str>) -> Self {
        Self { start, hashes }
    }

    #[must_use]
    pub fn of_records(start: SegmentStart<'a>, records: &'a [AgentDecisionRecord]) -> Self {
        Self::new(start, records.iter().map(|r| r.hash.as_str()).collect())
    }

    #[must_use]
    pub fn head_seq(&self) -> i64 {
        self.start
            .seq
            .saturating_add(i64::try_from(self.hashes.len()).unwrap_or(i64::MAX))
    }

    fn at(&self, seq: i64) -> Lookup<'a> {
        if seq < self.start.seq {
            return Lookup::Before;
        }
        if seq == self.start.seq {
            return Lookup::At(self.start.hash);
        }
        usize::try_from(seq - self.start.seq - 1)
            .ok()
            .and_then(|index| self.hashes.get(index))
            .copied()
            .map_or(Lookup::Ahead, Lookup::At)
    }

    fn records_after(&self, seq: i64) -> usize {
        usize::try_from(self.head_seq().saturating_sub(seq.max(self.start.seq))).unwrap_or(0)
    }
}

/// Problems found by [`verify_checkpoints`] and [`check_kept`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CheckpointError {
    #[error("checkpoint {seq}: {reason}")]
    Format { seq: i64, reason: String },
    #[error("checkpoint {seq}: it belongs to another tenant, partition or chain")]
    Scope { seq: i64 },
    #[error(
        "checkpoint {seq}: signed with development key {key_id}; dev-signed checkpoints are \
         accepted only when verifying a development stack"
    )]
    DevKey { seq: i64, key_id: String },
    #[error("checkpoint {seq}: hash does not match its content")]
    Hash { seq: i64 },
    #[error("checkpoint {seq}: signature invalid ({reason})")]
    Signature { seq: i64, reason: String },
    #[error("checkpoint {seq}: does not advance past checkpoint {previous}")]
    Order { seq: i64, previous: i64 },
    #[error("checkpoint {seq}: does not link to the checkpoint before it")]
    Link { seq: i64 },
    #[error("checkpoint {seq}: record {seq} has a different hash; the chain was rewritten")]
    Mismatch { seq: i64 },
    #[error(
        "checkpoint {seq}: the chain ends at record {head_seq}; records after it were removed"
    )]
    Ahead { seq: i64, head_seq: i64 },
    #[error(
        "kept checkpoint {seq}: it is older than this segment (which starts after record \
         {start_seq}) and cannot be checked against it"
    )]
    KeptBeforeSegment { seq: i64, start_seq: i64 },
    #[error(
        "kept checkpoint {seq}: the checkpoints supplied cover that point but do not include \
         it; checkpoint history was rewritten"
    )]
    KeptAbsent { seq: i64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointReport {
    pub checkpoints: usize,
    /// The newest checkpoint: its `seq` and its own hash.
    pub last: Option<(i64, String)>,
    /// Records newer than the newest checkpoint (all of them when there is
    /// none): not yet covered by any checkpoint.
    pub records_after_last: usize,
    /// Checkpoints older than the segment: signature and links checked, but
    /// not compared with a record.
    pub before_segment: usize,
    /// Whether the first checkpoint supplied is the first of the chain.
    pub from_first: bool,
    /// Things worth a look that are not integrity failures.
    pub warnings: Vec<String>,
}

/// Format, scope, key, hash and signature of one checkpoint.
pub fn check_one(
    checkpoint: &Checkpoint,
    scope: Scope<'_>,
    keys: &BTreeMap<String, PublicKey>,
    dev_keys: DevKeys,
) -> Result<(), CheckpointError> {
    let p = &checkpoint.payload;
    let seq = p.seq;
    let format = |reason: &str| CheckpointError::Format {
        seq,
        reason: reason.into(),
    };
    if p.kind != KIND_CHECKPOINT {
        return Err(format("not an evidence checkpoint"));
    }
    if p.version != CHECKPOINT_VERSION {
        return Err(format("unknown checkpoint version"));
    }
    if seq < 1 || !is_hash(&p.head_hash) || !is_hash(&p.prev_checkpoint_hash) {
        return Err(format("seq must be >= 1 and hashes 64 lowercase hex"));
    }
    if p.tenant_id != scope.tenant_id
        || p.partition_id != scope.partition_id
        || p.chain != scope.chain
    {
        return Err(CheckpointError::Scope { seq });
    }
    if dev_keys == DevKeys::Refuse && is_dev_key(&p.key_id) {
        return Err(CheckpointError::DevKey {
            seq,
            key_id: p.key_id.clone(),
        });
    }
    if checkpoint_hash(p).ok().as_deref() != Some(checkpoint.hash.as_str()) {
        return Err(CheckpointError::Hash { seq });
    }
    let signature = |reason: String| CheckpointError::Signature { seq, reason };
    let key = keys
        .get(&p.key_id)
        .ok_or_else(|| signature(format!("unknown key {}", p.key_id)))?;
    let sig = hex::decode(&checkpoint.sig).map_err(|_| signature("not hex".into()))?;
    verify_ed25519(key, &checkpoint_signing_message(&checkpoint.hash), &sig)
        .map_err(|e| signature(e.to_string()))
}

fn check_against_chain(
    checkpoint: &Checkpoint,
    segment: &ChainSegment<'_>,
) -> Result<bool, CheckpointError> {
    let seq = checkpoint.payload.seq;
    match segment.at(seq) {
        Lookup::Before => Ok(false),
        Lookup::At(hash) if hash == checkpoint.payload.head_hash => Ok(true),
        Lookup::At(_) => Err(CheckpointError::Mismatch { seq }),
        Lookup::Ahead => Err(CheckpointError::Ahead {
            seq,
            head_seq: segment.head_seq(),
        }),
    }
}

/// Verifies checkpoints (in `seq` order) offline against `segment`:
/// format, scope, signatures against `keys`, the links between them, and
/// that each one matches the record at its `seq`.
///
/// `keys` must come from the operator, never from the material being
/// verified. A checkpoint newer than the newest record means records were
/// removed. When the segment starts at the first record, the first
/// checkpoint must be the first of the chain.
pub fn verify_checkpoints(
    checkpoints: &[Checkpoint],
    scope: Scope<'_>,
    segment: &ChainSegment<'_>,
    keys: &BTreeMap<String, PublicKey>,
    dev_keys: DevKeys,
) -> Result<CheckpointReport, CheckpointError> {
    let mut before_segment = 0;
    let mut warnings = Vec::new();
    let mut previous: Option<&Checkpoint> = None;
    for checkpoint in checkpoints {
        check_one(checkpoint, scope, keys, dev_keys)?;
        let p = &checkpoint.payload;
        match previous {
            Some(before) => {
                if p.seq <= before.payload.seq {
                    return Err(CheckpointError::Order {
                        seq: p.seq,
                        previous: before.payload.seq,
                    });
                }
                if p.prev_checkpoint_hash != before.hash {
                    return Err(CheckpointError::Link { seq: p.seq });
                }
                if p.ts < before.payload.ts {
                    warnings.push(format!(
                        "checkpoint {} is dated before checkpoint {}",
                        p.seq, before.payload.seq
                    ));
                }
            }
            None => {
                if segment.start.seq == 0 && p.prev_checkpoint_hash != GENESIS {
                    return Err(CheckpointError::Link { seq: p.seq });
                }
            }
        }
        if !check_against_chain(checkpoint, segment)? {
            before_segment += 1;
        }
        previous = Some(checkpoint);
    }
    let from_first = checkpoints
        .first()
        .is_some_and(|c| c.payload.prev_checkpoint_hash == GENESIS);
    let last = previous.map(|c| (c.payload.seq, c.hash.clone()));
    let records_after_last = segment.records_after(last.as_ref().map_or(0, |(seq, _)| *seq));
    Ok(CheckpointReport {
        checkpoints: checkpoints.len(),
        last,
        records_after_last,
        before_segment,
        from_first,
        warnings,
    })
}

/// Checks the chain against a checkpoint the operator kept out of band:
/// the one check that detects a chain cut short or rewritten by someone who
/// also holds the keys.
///
/// The kept checkpoint must verify, the record at its `seq` must have its
/// hash, and when `checkpoints` (already verified) covers its `seq` it must
/// be among them.
pub fn check_kept(
    kept: &Checkpoint,
    scope: Scope<'_>,
    checkpoints: &[Checkpoint],
    segment: &ChainSegment<'_>,
    keys: &BTreeMap<String, PublicKey>,
    dev_keys: DevKeys,
) -> Result<(), CheckpointError> {
    check_one(kept, scope, keys, dev_keys)?;
    let seq = kept.payload.seq;
    if !check_against_chain(kept, segment)? {
        return Err(CheckpointError::KeptBeforeSegment {
            seq,
            start_seq: segment.start.seq,
        });
    }
    let covered = checkpoints.first().is_some_and(|first| {
        first.payload.seq <= seq || first.payload.prev_checkpoint_hash == GENESIS
    });
    if covered && !checkpoints.iter().any(|c| c.hash == kept.hash) {
        return Err(CheckpointError::KeptAbsent { seq });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyAlgorithm;
    use ed25519_dalek::{Signer, SigningKey};

    struct Key(&'static str, SigningKey);

    impl EvidenceSigner for Key {
        fn key_id(&self) -> &str {
            self.0
        }
        fn sign(&self, message: &[u8]) -> Result<Vec<u8>, PortError> {
            Ok(self.1.sign(message).to_bytes().to_vec())
        }
    }

    const SCOPE: Scope<'static> = Scope {
        tenant_id: "t",
        partition_id: 0,
        chain: CHAIN_AGENT_DECISIONS,
    };

    fn key() -> Key {
        Key("checkpoint-1", SigningKey::from_bytes(&[7u8; 32]))
    }

    fn keys(key: &Key) -> BTreeMap<String, PublicKey> {
        BTreeMap::from([(
            key.0.to_string(),
            PublicKey {
                kid: key.0.into(),
                algorithm: KeyAlgorithm::Ed25519,
                bytes: key.1.verifying_key().to_bytes(),
            },
        )])
    }

    /// Stand-ins for record hashes 1..=n.
    fn hashes(n: u8) -> Vec<String> {
        (1..=n).map(|i| format!("{i:02x}").repeat(32)).collect()
    }

    fn at(seconds: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_790_000_000 + seconds, 0).unwrap()
    }

    fn sync() -> TimeSync {
        TimeSync {
            status: "synced".into(),
            max_error_ms: Some(20),
        }
    }

    fn sign(chain: &[String], seq: usize, previous: Option<&Checkpoint>, key: &Key) -> Checkpoint {
        let head = Head {
            scope: SCOPE,
            seq: i64::try_from(seq).unwrap(),
            hash: &chain[seq - 1],
        };
        sign_checkpoint(head, previous, at(i64::try_from(seq).unwrap()), sync(), key).unwrap()
    }

    fn segment(chain: &[String]) -> ChainSegment<'_> {
        ChainSegment::new(
            SegmentStart::GENESIS,
            chain.iter().map(String::as_str).collect(),
        )
    }

    fn verify(
        checkpoints: &[Checkpoint],
        segment: &ChainSegment<'_>,
        key: &Key,
    ) -> Result<CheckpointReport, CheckpointError> {
        verify_checkpoints(checkpoints, SCOPE, segment, &keys(key), DevKeys::Refuse)
    }

    #[test]
    fn checkpoints_verify_against_the_chain_and_report_the_uncovered_tail() {
        let key = key();
        let chain = hashes(9);
        let first = sign(&chain, 3, None, &key);
        let second = sign(&chain, 7, Some(&first), &key);
        assert_eq!(first.payload.prev_checkpoint_hash, GENESIS);
        assert_eq!(second.payload.prev_checkpoint_hash, first.hash);

        let report = verify(&[first.clone(), second.clone()], &segment(&chain), &key).unwrap();
        assert_eq!(report.checkpoints, 2);
        assert_eq!(report.last, Some((7, second.hash.clone())));
        assert_eq!(report.records_after_last, 2);
        assert_eq!(report.before_segment, 0);
        assert!(report.from_first);
        assert!(report.warnings.is_empty());

        // No checkpoints at all: every record is uncovered, and that is said.
        let none = verify(&[], &segment(&chain), &key).unwrap();
        assert_eq!((none.checkpoints, none.records_after_last), (0, 9));
        assert_eq!(none.last, None);

        // A checkpoint round-trips through JSON (one line of a bundle).
        let line = serde_json::to_string(&second).unwrap();
        assert_eq!(serde_json::from_str::<Checkpoint>(&line).unwrap(), second);
    }

    #[test]
    fn a_cut_or_rewritten_chain_fails_against_its_checkpoints() {
        let key = key();
        let chain = hashes(9);
        let first = sign(&chain, 3, None, &key);
        let second = sign(&chain, 7, Some(&first), &key);
        let both = [first.clone(), second.clone()];

        // Records 6..9 removed: the chain now ends before checkpoint 7.
        assert_eq!(
            verify(&both, &segment(&chain[..5]), &key),
            Err(CheckpointError::Ahead {
                seq: 7,
                head_seq: 5
            })
        );
        // Record 7 replaced.
        let mut rewritten = chain.clone();
        rewritten[6] = "ee".repeat(32);
        assert_eq!(
            verify(&both, &segment(&rewritten), &key),
            Err(CheckpointError::Mismatch { seq: 7 })
        );
    }

    #[test]
    fn tampered_checkpoints_are_refused() {
        let key = key();
        let chain = hashes(9);
        let first = sign(&chain, 3, None, &key);
        let second = sign(&chain, 7, Some(&first), &key);
        let segment = segment(&chain);
        let check = |checkpoints: &[Checkpoint]| verify(checkpoints, &segment, &key);

        // Edited content.
        let mut edited = second.clone();
        edited.payload.seq = 8;
        assert_eq!(
            check(&[first.clone(), edited]),
            Err(CheckpointError::Hash { seq: 8 })
        );

        // Re-signed by someone without the checkpoint key, under its key id.
        let impostor = Key("checkpoint-1", SigningKey::from_bytes(&[8u8; 32]));
        let forged = sign(&chain, 7, Some(&first), &impostor);
        assert!(matches!(
            check(&[first.clone(), forged]),
            Err(CheckpointError::Signature { seq: 7, .. })
        ));
        // A key the operator did not supply.
        let other = Key("checkpoint-2", SigningKey::from_bytes(&[8u8; 32]));
        assert!(matches!(
            check(&[sign(&chain, 3, None, &other)]),
            Err(CheckpointError::Signature { seq: 3, .. })
        ));
        // A record signature is not a checkpoint signature (domain separation).
        let mut cross = first.clone();
        cross.sig = hex::encode(
            key.sign(&crate::agent_evidence::signing_message(&first.hash))
                .unwrap(),
        );
        assert!(matches!(
            check(&[cross]),
            Err(CheckpointError::Signature { seq: 3, .. })
        ));

        // A checkpoint dropped from the middle, or out of order.
        let third = sign(&chain, 9, Some(&second), &key);
        assert_eq!(
            check(&[first.clone(), third.clone()]),
            Err(CheckpointError::Link { seq: 9 })
        );
        assert_eq!(
            check(&[second.clone(), first.clone()]),
            Err(CheckpointError::Link { seq: 7 })
        );
        assert_eq!(
            check(&[first.clone(), second.clone(), second.clone()]),
            Err(CheckpointError::Order {
                seq: 7,
                previous: 7
            })
        );
        // The first checkpoint dropped from a chain exported from its start.
        assert_eq!(
            check(&[second.clone(), third]),
            Err(CheckpointError::Link { seq: 7 })
        );

        // Another tenant's, an unknown version, a malformed hash.
        let elsewhere = Scope {
            tenant_id: "other",
            ..SCOPE
        };
        assert_eq!(
            verify_checkpoints(
                std::slice::from_ref(&first),
                elsewhere,
                &segment,
                &keys(&key),
                DevKeys::Refuse
            ),
            Err(CheckpointError::Scope { seq: 3 })
        );
        let mut future = first.clone();
        future.payload.version = 2;
        assert!(matches!(
            check(&[future]),
            Err(CheckpointError::Format { seq: 3, .. })
        ));
        let mut upper = first;
        upper.payload.head_hash = upper.payload.head_hash.to_uppercase().replace('0', "A");
        assert!(matches!(
            check(&[upper]),
            Err(CheckpointError::Format { seq: 3, .. })
        ));
    }

    #[test]
    fn a_kept_checkpoint_detects_truncation_and_rewrites_the_writer_could_hide() {
        let key = key();
        let chain = hashes(9);
        let first = sign(&chain, 3, None, &key);
        let second = sign(&chain, 7, Some(&first), &key);
        let kept = second.clone();
        let check = |checkpoints: &[Checkpoint], chain: &[String]| {
            let segment = segment(chain);
            verify(checkpoints, &segment, &key)?;
            check_kept(
                &kept,
                SCOPE,
                checkpoints,
                &segment,
                &keys(&key),
                DevKeys::Refuse,
            )
        };

        assert_eq!(check(&[first.clone(), second.clone()], &chain), Ok(()));

        // The writer cuts the chain to 5 records and drops checkpoint 7:
        // what remains is self-consistent, and only the kept copy shows it.
        assert_eq!(
            check(std::slice::from_ref(&first), &chain[..5]),
            Err(CheckpointError::Ahead {
                seq: 7,
                head_seq: 5
            })
        );
        // The writer rewrites records 5..9 and re-signs a new checkpoint 7.
        let mut rewritten = chain.clone();
        for hash in &mut rewritten[4..] {
            *hash = "ee".repeat(32);
        }
        let resigned = sign(&rewritten, 7, Some(&first), &key);
        assert_eq!(
            check(&[first.clone(), resigned], &rewritten),
            Err(CheckpointError::Mismatch { seq: 7 })
        );
        // Records intact, but the checkpoint history was replaced.
        let replaced = sign(&chain, 8, Some(&first), &key);
        assert_eq!(
            check(&[first.clone(), replaced], &chain),
            Err(CheckpointError::KeptAbsent { seq: 7 })
        );
        // A kept checkpoint that does not itself verify proves nothing.
        let mut edited = kept.clone();
        edited.payload.head_hash = "ee".repeat(32);
        assert_eq!(
            check_kept(
                &edited,
                SCOPE,
                &[first, second],
                &segment(&chain),
                &keys(&key),
                DevKeys::Refuse
            ),
            Err(CheckpointError::Hash { seq: 7 })
        );
    }

    #[test]
    fn a_segment_is_checked_from_the_checkpoint_it_follows() {
        let key = key();
        let chain = hashes(9);
        let first = sign(&chain, 3, None, &key);
        let second = sign(&chain, 7, Some(&first), &key);
        let third = sign(&chain, 9, Some(&second), &key);
        // Records 8 and 9, following checkpoint 7.
        let segment = ChainSegment::new(
            SegmentStart {
                seq: 7,
                hash: &chain[6],
            },
            chain[7..].iter().map(String::as_str).collect(),
        );

        let report = verify(&[second.clone(), third.clone()], &segment, &key).unwrap();
        assert_eq!(report.last.as_ref().map(|l| l.0), Some(9));
        assert_eq!(report.records_after_last, 0);
        assert!(!report.from_first);
        // Older checkpoints may ride along; they are counted, not compared.
        let all = [first.clone(), second.clone(), third.clone()];
        let report = verify(&all, &segment, &key).unwrap();
        assert_eq!(report.before_segment, 1);
        assert!(report.from_first);

        // A segment that claims to follow a different record 7.
        let wrong = "ee".repeat(32);
        let moved = ChainSegment::new(
            SegmentStart {
                seq: 7,
                hash: &wrong,
            },
            chain[7..].iter().map(String::as_str).collect(),
        );
        assert_eq!(
            verify(&[second.clone(), third.clone()], &moved, &key),
            Err(CheckpointError::Mismatch { seq: 7 })
        );

        // A kept checkpoint older than the segment cannot be checked here.
        assert_eq!(
            check_kept(&first, SCOPE, &all, &segment, &keys(&key), DevKeys::Refuse),
            Err(CheckpointError::KeptBeforeSegment {
                seq: 3,
                start_seq: 7
            })
        );
        assert_eq!(
            check_kept(&third, SCOPE, &all, &segment, &keys(&key), DevKeys::Refuse),
            Ok(())
        );
    }

    #[test]
    fn dev_keys_and_bad_heads_are_refused_and_time_is_microseconds() {
        let chain = hashes(4);
        let dev = Key("dev-checkpoint-1", SigningKey::from_bytes(&[9u8; 32]));
        let signed = sign(&chain, 2, None, &dev);
        let segment = segment(&chain);
        assert_eq!(
            verify(std::slice::from_ref(&signed), &segment, &dev),
            Err(CheckpointError::DevKey {
                seq: 2,
                key_id: "dev-checkpoint-1".into()
            })
        );
        verify_checkpoints(
            std::slice::from_ref(&signed),
            SCOPE,
            &segment,
            &keys(&dev),
            DevKeys::Accept,
        )
        .unwrap();

        let key = key();
        let head = |seq, hash| Head {
            scope: SCOPE,
            seq,
            hash,
        };
        let now = at(0) + TimeDelta::nanoseconds(1_234_567);
        // Nothing to checkpoint, a malformed hash, and a head that goes back.
        assert!(sign_checkpoint(head(0, GENESIS), None, now, sync(), &key).is_err());
        assert!(sign_checkpoint(head(1, "abc"), None, now, sync(), &key).is_err());
        let second = sign(&chain, 2, None, &key);
        assert!(sign_checkpoint(head(2, &chain[1]), Some(&second), now, sync(), &key).is_err());
        let other = Head {
            scope: Scope {
                partition_id: 1,
                ..SCOPE
            },
            seq: 3,
            hash: &chain[2],
        };
        assert!(sign_checkpoint(other, Some(&second), now, sync(), &key).is_err());

        let third = sign_checkpoint(head(3, &chain[2]), Some(&second), now, sync(), &key).unwrap();
        assert_eq!(third.payload.ts, at(0) + TimeDelta::microseconds(1234));
        // A clock that stepped back is a warning, not an integrity failure.
        let report = verify(&[second, third], &segment, &key).unwrap();
        assert_eq!(report.warnings.len(), 1, "{:?}", report.warnings);
    }
}

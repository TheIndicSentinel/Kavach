//! Agent Decision Record v1 and its chain (ADR-005 §4, H5a-3b).
//!
//! Records chain per `(tenant, partition)` in their own table, not linked to
//! the v1 `decision_events` chain (that merge is M2). Each record is hashed
//! (`v2`: SHA-256 over `kavach-evidence-v2` ‖ `prev_hash` ‖ RFC 8785 JCS of
//! the payload) and signed individually with a dedicated evidence key over a
//! domain-separated message. The subject is a keyed pseudonym, never the raw
//! reference (an ADR-005 §7 deviation until per-subject crypto-shredding).

use std::collections::BTreeMap;
use std::future::Future;

use chrono::{DateTime, NaiveDate, Utc};
use kavach_domain::Decision;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::PortError;
use crate::keys::{verify_ed25519, PublicKey};
use crate::time::{SyncStatus, TimeSource};

pub const KIND_AGENT_DECISION: &str = "agent_decision";
pub const HASH_ALG_V2: &str = "v2";
pub const HASH_PREFIX: &[u8] = b"kavach-evidence-v2";
pub const SIG_PREFIX: &[u8] = b"kavach-agent-evidence-sig-v1:";
pub const OUTCOME_SIG_PREFIX: &[u8] = b"kavach-agent-outcome-sig-v1:";
/// v2 adds the reason code (H5b); v1 rows (no reason) still verify.
pub const OUTCOME_SIG_PREFIX_V2: &[u8] = b"kavach-agent-outcome-sig-v2:";
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Who acted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Actor {
    pub agent_id: String,
    /// Source-qualified identity (e.g. `oidc:<iss>#<sub>`).
    pub identity_key: String,
}

/// Exact rules that produced the decision (ADR-005 §4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyVersions {
    /// Digest of the compiled-in Cedar schema and policies.
    pub cedar: String,
    pub cel: Option<String>,
    pub packs: Vec<String>,
    /// Digest of the agent tool registry (which parameters are
    /// reference-only, which values are allowed). Absent in records written
    /// before H5b, so their canonical bytes are unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools: Option<String>,
    /// Build identity of the deciding binary.
    pub build: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeSync {
    pub status: String,
    pub max_error_ms: Option<u64>,
}

impl From<SyncStatus> for TimeSync {
    fn from(sync: SyncStatus) -> Self {
        match sync {
            SyncStatus::Synced { max_error_ms } => Self {
                status: "synced".into(),
                max_error_ms: Some(max_error_ms),
            },
            SyncStatus::Unsynced => Self {
                status: "unsynced".into(),
                max_error_ms: None,
            },
            SyncStatus::Unknown => Self {
                status: "unknown".into(),
                max_error_ms: None,
            },
        }
    }
}

/// The hashed and signed content of a record (everything but `hash`/`sig`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentDecisionPayload {
    pub record_id: String,
    pub tenant_id: String,
    pub partition_id: i32,
    pub seq: i64,
    pub prev_hash: String,
    pub kind: String,
    pub hash_alg: String,
    /// The evidence key; inside the payload so a signature cannot be paired
    /// with another key id.
    pub key_id: String,
    pub actor: Actor,
    /// Mandate ids from root to the acting mandate.
    pub chain: Vec<String>,
    pub mandate_id: String,
    pub purpose: String,
    pub consent_refs: Vec<String>,
    pub action: String,
    pub request_id: String,
    pub subject_pseudonym: String,
    /// Keyed MAC of the canonical parameters; `None` when parameters were
    /// refused as raw identifiers (only the violation is recorded).
    pub params_mac: Option<String>,
    pub policy_versions: PolicyVersions,
    pub signals: Vec<String>,
    /// The authorization outcome before the commit-time checks.
    pub pre_commit_decision: Decision,
    pub policy_decision: Decision,
    pub returned_decision: Decision,
    pub obligations: Vec<String>,
    /// The credential minted with this id (`jti`); only on an allow.
    pub credential_id: Option<String>,
    pub credential_expires_at: Option<DateTime<Utc>>,
    pub send_by: Option<DateTime<Utc>>,
    pub time_sync: TimeSync,
    pub ts: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentDecisionRecord {
    #[serde(flatten)]
    pub payload: AgentDecisionPayload,
    pub hash: String,
    pub sig: String,
}

impl AgentDecisionRecord {
    /// Allowed records authorize a forward (PASS or ALERT, ADR-001).
    #[must_use]
    pub fn is_allow(&self) -> bool {
        is_allow(self.payload.returned_decision)
    }
}

#[must_use]
pub fn is_allow(decision: Decision) -> bool {
    matches!(decision, Decision::Pass | Decision::Alert)
}

/// `v2` hash of a payload, as lowercase hex.
pub fn payload_hash(payload: &AgentDecisionPayload) -> Result<String, PortError> {
    let canonical = crate::jcs::to_vec(payload)?;
    let mut hasher = Sha256::new();
    hasher.update(HASH_PREFIX);
    hasher.update(payload.prev_hash.as_bytes());
    hasher.update(&canonical);
    Ok(format!("{:x}", hasher.finalize()))
}

#[must_use]
pub fn signing_message(hash: &str) -> Vec<u8> {
    let mut message = SIG_PREFIX.to_vec();
    message.extend_from_slice(hash.as_bytes());
    message
}

/// Signs with the evidence key, synchronously (the key is held in memory;
/// signing happens under the partition lock). Signs nothing but evidence.
pub trait EvidenceSigner: Send + Sync {
    fn key_id(&self) -> &str;
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, PortError>;
}

/// Hashes and signs a payload into a record.
pub fn seal(
    payload: AgentDecisionPayload,
    signer: &dyn EvidenceSigner,
) -> Result<AgentDecisionRecord, PortError> {
    if payload.key_id != signer.key_id() {
        return Err(PortError::invalid("payload key_id differs from the signer"));
    }
    let hash = payload_hash(&payload)?;
    let sig = hex::encode(signer.sign(&signing_message(&hash))?);
    Ok(AgentDecisionRecord { payload, hash, sig })
}

/// What a commit binds a `request_id` to: a retry must carry the same.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestBinding {
    pub action: String,
    pub params_mac: Option<String>,
    pub subject_pseudonym: String,
    pub mandate_id: String,
}

/// A contact-slot reservation, made only when the decision allows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactReservation {
    pub ist_date: NaiveDate,
    pub max_per_day: u32,
}

/// Everything a commit needs; the store fills seq, links, hashes and signs.
#[derive(Debug, Clone)]
pub struct CommitRequest {
    pub tenant_id: String,
    pub partition_id: i32,
    pub binding: RequestBinding,
    /// Draft payload: `seq`, `prev_hash`, `record_id`, final decisions,
    /// credential fields, `time_sync` and `ts` are set by the store.
    pub draft: AgentDecisionPayload,
    /// Present for contact actions: reserve a slot on allow.
    pub contact: Option<ContactReservation>,
    /// Pre-allocated `jti`, kept only if the final decision allows.
    pub credential_id: String,
    pub credential_ttl: chrono::Duration,
    /// Maximum clock error accepted at commit.
    pub max_clock_error_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitResult {
    Committed(Box<AgentDecisionRecord>),
    /// The same request was already committed; its record is returned and
    /// nothing new is reserved or written.
    Replayed(Box<AgentDecisionRecord>),
    /// The `request_id` was used for different content.
    Conflict(Box<AgentDecisionRecord>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// The provider accepted it.
    Delivered,
    /// Nothing was sent: the connection failed before any request went out.
    Failed,
    /// The provider refused it (provably not delivered).
    Refused,
    /// The allow was committed but nothing was sent (resolver or broker
    /// failure, `send_by` passed before forwarding).
    NotExecuted,
    /// Sent, result not known (timeout or loss after sending, 408, 5xx, a
    /// `jti` conflict). Never retried.
    Unknown,
}

impl Outcome {
    pub const ALL: [Self; 5] = [
        Self::Delivered,
        Self::Failed,
        Self::Refused,
        Self::NotExecuted,
        Self::Unknown,
    ];

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Delivered => "delivered",
            Self::Failed => "failed",
            Self::Refused => "refused",
            Self::NotExecuted => "not_executed",
            Self::Unknown => "unknown",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|o| o.as_str() == value)
    }

    /// Final: a retry returns it. `Unknown` is not final for the agent (a
    /// retry is refused as in flight).
    #[must_use]
    pub fn is_final(self) -> bool {
        self != Self::Unknown
    }
}

/// An outcome reason: `[a-z0-9_]{1,64}`, a code, never a value.
#[must_use]
pub fn is_reason_code(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// What happened after an allow, linked by `credential_id` (off-chain).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutcomeRecord {
    pub tenant_id: String,
    pub credential_id: String,
    pub record_hash: String,
    pub outcome: Outcome,
    /// Why (a code such as `provider_409` or `timeout_after_send`). Signed
    /// (v2). `None` only on v1 rows written before H5b.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub ts: DateTime<Utc>,
    pub key_id: String,
    pub sig: String,
}

/// The signed message: v2 (with the reason) when there is a reason, v1
/// otherwise (rows written before H5b).
#[must_use]
pub fn outcome_message(
    credential_id: &str,
    record_hash: &str,
    outcome: Outcome,
    reason: Option<&str>,
    ts: DateTime<Utc>,
) -> Vec<u8> {
    let ts = ts.to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
    let outcome = outcome.as_str();
    let (mut message, body) = match reason {
        None => (
            OUTCOME_SIG_PREFIX.to_vec(),
            format!("{credential_id}\n{record_hash}\n{outcome}\n{ts}"),
        ),
        Some(reason) => (
            OUTCOME_SIG_PREFIX_V2.to_vec(),
            format!("{credential_id}\n{record_hash}\n{outcome}\n{reason}\n{ts}"),
        ),
    };
    message.extend_from_slice(body.as_bytes());
    message
}

/// Signs an outcome (always v2, with a reason code).
pub fn sign_outcome(
    tenant_id: &str,
    credential_id: &str,
    record_hash: &str,
    outcome: Outcome,
    reason: &str,
    ts: DateTime<Utc>,
    signer: &dyn EvidenceSigner,
) -> Result<OutcomeRecord, PortError> {
    if !is_reason_code(reason) {
        return Err(PortError::invalid(
            "outcome reason must be a code: [a-z0-9_]{1,64}",
        ));
    }
    let sig = hex::encode(signer.sign(&outcome_message(
        credential_id,
        record_hash,
        outcome,
        Some(reason),
        ts,
    ))?);
    Ok(OutcomeRecord {
        tenant_id: tenant_id.into(),
        credential_id: credential_id.into(),
        record_hash: record_hash.into(),
        outcome,
        reason: Some(reason.into()),
        ts,
        key_id: signer.key_id().into(),
        sig,
    })
}

/// Agent evidence persistence (ADR-005 §6 phase 1).
///
/// `commit` is one transaction: lock the partition head, then (allow only,
/// lock order head → counter) re-check trusted time against `send_by` and
/// reserve a contact slot; build, hash and sign the record; append; advance
/// the head. Any failure rolls everything back, so no allow exists without
/// its record and no slot is reserved without one.
pub trait AgentEvidenceStore: Send + Sync {
    fn commit(
        &self,
        request: CommitRequest,
        clock: &dyn TimeSource,
        signer: &dyn EvidenceSigner,
    ) -> impl Future<Output = Result<CommitResult, PortError>> + Send;

    /// The record for a request, if committed.
    fn get_by_request(
        &self,
        tenant_id: &str,
        agent_id: &str,
        request_id: &str,
    ) -> impl Future<Output = Result<Option<AgentDecisionRecord>, PortError>> + Send;

    /// Records the outcome for an allowed record's credential, once.
    fn record_outcome(
        &self,
        outcome: OutcomeRecord,
    ) -> impl Future<Output = Result<(), PortError>> + Send;

    fn outcome(
        &self,
        tenant_id: &str,
        credential_id: &str,
    ) -> impl Future<Output = Result<Option<OutcomeRecord>, PortError>> + Send;

    /// All records of a partition in `seq` order (export / verification).
    fn records(
        &self,
        tenant_id: &str,
        partition_id: i32,
    ) -> impl Future<Output = Result<Vec<AgentDecisionRecord>, PortError>> + Send;

    /// Contacts reserved for a subject on an IST date.
    fn contacts_on(
        &self,
        tenant_id: &str,
        subject_pseudonym: &str,
        ist_date: NaiveDate,
    ) -> impl Future<Output = Result<u32, PortError>> + Send;
}

/// Shared commit-time decision (used by every store, so they agree): the
/// final decision and the reason it changed, given the pre-commit decision,
/// trusted time at commit and whether a slot could be reserved.
#[must_use]
pub fn finalise(
    pre_commit: Decision,
    request: &CommitRequest,
    now: crate::time::TrustedNow,
) -> (Decision, Option<&'static str>) {
    if !is_allow(pre_commit) || request.contact.is_none() {
        return (pre_commit, None);
    }
    if now.require_synced(request.max_clock_error_ms).is_err() {
        return (Decision::Block, Some("trusted_time_unavailable"));
    }
    if request.draft.send_by.is_some_and(|by| now.utc >= by) {
        return (Decision::Block, Some("window_closed"));
    }
    (pre_commit, None)
}

/// Fills the store-owned fields of a draft.
#[must_use]
pub fn complete_payload(
    request: &CommitRequest,
    seq: i64,
    prev_hash: &str,
    final_decision: Decision,
    reason: Option<&str>,
    now: crate::time::TrustedNow,
) -> AgentDecisionPayload {
    let mut payload = request.draft.clone();
    payload.record_id = uuid_like(&request.tenant_id, request.partition_id, seq);
    payload.seq = seq;
    payload.prev_hash = prev_hash.to_string();
    payload.kind = KIND_AGENT_DECISION.into();
    payload.hash_alg = HASH_ALG_V2.into();
    payload.policy_decision = final_decision;
    payload.returned_decision = final_decision;
    if let Some(reason) = reason {
        payload.signals.push(reason.to_string());
    }
    if is_allow(final_decision) {
        payload.credential_id = Some(request.credential_id.clone());
        payload.credential_expires_at = Some(now.utc + request.credential_ttl);
        if let (Some(exp), Some(by)) = (payload.credential_expires_at, payload.send_by) {
            payload.credential_expires_at = Some(exp.min(by));
        }
    } else {
        // A converted allow never carries a credential that was not issued.
        payload.credential_id = None;
        payload.credential_expires_at = None;
    }
    payload.time_sync = now.sync.into();
    payload.ts = now.utc;
    payload
}

fn uuid_like(tenant: &str, partition: i32, seq: i64) -> String {
    format!("adr:{tenant}:{partition}:{seq}")
}

/// Problems found by [`verify_chain`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChainError {
    #[error(
        "record {seq}: signed with development key {key_id}; dev-signed evidence is not \
         accepted (use verify_dev_chain for development stacks)"
    )]
    DevKey { seq: i64, key_id: String },
    #[error("record {seq}: expected seq {expected}")]
    Gap { seq: i64, expected: i64 },
    #[error("record {seq}: prev_hash does not link to the previous record")]
    Link { seq: i64 },
    #[error("record {seq}: hash does not match its payload")]
    Hash { seq: i64 },
    #[error("record {seq}: signature invalid ({reason})")]
    Signature { seq: i64, reason: String },
    #[error(
        "chain head is seq {actual_seq} / {actual_hash}, expected {expected_seq} / {expected_hash}"
    )]
    Head {
        actual_seq: i64,
        actual_hash: String,
        expected_seq: i64,
        expected_hash: String,
    },
    #[error("the outcome of {credential_id} does not verify")]
    Outcome { credential_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainReport {
    pub records: usize,
    pub head_seq: i64,
    pub head_hash: String,
    /// Allows whose credential lifetime has passed with no recorded
    /// outcome (e.g. a crash between commit and forward), by credential id.
    pub outcome_missing: Vec<String>,
    /// Outcomes recorded as `unknown` (sent, result not known).
    pub outcome_unknown: Vec<String>,
}

/// Verifies a partition offline: `seq` continuity from 1, links, hashes and
/// signatures against `keys`, and (when the operator recorded it out of
/// band) the expected head — without which a truncated tail is undetectable.
/// `outcomes` are checked for signatures (v1 or v2): one that does not
/// verify is an error, as it is for `verify-bundle`. Allows past their
/// credential expiry at `now` without an outcome are reported as missing,
/// recorded `unknown` outcomes as unknown.
/// Key ids with this prefix are development keys (`kavach-devkit`):
/// refused at production startup and by [`verify_chain`].
pub const DEV_KEY_PREFIX: &str = "dev-";

#[must_use]
pub fn is_dev_key(key_id: &str) -> bool {
    key_id.starts_with(DEV_KEY_PREFIX)
}

pub fn verify_chain(
    records: &[AgentDecisionRecord],
    keys: &BTreeMap<String, PublicKey>,
    expected_head: Option<(i64, &str)>,
    outcomes: &[OutcomeRecord],
    now: DateTime<Utc>,
) -> Result<ChainReport, ChainError> {
    verify(records, keys, expected_head, outcomes, now, false)
}

/// [`verify_chain`] for development stacks: also accepts evidence signed
/// with `dev-` keys. Never use it to accept evidence from a deployment.
pub fn verify_dev_chain(
    records: &[AgentDecisionRecord],
    keys: &BTreeMap<String, PublicKey>,
    expected_head: Option<(i64, &str)>,
    outcomes: &[OutcomeRecord],
    now: DateTime<Utc>,
) -> Result<ChainReport, ChainError> {
    verify(records, keys, expected_head, outcomes, now, true)
}

/// Whether evidence signed with `dev-` keys is accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevKeys {
    /// Evidence from a deployment: `dev-` keys are an error.
    Refuse,
    /// A development stack only.
    Accept,
}

/// The record a segment follows: its `seq` and hash, taken from a verified
/// checkpoint. [`SegmentStart::GENESIS`] is the start of the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentStart<'a> {
    pub seq: i64,
    pub hash: &'a str,
}

impl SegmentStart<'static> {
    pub const GENESIS: Self = Self {
        seq: 0,
        hash: GENESIS,
    };
}

/// [`verify_chain`] for a segment that starts after a checkpoint rather
/// than at the first record (ADR-005 §10). The caller must have verified
/// the checkpoint that supplies `start`; nothing before it is checked.
pub fn verify_segment(
    records: &[AgentDecisionRecord],
    start: SegmentStart<'_>,
    keys: &BTreeMap<String, PublicKey>,
    expected_head: Option<(i64, &str)>,
    outcomes: &[OutcomeRecord],
    now: DateTime<Utc>,
    dev_keys: DevKeys,
) -> Result<ChainReport, ChainError> {
    verify_from(
        records,
        start,
        keys,
        expected_head,
        outcomes,
        now,
        dev_keys == DevKeys::Accept,
    )
}

/// One record of a chain: not dev-signed (unless allowed), the expected
/// `seq`, linked to `prev`, hashing to its content and signed by a key in
/// `keys`.
pub fn check_record(
    record: &AgentDecisionRecord,
    expected_seq: i64,
    prev: &str,
    keys: &BTreeMap<String, PublicKey>,
    allow_dev_keys: bool,
) -> Result<(), ChainError> {
    let p = &record.payload;
    if !allow_dev_keys && is_dev_key(&p.key_id) {
        return Err(ChainError::DevKey {
            seq: p.seq,
            key_id: p.key_id.clone(),
        });
    }
    if p.seq != expected_seq {
        return Err(ChainError::Gap {
            seq: p.seq,
            expected: expected_seq,
        });
    }
    if p.prev_hash != prev {
        return Err(ChainError::Link { seq: p.seq });
    }
    if payload_hash(p).ok().as_deref() != Some(record.hash.as_str()) {
        return Err(ChainError::Hash { seq: p.seq });
    }
    let signature = |reason: String| ChainError::Signature { seq: p.seq, reason };
    let key = keys
        .get(&p.key_id)
        .ok_or_else(|| signature(format!("unknown key {}", p.key_id)))?;
    let sig = hex::decode(&record.sig).map_err(|_| signature("not hex".into()))?;
    verify_ed25519(key, &signing_message(&record.hash), &sig).map_err(|e| signature(e.to_string()))
}

/// Whether an outcome's signature (v1 or v2) verifies with a key in `keys`
/// and its reason, if any, is a reason code.
#[must_use]
pub fn outcome_verifies(outcome: &OutcomeRecord, keys: &BTreeMap<String, PublicKey>) -> bool {
    let key = keys.get(&outcome.key_id);
    let sig = hex::decode(&outcome.sig).unwrap_or_default();
    let reason_ok = outcome.reason.as_deref().is_none_or(is_reason_code);
    let message = outcome_message(
        &outcome.credential_id,
        &outcome.record_hash,
        outcome.outcome,
        outcome.reason.as_deref(),
        outcome.ts,
    );
    reason_ok && key.is_some_and(|k| verify_ed25519(k, &message, &sig).is_ok())
}

fn verify(
    records: &[AgentDecisionRecord],
    keys: &BTreeMap<String, PublicKey>,
    expected_head: Option<(i64, &str)>,
    outcomes: &[OutcomeRecord],
    now: DateTime<Utc>,
    allow_dev_keys: bool,
) -> Result<ChainReport, ChainError> {
    verify_from(
        records,
        SegmentStart::GENESIS,
        keys,
        expected_head,
        outcomes,
        now,
        allow_dev_keys,
    )
}

fn verify_from(
    records: &[AgentDecisionRecord],
    start: SegmentStart<'_>,
    keys: &BTreeMap<String, PublicKey>,
    expected_head: Option<(i64, &str)>,
    outcomes: &[OutcomeRecord],
    now: DateTime<Utc>,
    allow_dev_keys: bool,
) -> Result<ChainReport, ChainError> {
    let mut prev = start.hash.to_string();
    for (index, record) in records.iter().enumerate() {
        let expected = start
            .seq
            .saturating_add(i64::try_from(index).unwrap_or(i64::MAX))
            .saturating_add(1);
        check_record(record, expected, &prev, keys, allow_dev_keys)?;
        prev.clone_from(&record.hash);
    }
    let head_seq = records.last().map_or(start.seq, |r| r.payload.seq);
    if let Some((expected_seq, expected_hash)) = expected_head {
        if head_seq != expected_seq || prev != expected_hash {
            return Err(ChainError::Head {
                actual_seq: head_seq,
                actual_hash: prev,
                expected_seq,
                expected_hash: expected_hash.into(),
            });
        }
    }
    let mut known = std::collections::BTreeSet::new();
    let mut outcome_unknown = Vec::new();
    for outcome in outcomes {
        if outcome_verifies(outcome, keys) {
            known.insert(outcome.credential_id.clone());
            if outcome.outcome == Outcome::Unknown {
                outcome_unknown.push(outcome.credential_id.clone());
            }
        } else {
            // A row that does not verify is evidence of tampering, not a
            // gap: fail, as the bundle verifier does.
            return Err(ChainError::Outcome {
                credential_id: outcome.credential_id.clone(),
            });
        }
    }
    let outcome_missing = records
        .iter()
        .filter(|r| r.is_allow())
        .filter_map(|r| {
            let id = r.payload.credential_id.as_ref()?;
            let expired = r.payload.credential_expires_at.is_none_or(|exp| exp <= now);
            (expired && !known.contains(id)).then(|| id.clone())
        })
        .collect();
    Ok(ChainReport {
        records: records.len(),
        head_seq,
        head_hash: prev,
        outcome_missing,
        outcome_unknown,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyAlgorithm;
    use ed25519_dalek::{Signer, SigningKey};

    struct Key(SigningKey);

    impl EvidenceSigner for Key {
        fn key_id(&self) -> &'static str {
            "ev-1"
        }
        fn sign(&self, message: &[u8]) -> Result<Vec<u8>, PortError> {
            Ok(self.0.sign(message).to_bytes().to_vec())
        }
    }

    fn payload(seq: i64, prev: &str) -> AgentDecisionPayload {
        AgentDecisionPayload {
            record_id: format!("r-{seq}"),
            tenant_id: "t".into(),
            partition_id: 0,
            seq,
            prev_hash: prev.into(),
            kind: KIND_AGENT_DECISION.into(),
            hash_alg: HASH_ALG_V2.into(),
            key_id: "ev-1".into(),
            actor: Actor {
                agent_id: "a".into(),
                identity_key: "oidc:i#a".into(),
            },
            chain: vec!["m".into()],
            mandate_id: "m".into(),
            purpose: "p".into(),
            consent_refs: vec![],
            action: "send_reminder".into(),
            request_id: format!("q-{seq}"),
            subject_pseudonym: "psn:x".into(),
            params_mac: None,
            policy_versions: PolicyVersions {
                cedar: "c".into(),
                cel: None,
                packs: vec![],
                tools: None,
                build: "b".into(),
            },
            signals: vec![],
            pre_commit_decision: Decision::Block,
            policy_decision: Decision::Block,
            returned_decision: Decision::Block,
            obligations: vec![],
            credential_id: None,
            credential_expires_at: None,
            send_by: None,
            time_sync: SyncStatus::Unknown.into(),
            ts: DateTime::from_timestamp(1_790_000_000, 0).unwrap(),
        }
    }

    fn chain(n: i64, key: &Key) -> Vec<AgentDecisionRecord> {
        let mut prev = GENESIS.to_string();
        (1..=n)
            .map(|seq| {
                let record = seal(payload(seq, &prev), key).unwrap();
                prev.clone_from(&record.hash);
                record
            })
            .collect()
    }

    fn keys(key: &Key) -> BTreeMap<String, PublicKey> {
        BTreeMap::from([(
            "ev-1".to_string(),
            PublicKey {
                kid: "ev-1".into(),
                algorithm: KeyAlgorithm::Ed25519,
                bytes: key.0.verifying_key().to_bytes(),
            },
        )])
    }

    #[test]
    fn records_without_a_tool_registry_keep_their_canonical_bytes() {
        let old = payload(1, GENESIS);
        let json = serde_json::to_value(&old.policy_versions).unwrap();
        assert!(json.get("tools").is_none(), "{json}");
        let hash = payload_hash(&old).unwrap();

        let mut pinned = old.clone();
        pinned.policy_versions.tools = Some("sha256:tools".into());
        assert_ne!(payload_hash(&pinned).unwrap(), hash);
        let back: PolicyVersions =
            serde_json::from_value(serde_json::to_value(&pinned.policy_versions).unwrap()).unwrap();
        assert_eq!(back, pinned.policy_versions);
    }

    /// Three allows (credentials c-1..c-3, expired by `now`).
    fn allows(key: &Key) -> Vec<AgentDecisionRecord> {
        let mut prev = GENESIS.to_string();
        (1..=3)
            .map(|seq| {
                let mut p = payload(seq, &prev);
                p.pre_commit_decision = Decision::Pass;
                p.policy_decision = Decision::Pass;
                p.returned_decision = Decision::Pass;
                p.credential_id = Some(format!("c-{seq}"));
                p.credential_expires_at = Some(DateTime::from_timestamp(1_790_000_000, 0).unwrap());
                let record = seal(p, key).unwrap();
                prev.clone_from(&record.hash);
                record
            })
            .collect()
    }

    #[test]
    fn outcomes_are_missing_or_unknown_an_invalid_one_fails_and_v1_still_verifies() {
        let key = Key(SigningKey::from_bytes(&[4u8; 32]));
        let now = DateTime::from_timestamp(1_790_000_100, 0).unwrap();
        let records = allows(&key);
        let at = DateTime::from_timestamp(1_790_000_001, 0).unwrap();

        // c-1: a v1 (pre-H5b) outcome, signed without a reason.
        let v1_sig = key
            .sign(&outcome_message(
                "c-1",
                &records[0].hash,
                Outcome::Delivered,
                None,
                at,
            ))
            .unwrap();
        let v1 = OutcomeRecord {
            tenant_id: "t".into(),
            credential_id: "c-1".into(),
            record_hash: records[0].hash.clone(),
            outcome: Outcome::Delivered,
            reason: None,
            ts: at,
            key_id: "ev-1".into(),
            sig: hex::encode(v1_sig),
        };
        // c-2: a v2 `unknown` outcome with its reason.
        let unknown = sign_outcome(
            "t",
            "c-2",
            &records[1].hash,
            Outcome::Unknown,
            "timeout_after_send",
            at,
            &key,
        )
        .unwrap();
        // c-3: no outcome at all (a crash between commit and forward).
        let report = verify_chain(
            &records,
            &keys(&key),
            None,
            &[v1.clone(), unknown.clone()],
            now,
        )
        .unwrap();
        assert_eq!(report.outcome_missing, vec!["c-3".to_string()]);
        assert_eq!(report.outcome_unknown, vec!["c-2".to_string()]);

        // A rewritten reason or outcome no longer verifies: the chain fails.
        let invalid = |credential_id: &str| {
            Err(ChainError::Outcome {
                credential_id: credential_id.into(),
            })
        };
        let mut reason_edited = unknown.clone();
        reason_edited.reason = Some("provider_202".into());
        let mut outcome_edited = unknown;
        outcome_edited.outcome = Outcome::Delivered;
        for edited in [reason_edited, outcome_edited] {
            assert_eq!(
                verify_chain(&records, &keys(&key), None, &[v1.clone(), edited], now),
                invalid("c-2")
            );
        }
        // A v1 row cannot be upgraded by adding a reason.
        let mut upgraded = v1;
        upgraded.reason = Some("provider_202".into());
        assert_eq!(
            verify_chain(&records, &keys(&key), None, &[upgraded], now),
            invalid("c-1")
        );
    }

    #[test]
    fn dev_signed_evidence_is_refused_unless_explicitly_verifying_a_dev_stack() {
        struct DevSigner(SigningKey);
        impl EvidenceSigner for DevSigner {
            fn key_id(&self) -> &'static str {
                "dev-evidence-1"
            }
            fn sign(&self, message: &[u8]) -> Result<Vec<u8>, PortError> {
                Ok(self.0.sign(message).to_bytes().to_vec())
            }
        }
        let key = Key(SigningKey::from_bytes(&[4u8; 32]));
        let dev = DevSigner(SigningKey::from_bytes(&[4u8; 32]));
        let now = DateTime::from_timestamp(1_790_000_000, 0).unwrap();
        let mut prev = GENESIS.to_string();
        let records: Vec<_> = (1..=2)
            .map(|seq| {
                let mut p = payload(seq, &prev);
                p.key_id = "dev-evidence-1".into();
                let record = seal(p, &dev).unwrap();
                prev.clone_from(&record.hash);
                record
            })
            .collect();
        let mut dev_keys = keys(&key);
        let public = dev_keys.remove("ev-1").unwrap();
        dev_keys.insert(
            "dev-evidence-1".into(),
            PublicKey {
                kid: "dev-evidence-1".into(),
                ..public
            },
        );
        assert!(matches!(
            verify_chain(&records, &dev_keys, None, &[], now),
            Err(ChainError::DevKey { seq: 1, .. })
        ));
        verify_dev_chain(&records, &dev_keys, None, &[], now)
            .expect("a dev stack verifies its own");
    }

    #[test]
    fn outcome_values_and_reason_codes() {
        for outcome in Outcome::ALL {
            assert_eq!(Outcome::parse(outcome.as_str()), Some(outcome));
        }
        assert_eq!(Outcome::parse("maybe"), None);
        assert!(!Outcome::Unknown.is_final() && Outcome::NotExecuted.is_final());
        assert!(is_reason_code("send_by_passed"));
        for bad in [
            "",
            "Timeout",
            "provider 409",
            "+919876543210",
            &"a".repeat(65),
        ] {
            assert!(!is_reason_code(bad), "{bad}");
        }
        let key = Key(SigningKey::from_bytes(&[4u8; 32]));
        let now = DateTime::from_timestamp(1_790_000_000, 0).unwrap();
        assert!(sign_outcome("t", "c", "h", Outcome::Failed, "call +91 98765", now, &key).is_err());
    }

    #[test]
    fn verifier_detects_each_kind_of_tampering() {
        let key = Key(SigningKey::from_bytes(&[4u8; 32]));
        let now = DateTime::from_timestamp(1_790_000_000, 0).unwrap();
        let good = chain(3, &key);
        let report = verify_chain(&good, &keys(&key), None, &[], now).unwrap();
        assert_eq!((report.records, report.head_seq), (3, 3));

        let mut edited = good.clone();
        edited[1].payload.action = "place_call".into();
        assert!(matches!(
            verify_chain(&edited, &keys(&key), None, &[], now),
            Err(ChainError::Hash { seq: 2 })
        ));

        let mut relinked = good.clone();
        relinked.remove(1);
        assert!(matches!(
            verify_chain(&relinked, &keys(&key), None, &[], now),
            Err(ChainError::Gap { .. })
        ));

        // Re-hashed by someone without the evidence key: signature fails.
        let impostor = Key(SigningKey::from_bytes(&[5u8; 32]));
        let mut forged = good.clone();
        forged[2] = seal(payload(3, &good[1].hash), &impostor).unwrap();
        assert!(matches!(
            verify_chain(&forged, &keys(&key), None, &[], now),
            Err(ChainError::Signature { seq: 3, .. })
        ));

        // A different key id cannot be swapped in: key_id is hashed.
        let mut rekeyed = good.clone();
        rekeyed[0].payload.key_id = "ev-2".into();
        assert!(verify_chain(&rekeyed, &keys(&key), None, &[], now).is_err());

        // Truncation is detected only against a known head.
        assert!(verify_chain(&good[..2], &keys(&key), None, &[], now).is_ok());
        assert!(matches!(
            verify_chain(&good[..2], &keys(&key), Some((3, &good[2].hash)), &[], now),
            Err(ChainError::Head { .. })
        ));
    }

    #[test]
    fn a_segment_verifies_from_the_record_it_follows() {
        let key = Key(SigningKey::from_bytes(&[4u8; 32]));
        let now = DateTime::from_timestamp(1_790_000_000, 0).unwrap();
        let good = chain(5, &key);
        let start = SegmentStart {
            seq: 2,
            hash: &good[1].hash,
        };
        let verify = |records: &[AgentDecisionRecord], start| {
            verify_segment(records, start, &keys(&key), None, &[], now, DevKeys::Refuse)
        };

        let report = verify(&good[2..], start).unwrap();
        assert_eq!((report.records, report.head_seq), (3, 5));
        assert_eq!(report.head_hash, good[4].hash);
        // From genesis it is the same as verify_chain.
        assert_eq!(
            verify(&good, SegmentStart::GENESIS).unwrap(),
            verify_chain(&good, &keys(&key), None, &[], now).unwrap()
        );
        // An empty segment reports its start as the head.
        assert_eq!(verify(&[], start).unwrap().head_seq, 2);

        // A segment that does not follow the stated record is refused.
        let wrong = SegmentStart {
            seq: 2,
            hash: &good[0].hash,
        };
        assert!(matches!(
            verify(&good[2..], wrong),
            Err(ChainError::Link { seq: 3 })
        ));
        // So is one that skips its first record.
        assert!(matches!(
            verify(&good[3..], start),
            Err(ChainError::Gap {
                seq: 4,
                expected: 3
            })
        ));
        // And the segment still needs a head to detect a cut tail.
        assert!(matches!(
            verify_segment(
                &good[2..4],
                start,
                &keys(&key),
                Some((5, &good[4].hash)),
                &[],
                now,
                DevKeys::Refuse
            ),
            Err(ChainError::Head { .. })
        ));
    }
}

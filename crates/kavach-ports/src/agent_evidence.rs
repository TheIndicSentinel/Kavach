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
    let canonical = serde_json_canonicalizer::to_vec(payload)
        .map_err(|e| PortError::invalid(format!("canonical payload: {e}")))?;
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
    Delivered,
    Failed,
    Refused,
}

impl Outcome {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Delivered => "delivered",
            Self::Failed => "failed",
            Self::Refused => "refused",
        }
    }
}

/// What happened after an allow, linked by `credential_id` (off-chain).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutcomeRecord {
    pub tenant_id: String,
    pub credential_id: String,
    pub record_hash: String,
    pub outcome: Outcome,
    pub ts: DateTime<Utc>,
    pub key_id: String,
    pub sig: String,
}

#[must_use]
pub fn outcome_message(
    credential_id: &str,
    record_hash: &str,
    outcome: Outcome,
    ts: DateTime<Utc>,
) -> Vec<u8> {
    let mut message = OUTCOME_SIG_PREFIX.to_vec();
    message.extend_from_slice(
        format!(
            "{credential_id}\n{record_hash}\n{}\n{}",
            outcome.as_str(),
            ts.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
        )
        .as_bytes(),
    );
    message
}

pub fn sign_outcome(
    tenant_id: &str,
    credential_id: &str,
    record_hash: &str,
    outcome: Outcome,
    ts: DateTime<Utc>,
    signer: &dyn EvidenceSigner,
) -> Result<OutcomeRecord, PortError> {
    let sig =
        hex::encode(signer.sign(&outcome_message(credential_id, record_hash, outcome, ts))?);
    Ok(OutcomeRecord {
        tenant_id: tenant_id.into(),
        credential_id: credential_id.into(),
        record_hash: record_hash.into(),
        outcome,
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainReport {
    pub records: usize,
    pub head_seq: i64,
    pub head_hash: String,
    /// Allows whose credential has expired with no recorded outcome.
    pub outcome_unknown: Vec<String>,
}

/// Verifies a partition offline: `seq` continuity from 1, links, hashes and
/// signatures against `keys`, and (when the operator recorded it out of
/// band) the expected head — without which a truncated tail is undetectable.
/// `outcomes` are checked for signatures; allows past their credential
/// expiry at `now` without an outcome are reported as unknown.
pub fn verify_chain(
    records: &[AgentDecisionRecord],
    keys: &BTreeMap<String, PublicKey>,
    expected_head: Option<(i64, &str)>,
    outcomes: &[OutcomeRecord],
    now: DateTime<Utc>,
) -> Result<ChainReport, ChainError> {
    let mut prev = GENESIS.to_string();
    for (index, record) in records.iter().enumerate() {
        let p = &record.payload;
        let expected = i64::try_from(index).unwrap_or(i64::MAX) + 1;
        if p.seq != expected {
            return Err(ChainError::Gap {
                seq: p.seq,
                expected,
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
        verify_ed25519(key, &signing_message(&record.hash), &sig)
            .map_err(|e| signature(e.to_string()))?;
        prev.clone_from(&record.hash);
    }
    let head_seq = records.last().map_or(0, |r| r.payload.seq);
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
    for outcome in outcomes {
        let key = keys.get(&outcome.key_id);
        let sig = hex::decode(&outcome.sig).unwrap_or_default();
        let message = outcome_message(
            &outcome.credential_id,
            &outcome.record_hash,
            outcome.outcome,
            outcome.ts,
        );
        if key.is_some_and(|k| verify_ed25519(k, &message, &sig).is_ok()) {
            known.insert(outcome.credential_id.clone());
        }
    }
    let outcome_unknown = records
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
}

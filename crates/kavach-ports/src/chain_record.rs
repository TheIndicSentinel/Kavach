//! Records of the agent chain other than decisions, and a record of any
//! kind (ADR-012 §7, ADR-013).
//!
//! Every kind is hashed and signed like a decision (`v2` hash, the evidence
//! key, the same signing message) and takes its place in the same chain. The
//! kind is inside the signed payload, so a record cannot be passed off as
//! another kind, and a reader refuses a kind it does not know rather than
//! skipping it.

use chrono::{DateTime, DurationRound, TimeDelta, Utc};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

use crate::agent_evidence::{
    content_hash, signing_message, AgentDecisionRecord, ChainEntry, EvidenceSigner, TimeSync,
    HASH_ALG_V2, KIND_AGENT_DECISION, KIND_MANDATE_REVOCATION,
};
use crate::error::PortError;
use crate::time::TrustedNow;

/// Mandates revoked by a system-of-record event (ADR-012). It names the
/// event and the mandates, never the borrower or the loan reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationPayload {
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
    /// The system of record and its event.
    pub source_system: String,
    pub event_id: String,
    /// SHA-256 of the event as it was verified.
    pub event_sha256: String,
    pub event_type: String,
    /// Keyed pseudonym of the record (loan) the event is about.
    pub record_pseudonym: String,
    /// When the event says it happened: mandates issued after it stay live.
    pub occurred_at: DateTime<Utc>,
    /// The mandates it revoked, roots and their delegations.
    pub revoked: Vec<String>,
    /// When Kavach revoked them.
    pub revoked_at: DateTime<Utc>,
    /// When this record was written: later than `revoked_at` when it was
    /// written by the reconciler.
    pub recorded_at: DateTime<Utc>,
    pub time_sync: TimeSync,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationRecord {
    #[serde(flatten)]
    pub payload: RevocationPayload,
    pub hash: String,
    pub sig: String,
}

/// What a store needs to write a revocation record: everything but its
/// place in the chain, its key, its time and its seal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationDraft {
    pub tenant_id: String,
    pub partition_id: i32,
    pub source_system: String,
    pub event_id: String,
    pub event_sha256: String,
    pub event_type: String,
    pub record_pseudonym: String,
    pub occurred_at: DateTime<Utc>,
    pub revoked: Vec<String>,
    pub revoked_at: DateTime<Utc>,
}

impl RevocationDraft {
    /// The payload at `seq` after `prev_hash`, recorded at `now`.
    #[must_use]
    pub fn complete(
        &self,
        seq: i64,
        prev_hash: &str,
        key_id: &str,
        now: TrustedNow,
    ) -> RevocationPayload {
        RevocationPayload {
            record_id: format!("rev:{}:{}:{seq}", self.tenant_id, self.partition_id),
            tenant_id: self.tenant_id.clone(),
            partition_id: self.partition_id,
            seq,
            prev_hash: prev_hash.to_string(),
            kind: KIND_MANDATE_REVOCATION.into(),
            hash_alg: HASH_ALG_V2.into(),
            key_id: key_id.to_string(),
            source_system: self.source_system.clone(),
            event_id: self.event_id.clone(),
            event_sha256: self.event_sha256.clone(),
            event_type: self.event_type.clone(),
            record_pseudonym: self.record_pseudonym.clone(),
            occurred_at: micros(self.occurred_at),
            revoked: self.revoked.clone(),
            revoked_at: micros(self.revoked_at),
            recorded_at: micros(now.utc),
            time_sync: now.sync.into(),
        }
    }

    /// Whether `record` is this revocation: the same event, content and
    /// mandates.
    #[must_use]
    pub fn matches(&self, record: &RevocationRecord) -> bool {
        let p = &record.payload;
        p.tenant_id == self.tenant_id
            && p.source_system == self.source_system
            && p.event_id == self.event_id
            && p.event_sha256 == self.event_sha256
            && p.revoked == self.revoked
    }
}

/// A time as the stores keep it (Postgres `TIMESTAMPTZ`): whole
/// microseconds, so a record written now and one rebuilt from storage by the
/// reconciler state the same times.
fn micros(t: DateTime<Utc>) -> DateTime<Utc> {
    t.duration_trunc(TimeDelta::microseconds(1)).unwrap_or(t)
}

/// Hashes and signs a revocation payload into a record.
pub fn seal_revocation(
    payload: RevocationPayload,
    signer: &dyn EvidenceSigner,
) -> Result<RevocationRecord, PortError> {
    if payload.key_id != signer.key_id() {
        return Err(PortError::invalid("payload key_id differs from the signer"));
    }
    let hash = content_hash(&payload.prev_hash, &payload)?;
    let sig = hex::encode(signer.sign(&signing_message(&hash))?);
    Ok(RevocationRecord { payload, hash, sig })
}

impl ChainEntry for RevocationRecord {
    fn kind(&self) -> &str {
        &self.payload.kind
    }
    fn expected_kind(&self) -> &'static str {
        KIND_MANDATE_REVOCATION
    }
    fn tenant_id(&self) -> &str {
        &self.payload.tenant_id
    }
    fn partition_id(&self) -> i32 {
        self.payload.partition_id
    }
    fn seq(&self) -> i64 {
        self.payload.seq
    }
    fn ts(&self) -> DateTime<Utc> {
        self.payload.recorded_at
    }
    fn prev_hash(&self) -> &str {
        &self.payload.prev_hash
    }
    fn key_id(&self) -> &str {
        &self.payload.key_id
    }
    fn time_sync(&self) -> &TimeSync {
        &self.payload.time_sync
    }
    fn hash(&self) -> &str {
        &self.hash
    }
    fn sig(&self) -> &str {
        &self.sig
    }
    fn content_hash(&self) -> Option<String> {
        content_hash(&self.payload.prev_hash, &self.payload).ok()
    }
    fn as_decision(&self) -> Option<&AgentDecisionRecord> {
        None
    }
}

/// A record of the agent chain, of any kind this build knows. Read by its
/// signed `kind`; any other kind is refused, never skipped.
// Decisions are nearly every record of a chain: boxing them to shrink the
// enum would cost an allocation per record and save nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum ChainRecord {
    Decision(AgentDecisionRecord),
    Revocation(RevocationRecord),
}

impl ChainRecord {
    /// The decision, if this record is one.
    #[must_use]
    pub fn into_decision(self) -> Option<AgentDecisionRecord> {
        match self {
            Self::Decision(record) => Some(record),
            Self::Revocation(_) => None,
        }
    }
}

impl<'de> Deserialize<'de> for ChainRecord {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(deserializer)?;
        let kind = value
            .get("kind")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| D::Error::custom("a record without a kind"))?
            .to_string();
        match kind.as_str() {
            KIND_AGENT_DECISION => serde_json::from_value(value)
                .map(Self::Decision)
                .map_err(D::Error::custom),
            KIND_MANDATE_REVOCATION => serde_json::from_value(value)
                .map(Self::Revocation)
                .map_err(D::Error::custom),
            other => Err(D::Error::custom(format!(
                "a record of kind {other}, which this build does not know: refused"
            ))),
        }
    }
}

impl ChainEntry for ChainRecord {
    fn kind(&self) -> &str {
        match self {
            Self::Decision(r) => r.kind(),
            Self::Revocation(r) => r.kind(),
        }
    }
    fn expected_kind(&self) -> &'static str {
        match self {
            Self::Decision(r) => r.expected_kind(),
            Self::Revocation(r) => r.expected_kind(),
        }
    }
    fn tenant_id(&self) -> &str {
        match self {
            Self::Decision(r) => r.tenant_id(),
            Self::Revocation(r) => r.tenant_id(),
        }
    }
    fn partition_id(&self) -> i32 {
        match self {
            Self::Decision(r) => r.partition_id(),
            Self::Revocation(r) => r.partition_id(),
        }
    }
    fn seq(&self) -> i64 {
        match self {
            Self::Decision(r) => r.seq(),
            Self::Revocation(r) => r.seq(),
        }
    }
    fn ts(&self) -> DateTime<Utc> {
        match self {
            Self::Decision(r) => r.ts(),
            Self::Revocation(r) => r.ts(),
        }
    }
    fn prev_hash(&self) -> &str {
        match self {
            Self::Decision(r) => r.prev_hash(),
            Self::Revocation(r) => r.prev_hash(),
        }
    }
    fn key_id(&self) -> &str {
        match self {
            Self::Decision(r) => r.key_id(),
            Self::Revocation(r) => r.key_id(),
        }
    }
    fn time_sync(&self) -> &TimeSync {
        match self {
            Self::Decision(r) => r.time_sync(),
            Self::Revocation(r) => r.time_sync(),
        }
    }
    fn hash(&self) -> &str {
        match self {
            Self::Decision(r) => r.hash(),
            Self::Revocation(r) => r.hash(),
        }
    }
    fn sig(&self) -> &str {
        match self {
            Self::Decision(r) => r.sig(),
            Self::Revocation(r) => r.sig(),
        }
    }
    fn content_hash(&self) -> Option<String> {
        match self {
            Self::Decision(r) => ChainEntry::content_hash(r),
            Self::Revocation(r) => ChainEntry::content_hash(r),
        }
    }
    fn as_decision(&self) -> Option<&AgentDecisionRecord> {
        match self {
            Self::Decision(r) => Some(r),
            Self::Revocation(_) => None,
        }
    }
}

//! Records of the agent chain other than decisions, and a record of any
//! kind (ADR-012 §7, ADR-013).
//!
//! Every kind is hashed and signed like a decision (`v2` hash, the evidence
//! key, the same signing message) and takes its place in the same chain. The
//! kind is inside the signed payload, so a record cannot be passed off as
//! another kind, and a reader refuses a kind it does not know rather than
//! skipping it.

use chrono::{DateTime, DurationRound, TimeDelta, Utc};
use kavach_domain::{AgentState, ReasonCode};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

use crate::agent_evidence::{
    content_hash, signing_message, AgentDecisionRecord, ChainEntry, EvidenceSigner, TimeSync,
    HASH_ALG_V2, KIND_AGENT_DECISION, KIND_AGENT_STATE, KIND_MANDATE_REVOCATION,
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
    /// The event's digest, `sha256-jcs-v1:` and 64 hex characters: SHA-256
    /// of the event's RFC 8785 bytes, which are the payload of the signed
    /// token (docs/specs/mandate-and-sor-event.md section 5). Exactly one
    /// of this and `event_sha256` is present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_digest: Option<String>,
    /// **Legacy**, written before `event_digest`: SHA-256 (64 hex
    /// characters) of the event's members in struct declaration order. It
    /// cannot be recomputed without that order, so it is kept readable and
    /// never written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_sha256: Option<String>,
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
    /// The event's digest: `sha256-jcs-v1:<hex>`, or a legacy bare 64-hex
    /// SHA-256 for a revocation stored before that form existed. A legacy
    /// value is written to the record as `event_sha256`, so a record
    /// rebuilt from an old row is the record that row always had.
    pub event_digest: String,
    pub event_type: String,
    pub record_pseudonym: String,
    pub occurred_at: DateTime<Utc>,
    pub revoked: Vec<String>,
    pub revoked_at: DateTime<Utc>,
}

/// Prefix of the digest of an event (version 1: SHA-256 over JCS bytes).
pub const EVENT_DIGEST_PREFIX: &str = "sha256-jcs-v1:";

fn is_lower_hex_64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

impl RevocationPayload {
    /// The digest this record states, in the form a draft carries it, if
    /// the record has exactly one well-formed digest.
    #[must_use]
    pub fn digest(&self) -> Option<&str> {
        match (&self.event_digest, &self.event_sha256) {
            (Some(d), None) => d
                .strip_prefix(EVENT_DIGEST_PREFIX)
                .filter(|h| is_lower_hex_64(h))
                .map(|_| d.as_str()),
            (None, Some(h)) if is_lower_hex_64(h) => Some(h.as_str()),
            _ => None,
        }
    }
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
            event_digest: self
                .event_digest
                .starts_with(EVENT_DIGEST_PREFIX)
                .then(|| self.event_digest.clone()),
            event_sha256: (!self.event_digest.starts_with(EVENT_DIGEST_PREFIX))
                .then(|| self.event_digest.clone()),
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
            && p.digest() == Some(self.event_digest.as_str())
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
    fn hash_alg(&self) -> &str {
        &self.payload.hash_alg
    }
    fn form(&self) -> Result<(), &'static str> {
        self.payload.digest().map(|_| ()).ok_or(
            "exactly one well-formed event digest (event_digest or event_sha256) is required",
        )
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

/// A change of an agent's state (ADR-013 §4): who stopped or reinstated
/// which agent, from what to what, why (a closed code; never the operator's
/// free text), and who approved a loosening. The agent is named, never a
/// borrower.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentStatePayload {
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
    pub agent_id: String,
    /// 1 for the agent's first change, then 2, 3, …: the change's identity.
    pub change_no: i64,
    pub from_state: AgentState,
    pub to_state: AgentState,
    pub reason_code: ReasonCode,
    /// `mac:` and 64 lowercase hex: a keyed digest of the operator's free
    /// text, which stays outside the chain. `None` when there was none.
    pub reason_digest: Option<String>,
    pub changed_by: String,
    /// Present exactly when the change loosens, and not the changer.
    pub approved_by: Option<String>,
    /// When the state changed (trusted time, whole microseconds).
    pub changed_at: DateTime<Utc>,
    /// When this record was written: later than `changed_at` when the
    /// reconciler wrote it.
    pub recorded_at: DateTime<Utc>,
    pub time_sync: TimeSync,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentStateRecord {
    #[serde(flatten)]
    pub payload: AgentStatePayload,
    pub hash: String,
    pub sig: String,
}

/// What a store needs to write an agent-state record: everything but its
/// place in the chain, its key, its time and its seal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentStateDraft {
    pub tenant_id: String,
    pub partition_id: i32,
    pub agent_id: String,
    pub change_no: i64,
    pub from_state: AgentState,
    pub to_state: AgentState,
    pub reason_code: ReasonCode,
    pub reason_digest: Option<String>,
    pub changed_by: String,
    pub approved_by: Option<String>,
    pub changed_at: DateTime<Utc>,
}

impl AgentStateDraft {
    /// The payload at `seq` after `prev_hash`, recorded at `now`.
    #[must_use]
    pub fn complete(
        &self,
        seq: i64,
        prev_hash: &str,
        key_id: &str,
        now: TrustedNow,
    ) -> AgentStatePayload {
        AgentStatePayload {
            record_id: format!("ast:{}:{}:{seq}", self.tenant_id, self.partition_id),
            tenant_id: self.tenant_id.clone(),
            partition_id: self.partition_id,
            seq,
            prev_hash: prev_hash.to_string(),
            kind: KIND_AGENT_STATE.into(),
            hash_alg: HASH_ALG_V2.into(),
            key_id: key_id.to_string(),
            agent_id: self.agent_id.clone(),
            change_no: self.change_no,
            from_state: self.from_state,
            to_state: self.to_state,
            reason_code: self.reason_code,
            reason_digest: self.reason_digest.clone(),
            changed_by: self.changed_by.clone(),
            approved_by: self.approved_by.clone(),
            changed_at: micros(self.changed_at),
            recorded_at: micros(now.utc),
            time_sync: now.sync.into(),
        }
    }

    /// Whether `record` is this change.
    #[must_use]
    pub fn matches(&self, record: &AgentStateRecord) -> bool {
        let p = &record.payload;
        p.tenant_id == self.tenant_id
            && p.agent_id == self.agent_id
            && p.change_no == self.change_no
            && p.from_state == self.from_state
            && p.to_state == self.to_state
            && p.reason_code == self.reason_code
            && p.reason_digest == self.reason_digest
            && p.changed_by == self.changed_by
            && p.approved_by == self.approved_by
    }
}

/// Hashes and signs an agent-state payload into a record.
pub fn seal_agent_state(
    payload: AgentStatePayload,
    signer: &dyn EvidenceSigner,
) -> Result<AgentStateRecord, PortError> {
    if payload.key_id != signer.key_id() {
        return Err(PortError::invalid("payload key_id differs from the signer"));
    }
    let hash = content_hash(&payload.prev_hash, &payload)?;
    let sig = hex::encode(signer.sign(&signing_message(&hash))?);
    Ok(AgentStateRecord { payload, hash, sig })
}

fn is_mac(s: &str) -> bool {
    s.strip_prefix("mac:")
        .is_some_and(|h| h.len() == 64 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

impl ChainEntry for AgentStateRecord {
    fn kind(&self) -> &str {
        &self.payload.kind
    }
    fn hash_alg(&self) -> &str {
        &self.payload.hash_alg
    }
    fn form(&self) -> Result<(), &'static str> {
        let p = &self.payload;
        if p.change_no < 1 {
            return Err("change_no starts at 1");
        }
        if p.from_state == p.to_state {
            return Err("a change from a state to itself is not a change");
        }
        if p.from_state == AgentState::Revoked {
            return Err("a revoked agent is never changed");
        }
        if p.reason_digest.as_deref().is_some_and(|d| !is_mac(d)) {
            return Err("reason_digest is not a well-formed digest");
        }
        match (
            p.from_state.loosens_to(p.to_state),
            p.approved_by.as_deref(),
        ) {
            (true, Some(approver)) if !approver.is_empty() && approver != p.changed_by => Ok(()),
            (true, _) => Err("a loosening needs an approver other than the changer"),
            (false, None) => Ok(()),
            (false, Some(_)) => Err("a change that tightens names no approver"),
        }
    }
    fn expected_kind(&self) -> &'static str {
        KIND_AGENT_STATE
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
    AgentState(AgentStateRecord),
}

impl ChainRecord {
    /// The decision, if this record is one.
    #[must_use]
    pub fn into_decision(self) -> Option<AgentDecisionRecord> {
        match self {
            Self::Decision(record) => Some(record),
            Self::Revocation(_) | Self::AgentState(_) => None,
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
            KIND_AGENT_STATE => serde_json::from_value(value)
                .map(Self::AgentState)
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
            Self::AgentState(r) => r.kind(),
        }
    }
    fn hash_alg(&self) -> &str {
        match self {
            Self::Decision(r) => r.hash_alg(),
            Self::Revocation(r) => r.hash_alg(),
            Self::AgentState(r) => r.hash_alg(),
        }
    }
    fn form(&self) -> Result<(), &'static str> {
        match self {
            Self::Decision(r) => r.form(),
            Self::Revocation(r) => r.form(),
            Self::AgentState(r) => r.form(),
        }
    }
    fn expected_kind(&self) -> &'static str {
        match self {
            Self::Decision(r) => r.expected_kind(),
            Self::Revocation(r) => r.expected_kind(),
            Self::AgentState(r) => r.expected_kind(),
        }
    }
    fn tenant_id(&self) -> &str {
        match self {
            Self::Decision(r) => r.tenant_id(),
            Self::Revocation(r) => r.tenant_id(),
            Self::AgentState(r) => r.tenant_id(),
        }
    }
    fn partition_id(&self) -> i32 {
        match self {
            Self::Decision(r) => r.partition_id(),
            Self::Revocation(r) => r.partition_id(),
            Self::AgentState(r) => r.partition_id(),
        }
    }
    fn seq(&self) -> i64 {
        match self {
            Self::Decision(r) => r.seq(),
            Self::Revocation(r) => r.seq(),
            Self::AgentState(r) => r.seq(),
        }
    }
    fn ts(&self) -> DateTime<Utc> {
        match self {
            Self::Decision(r) => r.ts(),
            Self::Revocation(r) => r.ts(),
            Self::AgentState(r) => r.ts(),
        }
    }
    fn prev_hash(&self) -> &str {
        match self {
            Self::Decision(r) => r.prev_hash(),
            Self::Revocation(r) => r.prev_hash(),
            Self::AgentState(r) => r.prev_hash(),
        }
    }
    fn key_id(&self) -> &str {
        match self {
            Self::Decision(r) => r.key_id(),
            Self::Revocation(r) => r.key_id(),
            Self::AgentState(r) => r.key_id(),
        }
    }
    fn time_sync(&self) -> &TimeSync {
        match self {
            Self::Decision(r) => r.time_sync(),
            Self::Revocation(r) => r.time_sync(),
            Self::AgentState(r) => r.time_sync(),
        }
    }
    fn hash(&self) -> &str {
        match self {
            Self::Decision(r) => r.hash(),
            Self::Revocation(r) => r.hash(),
            Self::AgentState(r) => r.hash(),
        }
    }
    fn sig(&self) -> &str {
        match self {
            Self::Decision(r) => r.sig(),
            Self::Revocation(r) => r.sig(),
            Self::AgentState(r) => r.sig(),
        }
    }
    fn content_hash(&self) -> Option<String> {
        match self {
            Self::Decision(r) => ChainEntry::content_hash(r),
            Self::Revocation(r) => ChainEntry::content_hash(r),
            Self::AgentState(r) => ChainEntry::content_hash(r),
        }
    }
    fn as_decision(&self) -> Option<&AgentDecisionRecord> {
        match self {
            Self::Decision(r) => Some(r),
            Self::Revocation(_) | Self::AgentState(_) => None,
        }
    }
}

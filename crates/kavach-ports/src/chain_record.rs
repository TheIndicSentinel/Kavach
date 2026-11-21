//! Records of the agent chain other than decisions, and a record of any
//! kind (ADR-012 §7, ADR-013).
//!
//! Every kind is hashed and signed like a decision (`v2` hash, the evidence
//! key, the same signing message) and takes its place in the same chain. The
//! kind is inside the signed payload, so a record cannot be passed off as
//! another kind, and a reader refuses a kind it does not know rather than
//! skipping it.

use chrono::{DateTime, DurationRound, TimeDelta, Utc};
use kavach_domain::{AgentState, Decision, ReasonCode};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

use crate::agent_evidence::{
    content_hash, signing_message, Actor, AgentDecisionRecord, ChainEntry, EvidenceSigner,
    PolicyVersions, TimeSync, HASH_ALG_V2, KIND_AGENT_DECISION, KIND_AGENT_STATE,
    KIND_MANDATE_REVOCATION,
};
use crate::error::PortError;
use crate::time::TrustedNow;

pub const KIND_EVIDENCE_TRANSITION: &str = "evidence_transition";
pub const KIND_MODEL_INVOCATION: &str = "model_invocation";
pub const KIND_MODEL_OUTCOME: &str = "model_outcome";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelOutcomeStatus {
    Completed,
    Failed,
    Unknown,
}

/// Signed digest-only result metadata linked to its prior model invocation.
/// Completion content itself is never included.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelOutcomePayload {
    pub record_id: String,
    pub tenant_id: String,
    pub partition_id: i32,
    pub seq: i64,
    pub prev_hash: String,
    pub kind: String,
    pub hash_alg: String,
    pub key_id: String,
    pub agent_id: String,
    pub request_id: String,
    pub invocation_record_id: String,
    pub invocation_hash: String,
    pub status: ModelOutcomeStatus,
    /// SHA-256 of transient completion text; present only for `completed`.
    pub response_digest: Option<String>,
    /// Elapsed model-call time in milliseconds, bounded by its u32 encoding.
    pub duration_ms: u32,
    pub time_sync: TimeSync,
    pub recorded_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelOutcomeRecord {
    #[serde(flatten)]
    pub payload: ModelOutcomePayload,
    pub hash: String,
    pub sig: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelOutcomeDraft {
    pub invocation: ModelInvocationRecord,
    pub status: ModelOutcomeStatus,
    pub response_digest: Option<String>,
    pub duration_ms: u32,
}

impl ModelOutcomeDraft {
    #[must_use]
    pub fn complete(
        &self,
        seq: i64,
        prev_hash: &str,
        key_id: &str,
        now: crate::time::TrustedNow,
    ) -> ModelOutcomePayload {
        let invocation = &self.invocation.payload;
        ModelOutcomePayload {
            record_id: format!(
                "mout:{}:{}:{seq}",
                invocation.tenant_id, invocation.partition_id
            ),
            tenant_id: invocation.tenant_id.clone(),
            partition_id: invocation.partition_id,
            seq,
            prev_hash: prev_hash.to_string(),
            kind: KIND_MODEL_OUTCOME.into(),
            hash_alg: HASH_ALG_V2.into(),
            key_id: key_id.to_string(),
            agent_id: invocation.actor.agent_id.clone(),
            request_id: invocation.request_id.clone(),
            invocation_record_id: invocation.record_id.clone(),
            invocation_hash: self.invocation.hash.clone(),
            status: self.status,
            response_digest: self.response_digest.clone(),
            duration_ms: self.duration_ms,
            time_sync: now.sync.into(),
            recorded_at: micros(now.utc),
        }
    }

    #[must_use]
    pub fn matches(&self, record: &ModelOutcomeRecord) -> bool {
        let p = &record.payload;
        p.tenant_id == self.invocation.payload.tenant_id
            && p.partition_id == self.invocation.payload.partition_id
            && p.agent_id == self.invocation.payload.actor.agent_id
            && p.request_id == self.invocation.payload.request_id
            && p.invocation_record_id == self.invocation.payload.record_id
            && p.invocation_hash == self.invocation.hash
            && p.status == self.status
            && p.response_digest == self.response_digest
            && p.duration_ms == self.duration_ms
    }
}

pub fn seal_model_outcome(
    payload: ModelOutcomePayload,
    signer: &dyn EvidenceSigner,
) -> Result<ModelOutcomeRecord, PortError> {
    if payload.key_id != signer.key_id() {
        return Err(PortError::invalid("payload key_id differs from the signer"));
    }
    let hash = content_hash(&payload.prev_hash, &payload)?;
    let sig = hex::encode(signer.sign(&signing_message(&hash))?);
    Ok(ModelOutcomeRecord { payload, hash, sig })
}

impl ChainEntry for ModelOutcomeRecord {
    fn kind(&self) -> &str {
        &self.payload.kind
    }
    fn hash_alg(&self) -> &str {
        &self.payload.hash_alg
    }
    fn form(&self) -> Result<(), &'static str> {
        let p = &self.payload;
        if p.record_id.is_empty()
            || p.record_id.len() > 128
            || p.tenant_id.is_empty()
            || p.tenant_id.len() > 128
            || p.tenant_id.chars().any(char::is_control)
            || p.partition_id < 0
            || p.seq < 1
            || (!is_hash(&p.prev_hash) && p.prev_hash != crate::agent_evidence::GENESIS)
            || p.agent_id.is_empty()
            || p.agent_id.len() > 128
            || p.request_id.is_empty()
            || p.request_id.len() > 128
            || p.invocation_record_id.is_empty()
            || p.invocation_record_id.len() > 128
            || !is_hash(&p.invocation_hash)
        {
            return Err("model outcome binding is invalid");
        }
        match (p.status, p.response_digest.as_deref()) {
            (ModelOutcomeStatus::Completed, Some(digest)) if is_hash(digest) => Ok(()),
            (ModelOutcomeStatus::Completed, _) => {
                Err("completed model outcome needs a response digest")
            }
            (_, None) => Ok(()),
            (_, Some(_)) => Err("non-completed model outcome cannot include a response digest"),
        }
    }
    fn expected_kind(&self) -> &'static str {
        KIND_MODEL_OUTCOME
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelInvocationRole {
    Collections,
    Translation,
}

impl ModelInvocationRole {
    pub const fn action(self) -> &'static str {
        match self {
            Self::Collections => "invoke_collections_model",
            Self::Translation => "invoke_translation_model",
        }
    }
}

/// Signed, digest-only authorization evidence written before a model call.
/// Prompt and completion text are deliberately absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelInvocationPayload {
    pub record_id: String,
    pub tenant_id: String,
    pub partition_id: i32,
    pub seq: i64,
    pub prev_hash: String,
    pub kind: String,
    pub hash_alg: String,
    pub key_id: String,
    pub actor: Actor,
    pub mandate_chain: Vec<String>,
    pub mandate_id: String,
    pub action: String,
    pub request_id: String,
    pub subject_pseudonym: String,
    pub model_role: ModelInvocationRole,
    /// `sha256:<lowercase hex>` of the pinned local model artifact.
    pub model_digest: String,
    /// Lowercase SHA-256 hex digest of transient prompt input.
    pub prompt_digest: String,
    pub policy_versions: PolicyVersions,
    pub policy_decision: Decision,
    pub returned_decision: Decision,
    /// Closed reason codes only; never free-form policy text.
    pub signals: Vec<String>,
    pub time_sync: TimeSync,
    pub recorded_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelInvocationRecord {
    #[serde(flatten)]
    pub payload: ModelInvocationPayload,
    pub hash: String,
    pub sig: String,
}

/// Input to the evidence-chain writer before sequence and trusted time are
/// assigned under the chain lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelInvocationDraft {
    pub tenant_id: String,
    pub partition_id: i32,
    pub actor: Actor,
    pub mandate_chain: Vec<String>,
    pub mandate_id: String,
    pub action: String,
    pub request_id: String,
    pub subject_pseudonym: String,
    pub model_role: ModelInvocationRole,
    pub model_digest: String,
    pub prompt_digest: String,
    pub policy_versions: PolicyVersions,
    pub policy_decision: Decision,
    pub returned_decision: Decision,
    pub signals: Vec<String>,
}

impl ModelInvocationDraft {
    #[must_use]
    pub fn complete(
        &self,
        seq: i64,
        prev_hash: &str,
        key_id: &str,
        now: TrustedNow,
    ) -> ModelInvocationPayload {
        ModelInvocationPayload {
            record_id: format!("minv:{}:{}:{seq}", self.tenant_id, self.partition_id),
            tenant_id: self.tenant_id.clone(),
            partition_id: self.partition_id,
            seq,
            prev_hash: prev_hash.to_string(),
            kind: KIND_MODEL_INVOCATION.into(),
            hash_alg: HASH_ALG_V2.into(),
            key_id: key_id.to_string(),
            actor: self.actor.clone(),
            mandate_chain: self.mandate_chain.clone(),
            mandate_id: self.mandate_id.clone(),
            action: self.action.clone(),
            request_id: self.request_id.clone(),
            subject_pseudonym: self.subject_pseudonym.clone(),
            model_role: self.model_role,
            model_digest: self.model_digest.clone(),
            prompt_digest: self.prompt_digest.clone(),
            policy_versions: self.policy_versions.clone(),
            policy_decision: self.policy_decision,
            returned_decision: self.returned_decision,
            signals: self.signals.clone(),
            time_sync: now.sync.into(),
            recorded_at: micros(now.utc),
        }
    }

    /// Whether a previously persisted record is the same invocation. Chain
    /// coordinates, trusted time and signature are assigned by the store and
    /// intentionally excluded from this comparison.
    #[must_use]
    pub fn matches(&self, record: &ModelInvocationRecord) -> bool {
        let p = &record.payload;
        p.tenant_id == self.tenant_id
            && p.partition_id == self.partition_id
            && p.actor == self.actor
            && p.mandate_chain == self.mandate_chain
            && p.mandate_id == self.mandate_id
            && p.action == self.action
            && p.request_id == self.request_id
            && p.subject_pseudonym == self.subject_pseudonym
            && p.model_role == self.model_role
            && p.model_digest == self.model_digest
            && p.prompt_digest == self.prompt_digest
            && p.policy_versions == self.policy_versions
            && p.policy_decision == self.policy_decision
            && p.returned_decision == self.returned_decision
            && p.signals == self.signals
    }
}

/// Hashes and signs a model invocation payload with the evidence key.
pub fn seal_model_invocation(
    payload: ModelInvocationPayload,
    signer: &dyn EvidenceSigner,
) -> Result<ModelInvocationRecord, PortError> {
    if payload.key_id != signer.key_id() {
        return Err(PortError::invalid("payload key_id differs from the signer"));
    }
    let hash = content_hash(&payload.prev_hash, &payload)?;
    let sig = hex::encode(signer.sign(&signing_message(&hash))?);
    Ok(ModelInvocationRecord { payload, hash, sig })
}

impl ChainEntry for ModelInvocationRecord {
    fn kind(&self) -> &str {
        &self.payload.kind
    }
    fn hash_alg(&self) -> &str {
        &self.payload.hash_alg
    }
    fn form(&self) -> Result<(), &'static str> {
        let p = &self.payload;
        if p.record_id.is_empty()
            || p.record_id.len() > 128
            || p.record_id.chars().any(char::is_control)
            || p.tenant_id.is_empty()
            || p.tenant_id.len() > 128
            || p.tenant_id.chars().any(char::is_control)
            || p.partition_id < 0
            || p.seq < 1
            || (!is_hash(&p.prev_hash) && p.prev_hash != crate::agent_evidence::GENESIS)
        {
            return Err("model invocation chain coordinates are invalid");
        }
        let mandate_binding_valid = if p.mandate_chain.is_empty() {
            p.policy_decision == Decision::Block
                && p.returned_decision == Decision::Block
                && p.signals.iter().any(|signal| {
                    matches!(
                        signal.as_str(),
                        "mandate_invalid" | "dependency_unavailable"
                    )
                })
        } else {
            p.mandate_chain.iter().all(|id| !id.is_empty())
                && p.mandate_chain.last().map(String::as_str) == Some(p.mandate_id.as_str())
        };
        if p.actor.agent_id.is_empty()
            || p.actor.identity_key.is_empty()
            || p.mandate_id.is_empty()
            || !mandate_binding_valid
            || p.action != p.model_role.action()
            || p.request_id.is_empty()
            || p.request_id.len() > 128
            || p.request_id.chars().any(char::is_control)
            || p.subject_pseudonym.is_empty()
            || p.subject_pseudonym.len() > 256
        {
            return Err("model invocation authorization binding is invalid");
        }
        if !p.model_digest.strip_prefix("sha256:").is_some_and(is_hash)
            || !is_hash(&p.prompt_digest)
        {
            return Err("model invocation digests are invalid");
        }
        Ok(())
    }
    fn expected_kind(&self) -> &'static str {
        KIND_MODEL_INVOCATION
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
    /// The change request that carried out a loosening (ADR-009), so the
    /// record ties the change to its proposal and approval. Absent for an
    /// operator's stop. Written only when present, so a record without it
    /// hashes as it always did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_request_id: Option<String>,
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
    pub change_request_id: Option<String>,
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
            change_request_id: self.change_request_id.clone(),
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
            && p.change_request_id == self.change_request_id
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
        if let Some(id) = &p.change_request_id {
            if id.is_empty() || id.len() > 128 || id.chars().any(char::is_control) {
                return Err("change_request_id is not a plain identifier of 1 to 128 characters");
            }
            if !p.from_state.loosens_to(p.to_state) {
                return Err("only a loosening is carried out by a change request");
            }
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

/// Signed cutover record preserving both pre-M2 chain tips without rewriting
/// either history. It extends the legacy credit chain; the old agent tip is
/// committed as an independently verifiable branch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceTransitionPayload {
    pub record_id: String,
    pub tenant_id: String,
    pub partition_id: i32,
    pub seq: i64,
    pub prev_hash: String,
    pub kind: String,
    pub hash_alg: String,
    pub key_id: String,
    pub decision_event_head_seq: i64,
    pub decision_event_head_hash: String,
    pub legacy_agent_head_seq: i64,
    pub legacy_agent_head_hash: String,
    pub time_sync: TimeSync,
    pub recorded_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceTransitionRecord {
    #[serde(flatten)]
    pub payload: EvidenceTransitionPayload,
    pub hash: String,
    pub sig: String,
}

/// Hashes and signs the migration transition using the regular v2 evidence
/// domain and dedicated evidence signer.
pub fn seal_evidence_transition(
    payload: EvidenceTransitionPayload,
    signer: &dyn EvidenceSigner,
) -> Result<EvidenceTransitionRecord, PortError> {
    if payload.key_id != signer.key_id() {
        return Err(PortError::invalid("payload key_id differs from the signer"));
    }
    let hash = content_hash(&payload.prev_hash, &payload)?;
    let sig = hex::encode(signer.sign(&signing_message(&hash))?);
    Ok(EvidenceTransitionRecord { payload, hash, sig })
}

fn is_hash(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_chain_tip(seq: i64, hash: &str) -> bool {
    if seq == 0 {
        hash == crate::agent_evidence::GENESIS
    } else {
        seq > 0 && is_hash(hash)
    }
}

impl ChainEntry for EvidenceTransitionRecord {
    fn kind(&self) -> &str {
        &self.payload.kind
    }
    fn hash_alg(&self) -> &str {
        &self.payload.hash_alg
    }
    fn form(&self) -> Result<(), &'static str> {
        let p = &self.payload;
        if p.record_id.is_empty()
            || p.record_id.len() > 128
            || p.record_id.chars().any(char::is_control)
        {
            return Err("record_id must be a plain identifier of 1 to 128 characters");
        }
        if p.tenant_id.is_empty()
            || p.tenant_id.len() > 128
            || p.tenant_id.chars().any(char::is_control)
        {
            return Err("tenant_id must be a plain identifier of 1 to 128 characters");
        }
        if p.partition_id < 0 || p.seq < 1 || !is_hash(&p.prev_hash) {
            return Err("transition chain coordinates or previous hash are invalid");
        }
        if p.decision_event_head_seq.checked_add(1) != Some(p.seq)
            || p.decision_event_head_hash != p.prev_hash
        {
            return Err("transition must extend the recorded decision-event head");
        }
        if !is_chain_tip(p.decision_event_head_seq, &p.decision_event_head_hash)
            || !is_chain_tip(p.legacy_agent_head_seq, &p.legacy_agent_head_hash)
        {
            return Err("legacy chain tip must have a valid sequence and hash");
        }
        Ok(())
    }
    fn expected_kind(&self) -> &'static str {
        KIND_EVIDENCE_TRANSITION
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
    EvidenceTransition(EvidenceTransitionRecord),
    ModelInvocation(ModelInvocationRecord),
    ModelOutcome(ModelOutcomeRecord),
}

impl ChainRecord {
    /// The decision, if this record is one.
    #[must_use]
    pub fn into_decision(self) -> Option<AgentDecisionRecord> {
        match self {
            Self::Decision(record) => Some(record),
            Self::Revocation(_)
            | Self::AgentState(_)
            | Self::EvidenceTransition(_)
            | Self::ModelInvocation(_)
            | Self::ModelOutcome(_) => None,
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
            KIND_EVIDENCE_TRANSITION => serde_json::from_value(value)
                .map(Self::EvidenceTransition)
                .map_err(D::Error::custom),
            KIND_MODEL_INVOCATION => serde_json::from_value(value)
                .map(Self::ModelInvocation)
                .map_err(D::Error::custom),
            KIND_MODEL_OUTCOME => serde_json::from_value(value)
                .map(Self::ModelOutcome)
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
            Self::EvidenceTransition(r) => r.kind(),
            Self::ModelInvocation(r) => r.kind(),
            Self::ModelOutcome(r) => r.kind(),
        }
    }
    fn hash_alg(&self) -> &str {
        match self {
            Self::Decision(r) => r.hash_alg(),
            Self::Revocation(r) => r.hash_alg(),
            Self::AgentState(r) => r.hash_alg(),
            Self::EvidenceTransition(r) => r.hash_alg(),
            Self::ModelInvocation(r) => r.hash_alg(),
            Self::ModelOutcome(r) => r.hash_alg(),
        }
    }
    fn form(&self) -> Result<(), &'static str> {
        match self {
            Self::Decision(r) => r.form(),
            Self::Revocation(r) => r.form(),
            Self::AgentState(r) => r.form(),
            Self::EvidenceTransition(r) => r.form(),
            Self::ModelInvocation(r) => r.form(),
            Self::ModelOutcome(r) => r.form(),
        }
    }
    fn expected_kind(&self) -> &'static str {
        match self {
            Self::Decision(r) => r.expected_kind(),
            Self::Revocation(r) => r.expected_kind(),
            Self::AgentState(r) => r.expected_kind(),
            Self::EvidenceTransition(r) => r.expected_kind(),
            Self::ModelInvocation(r) => r.expected_kind(),
            Self::ModelOutcome(r) => r.expected_kind(),
        }
    }
    fn tenant_id(&self) -> &str {
        match self {
            Self::Decision(r) => r.tenant_id(),
            Self::Revocation(r) => r.tenant_id(),
            Self::AgentState(r) => r.tenant_id(),
            Self::EvidenceTransition(r) => r.tenant_id(),
            Self::ModelInvocation(r) => r.tenant_id(),
            Self::ModelOutcome(r) => r.tenant_id(),
        }
    }
    fn partition_id(&self) -> i32 {
        match self {
            Self::Decision(r) => r.partition_id(),
            Self::Revocation(r) => r.partition_id(),
            Self::AgentState(r) => r.partition_id(),
            Self::EvidenceTransition(r) => r.partition_id(),
            Self::ModelInvocation(r) => r.partition_id(),
            Self::ModelOutcome(r) => r.partition_id(),
        }
    }
    fn seq(&self) -> i64 {
        match self {
            Self::Decision(r) => r.seq(),
            Self::Revocation(r) => r.seq(),
            Self::AgentState(r) => r.seq(),
            Self::EvidenceTransition(r) => r.seq(),
            Self::ModelInvocation(r) => r.seq(),
            Self::ModelOutcome(r) => r.seq(),
        }
    }
    fn ts(&self) -> DateTime<Utc> {
        match self {
            Self::Decision(r) => r.ts(),
            Self::Revocation(r) => r.ts(),
            Self::AgentState(r) => r.ts(),
            Self::EvidenceTransition(r) => r.ts(),
            Self::ModelInvocation(r) => r.ts(),
            Self::ModelOutcome(r) => r.ts(),
        }
    }
    fn prev_hash(&self) -> &str {
        match self {
            Self::Decision(r) => r.prev_hash(),
            Self::Revocation(r) => r.prev_hash(),
            Self::AgentState(r) => r.prev_hash(),
            Self::EvidenceTransition(r) => r.prev_hash(),
            Self::ModelInvocation(r) => r.prev_hash(),
            Self::ModelOutcome(r) => r.prev_hash(),
        }
    }
    fn key_id(&self) -> &str {
        match self {
            Self::Decision(r) => r.key_id(),
            Self::Revocation(r) => r.key_id(),
            Self::AgentState(r) => r.key_id(),
            Self::EvidenceTransition(r) => r.key_id(),
            Self::ModelInvocation(r) => r.key_id(),
            Self::ModelOutcome(r) => r.key_id(),
        }
    }
    fn time_sync(&self) -> &TimeSync {
        match self {
            Self::Decision(r) => r.time_sync(),
            Self::Revocation(r) => r.time_sync(),
            Self::AgentState(r) => r.time_sync(),
            Self::EvidenceTransition(r) => r.time_sync(),
            Self::ModelInvocation(r) => r.time_sync(),
            Self::ModelOutcome(r) => r.time_sync(),
        }
    }
    fn hash(&self) -> &str {
        match self {
            Self::Decision(r) => r.hash(),
            Self::Revocation(r) => r.hash(),
            Self::AgentState(r) => r.hash(),
            Self::EvidenceTransition(r) => r.hash(),
            Self::ModelInvocation(r) => r.hash(),
            Self::ModelOutcome(r) => r.hash(),
        }
    }
    fn sig(&self) -> &str {
        match self {
            Self::Decision(r) => r.sig(),
            Self::Revocation(r) => r.sig(),
            Self::AgentState(r) => r.sig(),
            Self::EvidenceTransition(r) => r.sig(),
            Self::ModelInvocation(r) => r.sig(),
            Self::ModelOutcome(r) => r.sig(),
        }
    }
    fn content_hash(&self) -> Option<String> {
        match self {
            Self::Decision(r) => ChainEntry::content_hash(r),
            Self::Revocation(r) => ChainEntry::content_hash(r),
            Self::AgentState(r) => ChainEntry::content_hash(r),
            Self::EvidenceTransition(r) => ChainEntry::content_hash(r),
            Self::ModelInvocation(r) => ChainEntry::content_hash(r),
            Self::ModelOutcome(r) => ChainEntry::content_hash(r),
        }
    }
    fn as_decision(&self) -> Option<&AgentDecisionRecord> {
        match self {
            Self::Decision(r) => Some(r),
            Self::Revocation(_)
            | Self::AgentState(_)
            | Self::EvidenceTransition(_)
            | Self::ModelInvocation(_)
            | Self::ModelOutcome(_) => None,
        }
    }
}

#[cfg(test)]
mod evidence_transition_tests {
    use super::*;
    use crate::agent_evidence::{verify_segment, DevKeys, EvidenceSigner, SegmentStart, GENESIS};
    use crate::{KeyAlgorithm, PublicKey};
    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::BTreeMap;

    struct TestSigner(SigningKey);

    impl EvidenceSigner for TestSigner {
        fn key_id(&self) -> &'static str {
            "evidence-m2"
        }
        fn sign(&self, message: &[u8]) -> Result<Vec<u8>, PortError> {
            Ok(self.0.sign(message).to_bytes().to_vec())
        }
    }

    fn transition_payload() -> EvidenceTransitionPayload {
        EvidenceTransitionPayload {
            record_id: "m2-transition-default-0".into(),
            tenant_id: "default".into(),
            partition_id: 0,
            seq: 8,
            prev_hash: "a".repeat(64),
            kind: KIND_EVIDENCE_TRANSITION.into(),
            hash_alg: HASH_ALG_V2.into(),
            key_id: "evidence-m2".into(),
            decision_event_head_seq: 7,
            decision_event_head_hash: "a".repeat(64),
            legacy_agent_head_seq: 5,
            legacy_agent_head_hash: "b".repeat(64),
            time_sync: crate::SyncStatus::Synced { max_error_ms: 2 }.into(),
            recorded_at: DateTime::from_timestamp(1_795_000_000, 0).unwrap(),
        }
    }

    #[test]
    fn transition_binds_both_legacy_tips_and_verifies_as_a_chain_record() {
        let signer = TestSigner(SigningKey::from_bytes(&[7; 32]));
        let record = seal_evidence_transition(transition_payload(), &signer).unwrap();
        let key = PublicKey {
            kid: "evidence-m2".into(),
            algorithm: KeyAlgorithm::Ed25519,
            bytes: signer.0.verifying_key().to_bytes(),
        };
        let keys = BTreeMap::from([(key.kid.clone(), key)]);
        let credit_head = "a".repeat(64);
        let report = verify_segment(
            std::slice::from_ref(&record),
            SegmentStart {
                seq: 7,
                hash: &credit_head,
            },
            &keys,
            Some((record.payload.seq, &record.hash)),
            &[],
            record.payload.recorded_at,
            DevKeys::Refuse,
        )
        .unwrap();
        assert_eq!(report.head_seq, 8);
        assert_eq!(report.head_hash, record.hash);

        let parsed: ChainRecord =
            serde_json::from_value(serde_json::to_value(record).unwrap()).unwrap();
        assert!(matches!(parsed, ChainRecord::EvidenceTransition(_)));
    }

    #[test]
    fn transition_refuses_a_tip_that_does_not_match_its_chain_predecessor() {
        let signer = TestSigner(SigningKey::from_bytes(&[7; 32]));
        let mut payload = transition_payload();
        payload.decision_event_head_hash = GENESIS.into();
        let record = seal_evidence_transition(payload, &signer).unwrap();
        assert_eq!(
            record.form(),
            Err("transition must extend the recorded decision-event head")
        );
    }

    #[test]
    fn transition_supports_an_empty_legacy_agent_chain() {
        let signer = TestSigner(SigningKey::from_bytes(&[7; 32]));
        let mut payload = transition_payload();
        payload.legacy_agent_head_seq = 0;
        payload.legacy_agent_head_hash = GENESIS.into();
        assert!(seal_evidence_transition(payload, &signer)
            .unwrap()
            .form()
            .is_ok());
    }

    fn model_invocation_draft() -> ModelInvocationDraft {
        ModelInvocationDraft {
            tenant_id: "default".into(),
            partition_id: 0,
            actor: Actor {
                agent_id: "collections-agent".into(),
                identity_key: "oidc:https://idp#collections-agent".into(),
            },
            mandate_chain: vec!["mandate-1".into()],
            mandate_id: "mandate-1".into(),
            action: "invoke_collections_model".into(),
            request_id: "model-req-1".into(),
            subject_pseudonym: "psn:subject-1".into(),
            model_role: ModelInvocationRole::Collections,
            model_digest: format!("sha256:{}", "a".repeat(64)),
            prompt_digest: "b".repeat(64),
            policy_versions: PolicyVersions {
                cedar: "sha256:cedar".into(),
                cel: None,
                packs: Vec::new(),
                tools: Some("sha256:tools".into()),
                build: "kavach-tests".into(),
            },
            policy_decision: Decision::Pass,
            returned_decision: Decision::Pass,
            signals: vec!["authorized".into()],
        }
    }

    #[test]
    fn model_invocation_is_digest_only_signed_and_round_trips_as_a_chain_record() {
        let signer = TestSigner(SigningKey::from_bytes(&[7; 32]));
        let timestamp = DateTime::from_timestamp(1_795_000_000, 0).unwrap();
        let payload = model_invocation_draft().complete(
            1,
            GENESIS,
            "evidence-m2",
            crate::TrustedNow {
                utc: timestamp,
                sync: crate::SyncStatus::Synced { max_error_ms: 2 },
            },
        );
        let record = seal_model_invocation(payload, &signer).unwrap();
        assert!(record.form().is_ok());
        let encoded = serde_json::to_string(&record).unwrap();
        assert!(!encoded.contains("prompt text"));
        assert!(encoded.contains(&"b".repeat(64)));

        let parsed: ChainRecord = serde_json::from_str(&encoded).unwrap();
        assert!(matches!(parsed, ChainRecord::ModelInvocation(_)));

        let key = PublicKey {
            kid: "evidence-m2".into(),
            algorithm: KeyAlgorithm::Ed25519,
            bytes: signer.0.verifying_key().to_bytes(),
        };
        let keys = BTreeMap::from([(key.kid.clone(), key)]);
        let report = verify_segment(
            std::slice::from_ref(&record),
            SegmentStart {
                seq: 0,
                hash: GENESIS,
            },
            &keys,
            Some((1, &record.hash)),
            &[],
            timestamp,
            DevKeys::Refuse,
        )
        .unwrap();
        assert_eq!(report.head_hash, record.hash);
    }

    #[test]
    fn model_invocation_rejects_wrong_action_for_role() {
        let signer = TestSigner(SigningKey::from_bytes(&[7; 32]));
        let mut payload = model_invocation_draft().complete(
            1,
            GENESIS,
            "evidence-m2",
            crate::TrustedNow {
                utc: DateTime::from_timestamp(1_795_000_000, 0).unwrap(),
                sync: crate::SyncStatus::Synced { max_error_ms: 2 },
            },
        );
        payload.action = "invoke_translation_model".into();
        assert_eq!(
            seal_model_invocation(payload, &signer).unwrap().form(),
            Err("model invocation authorization binding is invalid")
        );
    }

    #[test]
    fn blocked_invocation_can_record_a_mandate_verification_refusal() {
        let signer = TestSigner(SigningKey::from_bytes(&[7; 32]));
        let now = crate::TrustedNow {
            utc: DateTime::from_timestamp(1_795_000_000, 0).unwrap(),
            sync: crate::SyncStatus::Synced { max_error_ms: 2 },
        };
        let mut draft = model_invocation_draft();
        draft.mandate_chain.clear();
        draft.mandate_id = "expired-mandate".into();
        draft.policy_decision = Decision::Block;
        draft.returned_decision = Decision::Block;
        draft.signals = vec!["mandate_invalid".into()];
        let payload = draft.complete(1, GENESIS, "evidence-m2", now);
        assert!(seal_model_invocation(payload, &signer)
            .unwrap()
            .form()
            .is_ok());

        draft.signals = vec!["authorized".into()];
        let payload = draft.complete(1, GENESIS, "evidence-m2", now);
        assert_eq!(
            seal_model_invocation(payload, &signer).unwrap().form(),
            Err("model invocation authorization binding is invalid")
        );

        draft.signals = vec!["mandate_invalid".into()];
        draft.returned_decision = Decision::Pass;
        let payload = draft.complete(1, GENESIS, "evidence-m2", now);
        assert_eq!(
            seal_model_invocation(payload, &signer).unwrap().form(),
            Err("model invocation authorization binding is invalid")
        );

        draft.returned_decision = Decision::Block;
        draft.mandate_id.clear();
        let payload = draft.complete(1, GENESIS, "evidence-m2", now);
        assert_eq!(
            seal_model_invocation(payload, &signer).unwrap().form(),
            Err("model invocation authorization binding is invalid")
        );
    }

    #[test]
    fn model_invocation_rejects_malformed_digests() {
        let signer = TestSigner(SigningKey::from_bytes(&[7; 32]));
        let now = crate::TrustedNow {
            utc: DateTime::from_timestamp(1_795_000_000, 0).unwrap(),
            sync: crate::SyncStatus::Synced { max_error_ms: 2 },
        };
        let mut payload = model_invocation_draft().complete(1, GENESIS, "evidence-m2", now);
        payload.prompt_digest = "not-a-digest".into();
        assert_eq!(
            seal_model_invocation(payload, &signer).unwrap().form(),
            Err("model invocation digests are invalid")
        );

        let mut payload = model_invocation_draft().complete(1, GENESIS, "evidence-m2", now);
        payload.model_digest = "granite3.3:2b".into();
        assert_eq!(
            seal_model_invocation(payload, &signer).unwrap().form(),
            Err("model invocation digests are invalid")
        );
    }

    #[test]
    fn model_outcome_is_signed_digest_only_and_linked_to_its_invocation() {
        let signer = TestSigner(SigningKey::from_bytes(&[7; 32]));
        let now = crate::TrustedNow {
            utc: DateTime::from_timestamp(1_795_000_000, 0).unwrap(),
            sync: crate::SyncStatus::Synced { max_error_ms: 2 },
        };
        let invocation = seal_model_invocation(
            model_invocation_draft().complete(1, GENESIS, "evidence-m2", now),
            &signer,
        )
        .unwrap();
        let draft = ModelOutcomeDraft {
            invocation: invocation.clone(),
            status: ModelOutcomeStatus::Completed,
            response_digest: Some("c".repeat(64)),
            duration_ms: 1_250,
        };
        let record = seal_model_outcome(
            draft.complete(2, &invocation.hash, "evidence-m2", now),
            &signer,
        )
        .unwrap();
        assert!(record.form().is_ok());
        let encoded = serde_json::to_string(&record).unwrap();
        assert!(!encoded.contains("completion text"));
        assert!(encoded.contains(&"c".repeat(64)));
        assert_eq!(
            record.payload.invocation_record_id,
            invocation.payload.record_id
        );
        assert_eq!(record.payload.invocation_hash, invocation.hash);
        assert!(matches!(
            serde_json::from_str::<ChainRecord>(&encoded).unwrap(),
            ChainRecord::ModelOutcome(_)
        ));
        let key = PublicKey {
            kid: "evidence-m2".into(),
            algorithm: KeyAlgorithm::Ed25519,
            bytes: signer.0.verifying_key().to_bytes(),
        };
        let keys = BTreeMap::from([(key.kid.clone(), key)]);
        let chain_record = ChainRecord::ModelOutcome(record.clone());
        let report = verify_segment(
            std::slice::from_ref(&chain_record),
            SegmentStart {
                seq: 1,
                hash: &invocation.hash,
            },
            &keys,
            Some((2, &record.hash)),
            &[],
            now.utc,
            DevKeys::Refuse,
        )
        .unwrap();
        assert_eq!(report.head_hash, record.hash);

        let unknown = ModelOutcomeDraft {
            invocation: invocation.clone(),
            status: ModelOutcomeStatus::Unknown,
            response_digest: None,
            duration_ms: 30_000,
        };
        let unknown = seal_model_outcome(
            unknown.complete(2, &invocation.hash, "evidence-m2", now),
            &signer,
        )
        .unwrap();
        assert!(unknown.form().is_ok());

        let invalid = ModelOutcomeDraft {
            invocation,
            status: ModelOutcomeStatus::Completed,
            response_digest: None,
            duration_ms: 1,
        };
        let invalid =
            seal_model_outcome(invalid.complete(2, GENESIS, "evidence-m2", now), &signer).unwrap();
        assert_eq!(
            invalid.form(),
            Err("completed model outcome needs a response digest")
        );
    }
}

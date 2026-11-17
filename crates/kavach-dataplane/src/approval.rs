//! Exact-action binding for the M4 human-review workflow (PRD D17 / FR-6).
//!
//! This computes a digest only. It does not create or validate an approval,
//! change an authorization decision, or issue a credential.

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::{Zeroize, Zeroizing};

use crate::authorize::{AgentIdentity, ToolCall};

const ACTION_HASH_DOMAIN: &[u8] = b"kavach-human-review-action-v1\0";
const ACTION_HASH_PREFIX: &str = "sha256-action-v1:";
const SNAPSHOT_VERSION: u8 = 1;
const SNAPSHOT_DOMAIN: &[u8] = b"kavach-human-review-snapshot-v1\0";
const MAX_SNAPSHOT_BYTES: usize = 64 * 1024;

/// The minimum action projection needed to render and recheck one HUMAN_REVIEW
/// decision. This value must only be persisted inside [`EncryptedReviewSnapshot`].
#[derive(Clone, PartialEq, Eq)]
pub struct ReviewActionSnapshot {
    pub tenant_id: String,
    pub agent_id: String,
    pub identity_key: String,
    pub tool_registry_digest: String,
    pub mandate_id: String,
    pub request_id: String,
    pub action: String,
    pub subject_ref: String,
    pub channel: Option<String>,
    pub waiver_bps: Option<i64>,
    pub requested_fields: BTreeSet<String>,
    pub parameters: BTreeMap<String, String>,
}

/// Private wire representation: the cleartext projection cannot be serialized
/// directly by downstream callers.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewSnapshotPayload {
    tenant_id: String,
    agent_id: String,
    identity_key: String,
    tool_registry_digest: String,
    mandate_id: String,
    request_id: String,
    action: String,
    subject_ref: String,
    channel: Option<String>,
    waiver_bps: Option<i64>,
    requested_fields: BTreeSet<String>,
    parameters: BTreeMap<String, String>,
}

impl From<&ReviewActionSnapshot> for ReviewSnapshotPayload {
    fn from(snapshot: &ReviewActionSnapshot) -> Self {
        Self {
            tenant_id: snapshot.tenant_id.clone(),
            agent_id: snapshot.agent_id.clone(),
            identity_key: snapshot.identity_key.clone(),
            tool_registry_digest: snapshot.tool_registry_digest.clone(),
            mandate_id: snapshot.mandate_id.clone(),
            request_id: snapshot.request_id.clone(),
            action: snapshot.action.clone(),
            subject_ref: snapshot.subject_ref.clone(),
            channel: snapshot.channel.clone(),
            waiver_bps: snapshot.waiver_bps,
            requested_fields: snapshot.requested_fields.clone(),
            parameters: snapshot.parameters.clone(),
        }
    }
}

impl ReviewSnapshotPayload {
    fn action_hash(&self) -> Result<String, kavach_ports::PortError> {
        hash_binding(&ActionHashBinding {
            version: 1,
            tenant_id: &self.tenant_id,
            agent_id: &self.agent_id,
            identity_key: &self.identity_key,
            tool_registry_digest: &self.tool_registry_digest,
            mandate_id: &self.mandate_id,
            request_id: &self.request_id,
            action: &self.action,
            subject_ref: &self.subject_ref,
            channel: &self.channel,
            waiver_bps: self.waiver_bps,
            requested_fields: &self.requested_fields,
            parameters: &self.parameters,
        })
    }

    fn into_snapshot(mut self) -> ReviewActionSnapshot {
        ReviewActionSnapshot {
            tenant_id: std::mem::take(&mut self.tenant_id),
            agent_id: std::mem::take(&mut self.agent_id),
            identity_key: std::mem::take(&mut self.identity_key),
            tool_registry_digest: std::mem::take(&mut self.tool_registry_digest),
            mandate_id: std::mem::take(&mut self.mandate_id),
            request_id: std::mem::take(&mut self.request_id),
            action: std::mem::take(&mut self.action),
            subject_ref: std::mem::take(&mut self.subject_ref),
            channel: self.channel.take(),
            waiver_bps: self.waiver_bps,
            requested_fields: std::mem::take(&mut self.requested_fields),
            parameters: std::mem::take(&mut self.parameters),
        }
    }
}

impl Drop for ReviewSnapshotPayload {
    fn drop(&mut self) {
        for value in [
            &mut self.tenant_id,
            &mut self.agent_id,
            &mut self.identity_key,
            &mut self.tool_registry_digest,
            &mut self.mandate_id,
            &mut self.request_id,
            &mut self.action,
            &mut self.subject_ref,
        ] {
            value.zeroize();
        }
        if let Some(channel) = &mut self.channel {
            channel.zeroize();
        }
        for mut field in std::mem::take(&mut self.requested_fields) {
            field.zeroize();
        }
        for (mut name, mut value) in std::mem::take(&mut self.parameters) {
            name.zeroize();
            value.zeroize();
        }
    }
}

impl ReviewActionSnapshot {
    /// Captures the inputs used by the exact-action hash. Extraction violations
    /// fail closed and cannot produce a review snapshot.
    pub fn from_request(
        tenant_id: &str,
        agent: &AgentIdentity,
        tool_registry_digest: &str,
        call: &ToolCall,
    ) -> Result<Self, kavach_ports::PortError> {
        if !call.violations.is_empty() {
            return Err(kavach_ports::PortError::rejected(
                "action with extraction violations cannot be snapshotted for review",
            ));
        }
        Ok(Self {
            tenant_id: tenant_id.to_owned(),
            agent_id: agent.agent_id.clone(),
            identity_key: agent.identity_key.clone(),
            tool_registry_digest: tool_registry_digest.to_owned(),
            mandate_id: call.mandate_id.clone(),
            request_id: call.request_id.clone(),
            action: call.action.clone(),
            subject_ref: call.subject_ref.clone(),
            channel: call.channel.clone(),
            waiver_bps: call.waiver_bps,
            requested_fields: call.requested_fields.clone(),
            parameters: call.extra.clone(),
        })
    }

    /// Recomputes the versioned action digest to prove the stored projection
    /// still describes the signed HUMAN_REVIEW record.
    pub fn action_hash(&self) -> Result<String, kavach_ports::PortError> {
        hash_binding(&ActionHashBinding {
            version: 1,
            tenant_id: &self.tenant_id,
            agent_id: &self.agent_id,
            identity_key: &self.identity_key,
            tool_registry_digest: &self.tool_registry_digest,
            mandate_id: &self.mandate_id,
            request_id: &self.request_id,
            action: &self.action,
            subject_ref: &self.subject_ref,
            channel: &self.channel,
            waiver_bps: self.waiver_bps,
            requested_fields: &self.requested_fields,
            parameters: &self.parameters,
        })
    }
}

impl Drop for ReviewActionSnapshot {
    fn drop(&mut self) {
        for value in [
            &mut self.tenant_id,
            &mut self.agent_id,
            &mut self.identity_key,
            &mut self.tool_registry_digest,
            &mut self.mandate_id,
            &mut self.request_id,
            &mut self.action,
            &mut self.subject_ref,
        ] {
            value.zeroize();
        }
        if let Some(channel) = &mut self.channel {
            channel.zeroize();
        }
        for mut field in std::mem::take(&mut self.requested_fields) {
            field.zeroize();
        }
        for (mut name, mut value) in std::mem::take(&mut self.parameters) {
            name.zeroize();
            value.zeroize();
        }
    }
}

/// AES-256-GCM encrypted review projection. Header values are authenticated as
/// associated data; ciphertext is safe to persist but is not a signature.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedReviewSnapshot {
    pub version: u8,
    pub key_id: String,
    pub tenant_id: String,
    pub record_id: String,
    pub action_hash: String,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

impl EncryptedReviewSnapshot {
    /// Authenticates and encrypts the snapshot using AES-256-GCM. The key is
    /// supplied by the storage integration and must be stable across restarts.
    pub fn seal(
        snapshot: &ReviewActionSnapshot,
        key_id: &str,
        record_id: &str,
        action_hash: &str,
        key: &[u8; 32],
    ) -> Result<Self, kavach_ports::PortError> {
        if key_id.is_empty()
            || key_id.len() > 128
            || key_id.chars().any(char::is_control)
            || record_id.is_empty()
            || snapshot.action_hash()? != action_hash
        {
            return Err(kavach_ports::PortError::rejected(
                "review snapshot does not match its action digest",
            ));
        }
        let payload = ReviewSnapshotPayload::from(snapshot);
        let mut plaintext = Zeroizing::new(kavach_ports::jcs::to_vec(&payload)?);
        if plaintext.len() > MAX_SNAPSHOT_BYTES {
            return Err(kavach_ports::PortError::invalid(
                "review snapshot exceeds its size limit",
            ));
        }
        let unbound = UnboundKey::new(&AES_256_GCM, key)
            .map_err(|_| kavach_ports::PortError::invalid("invalid review snapshot key"))?;
        let cipher = LessSafeKey::new(unbound);
        let mut nonce = [0u8; 12];
        SystemRandom::new().fill(&mut nonce).map_err(|_| {
            kavach_ports::PortError::unavailable("review snapshot randomness failed")
        })?;
        let aad = snapshot_aad(key_id, &snapshot.tenant_id, record_id, action_hash)?;
        cipher
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad.as_slice()),
                &mut *plaintext,
            )
            .map_err(|_| {
                kavach_ports::PortError::unavailable("review snapshot encryption failed")
            })?;
        Ok(Self {
            version: SNAPSHOT_VERSION,
            key_id: key_id.to_owned(),
            tenant_id: snapshot.tenant_id.clone(),
            record_id: record_id.to_owned(),
            action_hash: action_hash.to_owned(),
            nonce,
            ciphertext: plaintext.to_vec(),
        })
    }

    /// Decrypts only when all caller-supplied scope values match the
    /// authenticated envelope. Plaintext is zeroized when this returns.
    pub fn open(
        &self,
        expected_key_id: &str,
        tenant_id: &str,
        record_id: &str,
        action_hash: &str,
        key: &[u8; 32],
    ) -> Result<ReviewActionSnapshot, kavach_ports::PortError> {
        if self.version != SNAPSHOT_VERSION
            || self.key_id != expected_key_id
            || self.tenant_id != tenant_id
            || self.record_id != record_id
            || self.action_hash != action_hash
            || self.ciphertext.len() > MAX_SNAPSHOT_BYTES + 16
        {
            return Err(kavach_ports::PortError::rejected(
                "review snapshot scope or version is invalid",
            ));
        }
        let unbound = UnboundKey::new(&AES_256_GCM, key)
            .map_err(|_| kavach_ports::PortError::invalid("invalid review snapshot key"))?;
        let cipher = LessSafeKey::new(unbound);
        let aad = snapshot_aad(expected_key_id, tenant_id, record_id, action_hash)?;
        let mut plaintext = Zeroizing::new(self.ciphertext.clone());
        let bytes = cipher
            .open_in_place(
                Nonce::assume_unique_for_key(self.nonce),
                Aad::from(aad.as_slice()),
                &mut plaintext,
            )
            .map_err(|_| {
                kavach_ports::PortError::rejected("review snapshot authentication failed")
            })?;
        let payload: ReviewSnapshotPayload = serde_json::from_slice(bytes)
            .map_err(|_| kavach_ports::PortError::rejected("review snapshot payload is invalid"))?;
        if payload.tenant_id != tenant_id || payload.action_hash()? != action_hash {
            return Err(kavach_ports::PortError::rejected(
                "review snapshot does not match its action digest",
            ));
        }
        Ok(payload.into_snapshot())
    }
}

fn snapshot_aad(
    key_id: &str,
    tenant_id: &str,
    record_id: &str,
    action_hash: &str,
) -> Result<Vec<u8>, kavach_ports::PortError> {
    let mut aad = Vec::from(SNAPSHOT_DOMAIN);
    for value in [
        key_id.as_bytes(),
        tenant_id.as_bytes(),
        record_id.as_bytes(),
        action_hash.as_bytes(),
    ] {
        let length = u32::try_from(value.len())
            .map_err(|_| kavach_ports::PortError::invalid("review snapshot scope is too long"))?;
        aad.extend_from_slice(&length.to_be_bytes());
        aad.extend_from_slice(value);
    }
    Ok(aad)
}

#[derive(Serialize)]
struct ActionHashBinding<'a> {
    version: u8,
    tenant_id: &'a str,
    agent_id: &'a str,
    identity_key: &'a str,
    tool_registry_digest: &'a str,
    mandate_id: &'a str,
    request_id: &'a str,
    action: &'a str,
    subject_ref: &'a str,
    channel: &'a Option<String>,
    waiver_bps: Option<i64>,
    requested_fields: &'a std::collections::BTreeSet<String>,
    parameters: &'a std::collections::BTreeMap<String, String>,
}

/// Produces a deterministic digest for one extracted, human-review action.
///
/// The canonical bytes contain the action parameters transiently and are
/// zeroized after hashing; only the tagged digest is returned. The request id
/// makes approvals specific to one recorded attempt, while the registry
/// digest binds the action to the tool contract used to extract it.
pub fn review_action_hash(
    tenant_id: &str,
    agent: &AgentIdentity,
    tool_registry_digest: &str,
    call: &ToolCall,
) -> Result<String, kavach_ports::PortError> {
    if !call.violations.is_empty() {
        return Err(kavach_ports::PortError::invalid(
            "action with extraction violations cannot be submitted for review",
        ));
    }
    let binding = ActionHashBinding {
        version: 1,
        tenant_id,
        agent_id: &agent.agent_id,
        identity_key: &agent.identity_key,
        tool_registry_digest,
        mandate_id: &call.mandate_id,
        request_id: &call.request_id,
        action: &call.action,
        subject_ref: &call.subject_ref,
        channel: &call.channel,
        waiver_bps: call.waiver_bps,
        requested_fields: &call.requested_fields,
        parameters: &call.extra,
    };
    hash_binding(&binding)
}

fn hash_binding(binding: &ActionHashBinding<'_>) -> Result<String, kavach_ports::PortError> {
    let canonical = Zeroizing::new(kavach_ports::jcs::to_vec(binding)?);
    let mut hasher = Sha256::new();
    hasher.update(ACTION_HASH_DOMAIN);
    hasher.update(canonical.as_slice());
    Ok(format!("{ACTION_HASH_PREFIX}{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    fn identity() -> AgentIdentity {
        AgentIdentity {
            agent_id: "collections-agent".into(),
            identity_key: "issuer:subject-1".into(),
        }
    }

    fn call() -> ToolCall {
        ToolCall {
            mandate_id: "mandate-1".into(),
            action: "propose_plan".into(),
            request_id: "request-1".into(),
            approval_id: None,
            subject_ref: "ref:borrower:B-9382".into(),
            channel: None,
            waiver_bps: Some(3500),
            requested_fields: BTreeSet::new(),
            extra: BTreeMap::new(),
            violations: Vec::new(),
        }
    }

    #[test]
    fn encrypted_snapshot_round_trips_and_authenticates_tenant_record_and_action() {
        let snapshot =
            ReviewActionSnapshot::from_request("tenant-1", &identity(), "sha256:tools-1", &call())
                .unwrap();
        let action_hash = snapshot.action_hash().unwrap();
        let key = [7u8; 32];
        let sealed = EncryptedReviewSnapshot::seal(
            &snapshot,
            "review-key-v1",
            "adr:tenant-1:0:1",
            &action_hash,
            &key,
        )
        .unwrap();
        assert!(!sealed
            .ciphertext
            .windows(snapshot.subject_ref.len())
            .any(|window| window == snapshot.subject_ref.as_bytes()));
        assert!(
            sealed
                .open(
                    "review-key-v1",
                    "tenant-1",
                    "adr:tenant-1:0:1",
                    &action_hash,
                    &key
                )
                .unwrap()
                == snapshot
        );
        assert!(sealed
            .open(
                "review-key-v1",
                "tenant-2",
                "adr:tenant-1:0:1",
                &action_hash,
                &key
            )
            .is_err());
        assert!(sealed
            .open(
                "review-key-v2",
                "tenant-1",
                "adr:tenant-1:0:1",
                &action_hash,
                &key
            )
            .is_err());
        assert!(sealed
            .open(
                "review-key-v1",
                "tenant-1",
                "adr:tenant-1:0:2",
                &action_hash,
                &key
            )
            .is_err());
        let mut altered = sealed;
        altered.ciphertext[0] ^= 1;
        assert!(altered
            .open(
                "review-key-v1",
                "tenant-1",
                "adr:tenant-1:0:1",
                &action_hash,
                &key
            )
            .is_err());
    }

    #[test]
    fn snapshot_sealing_refuses_an_unbound_action_digest() {
        let snapshot =
            ReviewActionSnapshot::from_request("tenant-1", &identity(), "sha256:tools-1", &call())
                .unwrap();
        assert!(EncryptedReviewSnapshot::seal(
            &snapshot,
            "review-key-v1",
            "adr:tenant-1:0:1",
            &format!("sha256-action-v1:{}", "b".repeat(64)),
            &[7u8; 32],
        )
        .is_err());
    }

    #[test]
    fn review_action_hash_is_stable_and_tagged() {
        let first = review_action_hash("tenant-1", &identity(), "sha256:tools-1", &call()).unwrap();
        let second =
            review_action_hash("tenant-1", &identity(), "sha256:tools-1", &call()).unwrap();
        assert_eq!(first, second);
        assert!(first.starts_with(ACTION_HASH_PREFIX));
        assert_eq!(first.len(), ACTION_HASH_PREFIX.len() + 64);
    }

    #[test]
    fn approval_id_does_not_change_the_exact_action_hash() {
        let mut with_approval = call();
        let original =
            review_action_hash("tenant-1", &identity(), "sha256:tools-1", &with_approval)
                .expect("original hash");
        with_approval.approval_id = Some("approval-1".into());
        assert_eq!(
            review_action_hash("tenant-1", &identity(), "sha256:tools-1", &with_approval)
                .expect("hash with approval"),
            original
        );
    }

    #[test]
    fn changing_any_bound_identity_or_action_input_changes_the_hash() {
        let identity = identity();
        let call = call();
        let baseline = review_action_hash("tenant-1", &identity, "sha256:tools-1", &call).unwrap();

        let changed = review_action_hash("tenant-2", &identity, "sha256:tools-1", &call).unwrap();
        assert_ne!(baseline, changed, "tenant is bound");
        let changed = review_action_hash("tenant-1", &identity, "sha256:tools-2", &call).unwrap();
        assert_ne!(baseline, changed, "tool registry is bound");

        let mut changed_identity = identity.clone();
        changed_identity.agent_id.push_str("-other");
        let changed =
            review_action_hash("tenant-1", &changed_identity, "sha256:tools-1", &call).unwrap();
        assert_ne!(baseline, changed, "agent is bound");
        changed_identity.identity_key.push_str(":other");
        let changed =
            review_action_hash("tenant-1", &changed_identity, "sha256:tools-1", &call).unwrap();
        assert_ne!(baseline, changed, "authenticated identity is bound");

        let mut changed_call = call.clone();
        changed_call.waiver_bps = Some(3501);
        let changed =
            review_action_hash("tenant-1", &identity, "sha256:tools-1", &changed_call).unwrap();
        assert_ne!(baseline, changed, "action parameters are bound");
        changed_call.waiver_bps = Some(3500);
        changed_call.request_id.push_str("-other");
        let changed =
            review_action_hash("tenant-1", &identity, "sha256:tools-1", &changed_call).unwrap();
        assert_ne!(baseline, changed, "request attempt is bound");
        changed_call.request_id = call.request_id.clone();
        changed_call.mandate_id.push_str("-other");
        let changed =
            review_action_hash("tenant-1", &identity, "sha256:tools-1", &changed_call).unwrap();
        assert_ne!(baseline, changed, "mandate is bound");
        changed_call.mandate_id = call.mandate_id.clone();
        changed_call.action.push_str("-other");
        let changed =
            review_action_hash("tenant-1", &identity, "sha256:tools-1", &changed_call).unwrap();
        assert_ne!(baseline, changed, "action is bound");
        changed_call.action = call.action.clone();
        changed_call.subject_ref.push_str("-other");
        let changed =
            review_action_hash("tenant-1", &identity, "sha256:tools-1", &changed_call).unwrap();
        assert_ne!(baseline, changed, "subject is bound");
        changed_call.subject_ref = call.subject_ref.clone();
        changed_call.channel = Some("sms".into());
        let changed =
            review_action_hash("tenant-1", &identity, "sha256:tools-1", &changed_call).unwrap();
        assert_ne!(baseline, changed, "channel is bound");
        changed_call.channel = call.channel.clone();
        changed_call.requested_fields.insert("balance".into());
        let changed =
            review_action_hash("tenant-1", &identity, "sha256:tools-1", &changed_call).unwrap();
        assert_ne!(baseline, changed, "requested fields are bound");
        changed_call.requested_fields = call.requested_fields.clone();
        changed_call
            .extra
            .insert("purpose".into(), "reminder".into());
        let changed =
            review_action_hash("tenant-1", &identity, "sha256:tools-1", &changed_call).unwrap();
        assert_ne!(baseline, changed, "typed parameters are bound");
    }

    #[test]
    fn refuses_actions_with_extraction_violations() {
        let mut call = call();
        call.violations
            .push("reference_only_violation:subject_ref".into());
        assert!(review_action_hash("tenant-1", &identity(), "sha256:tools-1", &call).is_err());
    }
}

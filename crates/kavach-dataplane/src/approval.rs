//! Exact-action binding for the M4 human-review workflow (PRD D17 / FR-6).
//!
//! This computes a digest only. It does not create or validate an approval,
//! change an authorization decision, or issue a credential.

use serde::Serialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::authorize::{AgentIdentity, ToolCall};

const ACTION_HASH_DOMAIN: &[u8] = b"kavach-human-review-action-v1\0";
const ACTION_HASH_PREFIX: &str = "sha256-action-v1:";

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
    let canonical = Zeroizing::new(kavach_ports::jcs::to_vec(&binding)?);
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
            subject_ref: "ref:borrower:B-9382".into(),
            channel: None,
            waiver_bps: Some(3500),
            requested_fields: BTreeSet::new(),
            extra: BTreeMap::new(),
            violations: Vec::new(),
        }
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

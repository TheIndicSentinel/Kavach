// Response bodies typed from openapi.d.ts, so a spec change breaks the tests.
import type { AgentDecisionLookup, AgentStateView, RevocationLookup } from "../lib/api";

export const neverChanged: AgentStateView = {
  agent_id: "agent:collections-bot",
  state: "active",
  change_no: 0,
};

export const quarantined: AgentStateView = {
  agent_id: "agent:payments-bot",
  state: "quarantined",
  change_no: 3,
  reason_code: "compromise_suspected",
  note: "key seen on a paste site",
  changed_by: "operator-1",
  approved_by: null,
  change_request_id: null,
  changed_at: "2026-11-14T10:00:00Z",
};

export const reinstated: AgentStateView = {
  agent_id: "agent:kyc-bot",
  state: "restricted",
  change_no: 4,
  reason_code: "reviewed",
  changed_by: "admin-1",
  approved_by: "admin-2",
  change_request_id: "cr-0042",
  changed_at: "2026-11-14T11:30:00Z",
};

export const decisionLookup: AgentDecisionLookup = {
  record: {
    record_id: "adr:bank-1:0:42",
    tenant_id: "bank-1",
    partition_id: 0,
    seq: 42,
    prev_hash: "prevhash0",
    kind: "agent_decision",
    hash_alg: "sha256-jcs-v1",
    key_id: "evidence-key-1",
    actor: { agent_id: "agent:payments-bot", identity_key: "idkey" },
    chain: ["mandate-root"],
    mandate_id: "mandate-7",
    purpose: "collections",
    consent_refs: [],
    action: "send_reminder",
    request_id: "rq-1",
    subject_pseudonym: "subj-pseudo-1",
    params_mac: null,
    policy_versions: { cedar: "c1", cel: null, packs: [], build: "b1" },
    signals: [],
    pre_commit_decision: "PASS",
    policy_decision: "PASS",
    returned_decision: "BLOCK",
    obligations: [],
    credential_id: null,
    credential_expires_at: null,
    send_by: null,
    time_sync: { status: "synced", max_error_ms: 5 },
    ts: "2026-11-14T09:00:00Z",
    hash: "recordhash42",
    sig: "sig42",
  },
  outcome: null,
};

export const revocationLookup: RevocationLookup = {
  record: {
    record_id: "adr:bank-1:0:43",
    tenant_id: "bank-1",
    partition_id: 0,
    seq: 43,
    prev_hash: "recordhash42",
    kind: "mandate_revocation",
    hash_alg: "sha256-jcs-v1",
    key_id: "evidence-key-1",
    source_system: "los-core",
    event_id: "evt-9",
    event_digest: "sha256-jcs-v1:abc",
    event_type: "loan_closed",
    record_pseudonym: "loan-pseudo-1",
    occurred_at: "2026-11-14T08:00:00Z",
    revoked: ["mandate-7", "mandate-8"],
    revoked_at: "2026-11-14T08:00:01Z",
    recorded_at: "2026-11-14T08:00:02Z",
    time_sync: { status: "synced", max_error_ms: 5 },
    hash: "recordhash43",
    sig: "sig43",
  },
};

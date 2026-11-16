// Response bodies for the browser tests, typed from the generated OpenAPI
// types, so a spec change that these bodies no longer match fails typecheck.
import type { components } from "../src/lib/openapi";
import {
  neverChanged,
  quarantineApplied,
  quarantined,
  reinstated,
  reinstateProposed,
} from "../src/test/fixtures";
import { decisionLookup, revocationLookup, revokeHalfway } from "../src/test/fixtures";
import {
  EVIDENCE_ID,
  cleanReconciliation,
  decisionEvent,
  reconciliation,
} from "../src/test/evidenceFixtures";

type Schemas = components["schemas"];

export const runtime: Schemas["RuntimeView"] = {
  pack_id: "finance-core",
  pack_version: "1.4.0",
  model_id: "credit-risk",
  model_version: "2.1.0",
  sector: "finance",
  governance_mode: "enforce",
  pack_path: "packs/finance-core.yaml",
  model_path: "models/credit-risk.yaml",
  pack_sha256: "a1b2c3",
  pointer_version: 7,
  model_sha256: "d4e5f6",
  model_pack_mismatch: false,
  stored_pointer_version: 7,
  pointer_drift: false,
  insecure_dev: true,
  require_hardening: false,
  agent_only: false,
  relaxations: ["insecure_dev", "principal_header", "memory_evidence_store"],
  checkpoint_lag_seconds: 12,
  checkpoint_stalled: false,
  checkpoint_last_seq: 40,
  checkpoint_uncovered_records: 2,
};

export const packSummary: Schemas["PackSummary"] = {
  id: "finance-core",
  version: "1.4.0",
  sector: "finance",
  jurisdiction: "IN",
  effective_from: "2026-10-01T00:00:00Z",
  rule_count: 1,
  source_path: "packs/finance-core.yaml",
  active: true,
};

export const pack: Schemas["PolicyPack"] = {
  id: "finance-core",
  version: "1.4.0",
  sector: "finance",
  jurisdiction: "IN",
  effective_from: "2026-10-01T00:00:00Z",
  description: "Rules for the sample credit model.",
  rules: [
    {
      id: "income-floor",
      expression: "input.monthly_income_inr >= 15000",
      decision: "BLOCK",
      reason_code: "INCOME_BELOW_FLOOR",
      severity: "high",
    },
  ],
};

export const modelSummary: Schemas["ModelSummary"] = {
  model_id: "credit-risk",
  version: "2.1.0",
  sector: "finance",
  status: "production",
  risk_tier: "high",
  governance_mode: "enforce",
  origin: "in_house",
  pack_id: "finance-core",
  owner: "risk-team",
  source_path: "models/credit-risk.yaml",
  active: true,
  governed: true,
};

export const model: Schemas["ModelDetail"] = {
  model_id: "credit-risk",
  version: "2.1.0",
  sector: "finance",
  owner: "risk-team",
  risk_tier: "high",
  origin: "in_house",
  governance_mode: "enforce",
  input_schema: { type: "object" },
  human_review_hold_policy: null,
  status: "production",
  pack_id: "finance-core",
  purpose: "Credit decision support",
  governed: true,
};

export const auditEntry: Schemas["AuditEntry"] = {
  id: 1,
  action: "activate_pack",
  resource_type: "pack",
  resource_id: "finance-core",
  actor_principal: "admin-1",
  approver_principal: "approver-1",
  payload: {},
  created_at: "2026-11-14T10:00:00Z",
  acting_as_superadmin: false,
};

export const incident: Schemas["IncidentRecord"] = {
  id: 1,
  correlation_id: "corr-77",
  model_id: "credit-risk",
  reason: "evidence store unavailable",
  recorded_at: "2026-11-14T10:05:00Z",
};

export const batchJob: Schemas["BatchJobRecord"] = {
  job_id: "job-1",
  status: "completed",
  input_path: "in/job-1.ndjson",
  output_path: "out/job-1.ndjson",
  model_id: "credit-risk",
  governance_mode: "shadow",
  total_rows: 10,
  processed_rows: 10,
  succeeded_rows: 9,
  failed_rows: 1,
  skipped_rows: 0,
  error_summary: null,
  created_at: "2026-11-14T09:00:00Z",
  started_at: "2026-11-14T09:00:01Z",
  completed_at: "2026-11-14T09:00:05Z",
};

export const retention: Schemas["RetentionSettings"] = {
  evidence_retention_days: 2555,
  updated_at: "2026-11-01T00:00:00Z",
  updated_by: "admin-1",
  approved_by: "approver-1",
};

export const tombstone: Schemas["TombstoneRecord"] = {
  evidence_id: "ev-123",
  reason: "retention",
  actor_principal: "admin-1",
  approver_principal: "approver-1",
  tombstoned_at: "2026-11-02T00:00:00Z",
};

export const agentPage: Schemas["AgentStatePage"] = {
  items: [neverChanged, quarantined, reinstated],
  next_cursor: null,
};

export const forbidden: Schemas["Problem"] = {
  type: "/problems/forbidden",
  title: "Forbidden",
  status: 403,
  detail: "The principal may not do this.",
  code: "forbidden",
  request_id: "req-e2e-403",
  error: "The principal may not do this.",
};

/** `GET /auth/config`: console login configured. */
export const authConfigLogin: Schemas["ConsoleAuthConfig"] = { login_configured: true, pasted_token_allowed: false };

/** `GET /auth/config`: no console login, --insecure-dev (the development fallback). */
export const authConfigDev: Schemas["ConsoleAuthConfig"] = { login_configured: false, pasted_token_allowed: true };

/** `GET /auth/config`: no console login and no fallback. */
export const authConfigNone: Schemas["ConsoleAuthConfig"] = { login_configured: false, pasted_token_allowed: false };

/** A session whose token names the Cedar group `operators` (the API passes it to Cedar as it is). */
export const authSession: Schemas["ConsoleSession"] = {
  principal: "oidc-operator-7",
  groups: ["operators"],
  expires_at: "2026-11-15T18:00:00Z",
  idle_expires_at: "2026-11-15T10:15:00Z",
};

/** A viewers-only session: the role hints take the place of the stop and approve controls. */
export const viewerSession: Schemas["ConsoleSession"] = {
  ...authSession,
  principal: "oidc-viewer-3",
  groups: ["viewers"],
};

/** An admin and change approver: every control shows. */
export const approverSession: Schemas["ConsoleSession"] = {
  ...authSession,
  principal: "oidc-admin-2",
  groups: ["admins", "change-approvers"],
};

export const logoutLocal: Schemas["ConsoleLogout"] = { end_session_url: null };

/** The 401 problem `GET /auth/session` and every call answer when no session is live. */
export const noSession: Schemas["Problem"] = {
  type: "/problems/unauthorized",
  title: "Unauthorized",
  status: 401,
  detail: "No live console session.",
  code: "unauthorized",
  request_id: "req-e2e-401",
  error: "No live console session.",
};

export { neverChanged, quarantineApplied, reinstateProposed };

// UI-4 part 2: the states the axe and keyboard checks reach.

export { decisionLookup, revocationLookup, revokeHalfway, quarantined, reinstated };
export { EVIDENCE_ID, cleanReconciliation, decisionEvent, reconciliation };

/** A revoked agent: only "Repeat revoke" is left. */
export const revokedAgent: Schemas["AgentStateView"] = {
  agent_id: "agent:old-bot",
  state: "revoked",
  change_no: 5,
  reason_code: "compromise_suspected",
  changed_by: "operator-1",
  approved_by: null,
  change_request_id: null,
  changed_at: "2026-11-13T08:00:00Z",
};

/** What restricting agent:collections-bot returns. */
export const restrictApplied: Schemas["AgentStopResult"] = {
  ...quarantineApplied,
  state: "restricted",
  reason_code: "operator_request",
};

export const notFound: Schemas["Problem"] = {
  type: "/problems/not_found",
  title: "Not Found",
  status: 404,
  detail: "No such record.",
  code: "not_found",
  request_id: "req-e2e-404",
  error: "No such record.",
};

export const rateLimited: Schemas["Problem"] = {
  type: "/problems/rate_limited",
  title: "Too Many Requests",
  status: 429,
  detail: "Too many lookups: wait and try again.",
  code: "rate_limited",
  request_id: "req-e2e-429",
  error: "Too many lookups: wait and try again.",
};

export const evaluateResult: Schemas["EvaluateResponse"] = {
  policy_decision: "BLOCK",
  returned_decision: "BLOCK",
  evidence_id: EVIDENCE_ID,
  reason_codes: ["INCOME_BELOW_FLOOR"],
  policy_hits: ["income-floor"],
  latency_ms: 3,
};

/** The fixture's pending reinstatement once decided by admin-2 (or cancelled by its proposer). */
export function reinstateDecided(status: Schemas["ChangeStatus"]): Schemas["ChangeRequest"] {
  return {
    ...reinstateProposed,
    status,
    decided_by: status === "cancelled" ? reinstateProposed.proposer : "admin-2",
    decided_at: "2026-11-15T10:00:00Z",
  };
}

/** Two pages of agents, for paging: the first names a cursor to the second. */
export const agentPageOne: Schemas["AgentStatePage"] = {
  items: [neverChanged, reinstated],
  next_cursor: "cursor-page-2",
};

export const agentPageTwo: Schemas["AgentStatePage"] = {
  items: [quarantined],
  next_cursor: null,
};

/** `GET /v1/me`: the current caller has no Kavach roles bound. */
export const meNoRoles: Schemas["Me"] = { principal: "dev", roles: [] };

/** One read-only page of the Users & roles directory. */
export const principalPage: Schemas["PrincipalPage"] = {
  items: [
    {
      issuer: "https://idp.example.test",
      subject: "oidc-admin-2",
      display_name: "Asha Rao",
      first_seen_at: "2026-11-01T09:00:00Z",
      last_seen_at: "2026-11-15T09:30:00Z",
    },
  ],
  next_cursor: "principal-page-2",
};

export const principalPageTwo: Schemas["PrincipalPage"] = {
  items: [
    {
      issuer: "https://idp.example.test",
      subject: "oidc-auditor-5",
      display_name: "Asha Rao (contractor)",
      first_seen_at: "2026-11-02T09:00:00Z",
      last_seen_at: "2026-11-14T16:00:00Z",
    },
  ],
  next_cursor: null,
};

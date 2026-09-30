const PRINCIPAL_KEY = "kavach.principal";
const TOKEN_KEY = "kavach.accessToken";

/** OIDC access token from the bank IdP (ADR-008). Kept in sessionStorage only. */
export function getAccessToken(): string {
  return sessionStorage.getItem(TOKEN_KEY) ?? "";
}

export function setAccessToken(value: string): void {
  if (value.trim()) {
    sessionStorage.setItem(TOKEN_KEY, value.trim());
  } else {
    sessionStorage.removeItem(TOKEN_KEY);
  }
}

export function getPrincipal(): string {
  return sessionStorage.getItem(PRINCIPAL_KEY) ?? "";
}

export function setPrincipal(value: string): void {
  if (value.trim()) {
    sessionStorage.setItem(PRINCIPAL_KEY, value.trim());
  } else {
    sessionStorage.removeItem(PRINCIPAL_KEY);
  }
}

/**
 * Bearer token when configured; otherwise the self-asserted principal header,
 * which the API accepts only in --insecure-dev (development).
 */
function authHeaders(): Record<string, string> {
  const token = getAccessToken();
  if (token) {
    return { Authorization: `Bearer ${token}` };
  }
  const principal = getPrincipal();
  return principal ? { "X-Kavach-Principal": principal } : {};
}

export class ApiError extends Error {
  readonly status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

export async function fetchHealth(): Promise<{ status: string }> {
  const response = await fetch("/health", { headers: authHeaders() });
  if (!response.ok) {
    throw new ApiError(`Health check failed (${response.status})`, response.status);
  }
  return response.json() as Promise<{ status: string }>;
}

export type EvaluateResponse = {
  returned_decision: string;
  policy_decision: string;
  evidence_id?: string;
  reason_codes: string[];
  policy_hits: string[];
};

export async function evaluateRequest(
  body: unknown,
): Promise<EvaluateResponse> {
  const response = await fetch("/v1/evaluate", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...authHeaders(),
    },
    body: JSON.stringify(body),
  });
  const payload = await response.json();
  if (!response.ok) {
    const message =
      typeof payload?.error === "string"
        ? payload.error
        : `Evaluate failed (${response.status})`;
    throw new ApiError(message, response.status);
  }
  return payload as EvaluateResponse;
}

export type RuntimeInfo = {
  pack_id: string;
  pack_version: string;
  model_id: string;
  model_version: string;
  sector: string;
  governance_mode: string;
  pack_path: string;
  model_path: string;
  pack_sha256?: string | null;
  model_sha256?: string | null;
  pointer_version?: number;
  stored_pointer_version?: number;
  pointer_drift?: boolean;
  /** The active model names a different pack than the one running (ADR-010). */
  model_pack_mismatch?: boolean;
};

export type PackSummary = {
  id: string;
  version: string;
  sector: string;
  jurisdiction: string;
  effective_from: string;
  rule_count: number;
  source_path: string;
  active: boolean;
  /** False: no governed state yet; activate it with an activate_model change. */
  governed: boolean;
};

export type PolicyPack = {
  id: string;
  version: string;
  sector: string;
  jurisdiction: string;
  effective_from: string;
  description?: string;
  rules: Array<{
    id: string;
    expression: string;
    decision: string;
    reason_code: string;
    severity?: string;
    control_mappings?: string[];
  }>;
  control_mappings?: Record<string, string>;
};

export type ModelSummary = {
  model_id: string;
  version: string;
  sector: string;
  status: string;
  risk_tier: string;
  governance_mode: string;
  origin: string;
  pack_id: string;
  owner: string;
  source_path: string;
  active: boolean;
};

export type ModelRecord = {
  model_id: string;
  version: string;
  sector: string;
  owner: string;
  risk_tier: string;
  origin: string;
  governance_mode: string;
  input_schema: Record<string, unknown>;
  human_review_hold_policy?: string;
  status: string;
  pack_id: string;
  purpose: string;
  governed?: boolean;
};

async function governanceFetch<T>(path: string): Promise<T> {
  const response = await fetch(path, { headers: authHeaders() });
  const payload = await response.json();
  if (!response.ok) {
    const message =
      typeof payload?.error === "string"
        ? payload.error
        : `Request failed (${response.status})`;
    throw new ApiError(message, response.status);
  }
  return payload as T;
}

export function fetchRuntime(): Promise<RuntimeInfo> {
  return governanceFetch("/v1/runtime");
}

export function fetchPacks(): Promise<PackSummary[]> {
  return governanceFetch("/v1/packs");
}

export function fetchPack(packId: string): Promise<PolicyPack> {
  return governanceFetch(`/v1/packs/${encodeURIComponent(packId)}`);
}

export function fetchModels(): Promise<ModelSummary[]> {
  return governanceFetch("/v1/models");
}

export function fetchModel(modelId: string): Promise<ModelRecord> {
  return governanceFetch(`/v1/models/${encodeURIComponent(modelId)}`);
}

export type AuditEntry = {
  id: number;
  action: string;
  resource_type: string;
  resource_id: string;
  actor_principal: string;
  approver_principal: string;
  payload: Record<string, unknown>;
  created_at: string;
};

export function fetchAuditLog(limit = 50): Promise<AuditEntry[]> {
  return governanceFetch(`/v1/admin/audit?limit=${limit}`);
}

export type IncidentRecord = {
  id: number;
  correlation_id: string;
  model_id: string;
  reason: string;
  recorded_at: string;
};

export function fetchIncidents(limit = 50): Promise<IncidentRecord[]> {
  return governanceFetch(`/v1/admin/incidents?limit=${limit}`);
}

export type BatchJob = {
  job_id: string;
  status: string;
  input_path: string;
  output_path?: string | null;
  model_id: string;
  governance_mode: string;
  total_rows: number;
  processed_rows: number;
  succeeded_rows: number;
  failed_rows: number;
  skipped_rows: number;
  error_summary?: string | null;
  created_at: string;
  started_at?: string | null;
  completed_at?: string | null;
};

export function fetchBatchJobs(limit = 50): Promise<BatchJob[]> {
  return governanceFetch(`/v1/admin/batch-jobs?limit=${limit}`);
}

export function fetchBatchJob(jobId: string): Promise<BatchJob> {
  return governanceFetch(`/v1/admin/batch-jobs/${encodeURIComponent(jobId)}`);
}

export interface RetentionSettings {
  evidence_retention_days: number;
  updated_at: string;
  updated_by?: string | null;
  approved_by?: string | null;
}

export interface TombstoneRecord {
  evidence_id: string;
  reason: string;
  actor_principal: string;
  approver_principal: string;
  tombstoned_at: string;
}

export interface RetentionApplyReport {
  tombstoned_count: number;
  evidence_ids: string[];
}

export function fetchRetentionSettings(): Promise<RetentionSettings> {
  return governanceFetch("/v1/admin/retention");
}

export function fetchTombstones(limit = 50): Promise<TombstoneRecord[]> {
  return governanceFetch(`/v1/admin/tombstones?limit=${limit}`);
}

export type ChangeKind =
  | "activate_pack"
  | "rollback_pack"
  | "update_model"
  | "update_retention"
  | "erase_evidence"
  | "apply_retention"
  | "activate_model";

export type ChangeStatus =
  | "pending"
  | "applied"
  | "failed"
  | "rejected"
  | "cancelled"
  | "expired";

/** A maker-checker change request (ADR-009). */
export interface ChangeRequest {
  id: string;
  kind: ChangeKind;
  params: Record<string, unknown>;
  binding: Record<string, unknown>;
  change_digest: string;
  reason?: string | null;
  proposer: string;
  status: ChangeStatus;
  decided_by?: string | null;
  outcome?: Record<string, unknown> | null;
  created_at: string;
  expires_at: string;
  decided_at?: string | null;
}

async function changeFetch<T>(path: string, body?: unknown): Promise<T> {
  const response = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...authHeaders() },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const payload = await response.json();
  if (!response.ok) {
    const message =
      typeof payload?.error === "string"
        ? payload.error
        : `Request failed (${response.status})`;
    throw new ApiError(message, response.status);
  }
  return payload as T;
}

/** Proposes a governance change; a different principal must approve it. */
export function proposeChange(
  kind: ChangeKind,
  params: Record<string, unknown> = {},
  reason?: string,
): Promise<ChangeRequest> {
  return changeFetch("/v1/change-requests", { kind, params, reason });
}

export function fetchChangeRequests(
  status?: ChangeStatus,
  limit = 50,
): Promise<ChangeRequest[]> {
  const query = status ? `status=${status}&limit=${limit}` : `limit=${limit}`;
  return governanceFetch(`/v1/change-requests?${query}`);
}

/** Approving applies the change. The digest must match what was reviewed. */
export function approveChange(request: ChangeRequest): Promise<ChangeRequest> {
  return changeFetch(
    `/v1/change-requests/${encodeURIComponent(request.id)}/approve`,
    { change_digest: request.change_digest },
  );
}

export function rejectChange(id: string, reason?: string): Promise<ChangeRequest> {
  return changeFetch(`/v1/change-requests/${encodeURIComponent(id)}/reject`, {
    reason,
  });
}

export function cancelChange(id: string): Promise<ChangeRequest> {
  return changeFetch(`/v1/change-requests/${encodeURIComponent(id)}/cancel`);
}

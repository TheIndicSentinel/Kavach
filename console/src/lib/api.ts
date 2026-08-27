const PRINCIPAL_KEY = "kavach.principal";
const APPROVER_KEY = "kavach.approver";

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

export function getApprover(): string {
  return sessionStorage.getItem(APPROVER_KEY) ?? "";
}

export function setApprover(value: string): void {
  if (value.trim()) {
    sessionStorage.setItem(APPROVER_KEY, value.trim());
  } else {
    sessionStorage.removeItem(APPROVER_KEY);
  }
}

function authHeaders(): HeadersInit {
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

function dualControlHeaders(actor: string, approver: string): HeadersInit {
  return {
    "X-Kavach-Principal": actor,
    "X-Kavach-Approver": approver,
  };
}

export function fetchAuditLog(limit = 50): Promise<AuditEntry[]> {
  return governanceFetch(`/v1/admin/audit?limit=${limit}`);
}

export function activatePack(
  packId: string,
  actor: string,
  approver: string,
): Promise<RuntimeInfo> {
  return fetch(`/v1/packs/${encodeURIComponent(packId)}/activate`, {
    method: "POST",
    headers: dualControlHeaders(actor, approver),
  }).then(async (response) => {
    const payload = await response.json();
    if (!response.ok) {
      throw new ApiError(
        typeof payload?.error === "string" ? payload.error : "Activate failed",
        response.status,
      );
    }
    return payload as RuntimeInfo;
  });
}

export function rollbackPack(
  actor: string,
  approver: string,
): Promise<RuntimeInfo> {
  return fetch("/v1/packs/rollback", {
    method: "POST",
    headers: dualControlHeaders(actor, approver),
  }).then(async (response) => {
    const payload = await response.json();
    if (!response.ok) {
      throw new ApiError(
        typeof payload?.error === "string" ? payload.error : "Rollback failed",
        response.status,
      );
    }
    return payload as RuntimeInfo;
  });
}

export function updateModel(
  modelId: string,
  body: { status?: string; governance_mode?: string },
  actor: string,
  approver: string,
): Promise<RuntimeInfo> {
  return fetch(`/v1/models/${encodeURIComponent(modelId)}`, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
      ...dualControlHeaders(actor, approver),
    },
    body: JSON.stringify(body),
  }).then(async (response) => {
    const payload = await response.json();
    if (!response.ok) {
      throw new ApiError(
        typeof payload?.error === "string" ? payload.error : "Update failed",
        response.status,
      );
    }
    return payload as RuntimeInfo;
  });
}

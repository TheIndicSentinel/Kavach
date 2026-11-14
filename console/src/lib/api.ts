import type { components, operations, paths } from "./openapi";

/** Every type the API sends or accepts, generated from docs/openapi.yaml. */
type Schemas = components["schemas"];

/** The JSON body of an operation's 200 response. */
type Ok<Op extends keyof operations> = operations[Op]["responses"] extends {
  200: { content: { "application/json": infer Body } };
}
  ? Body
  : never;

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
  /** The server's `request_id`, to quote when reporting a refusal. */
  readonly requestId?: string;
  /** The refusal without the request id appended (the problem `detail`, or the status). */
  readonly detail: string;

  constructor(message: string, status: number, requestId?: string, detail?: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.requestId = requestId;
    this.detail = detail ?? message;
  }
}

/**
 * The text of a refusal: the RFC 9457 `detail` (or the `error` member older
 * servers sent), with the `request_id` to quote when reporting it.
 */
function problemOf(payload: unknown): { text?: string; requestId?: string } {
  const body = payload as
    | { detail?: unknown; error?: unknown; request_id?: unknown }
    | null;
  const text =
    typeof body?.detail === "string"
      ? body.detail
      : typeof body?.error === "string"
        ? body.error
        : undefined;
  const requestId =
    typeof body?.request_id === "string" ? body.request_id : undefined;
  return { text, requestId };
}

/**
 * The one way the console calls the API. The status is checked before the
 * body is read, so an error page from a proxy (a 502 or 504 in HTML) is
 * reported by its status, never as a JSON parse error.
 */
export async function request<T>(
  path: string,
  init: { method?: "GET" | "POST"; body?: unknown } = {},
): Promise<T> {
  const method = init.method ?? "GET";
  const headers: Record<string, string> = { Accept: "application/json", ...authHeaders() };
  if (init.body !== undefined) headers["Content-Type"] = "application/json";

  let response: Response;
  try {
    response = await fetch(path, {
      method,
      headers,
      body: init.body === undefined ? undefined : JSON.stringify(init.body),
      credentials: "same-origin",
    });
  } catch {
    throw new ApiError("The API could not be reached", 0);
  }

  const isJson = (response.headers.get("Content-Type") ?? "").includes("json");
  const payload: unknown = isJson ? await response.json().catch(() => undefined) : undefined;

  if (!response.ok) {
    const { text, requestId } = problemOf(payload);
    const message = text ?? `${method} ${path} failed (${response.status} ${response.statusText})`.trim();
    throw new ApiError(
      requestId ? `${message} (request ${requestId})` : message,
      response.status,
      requestId,
      message,
    );
  }
  if (payload === undefined) {
    throw new ApiError(`${method} ${path} returned no JSON body`, response.status);
  }
  return payload as T;
}

export function fetchHealth(): Promise<{ status: string }> {
  return request("/health");
}

export type EvaluateResponse = Schemas["EvaluateResponse"];

export function evaluateRequest(body: unknown): Promise<EvaluateResponse> {
  return request("/v1/evaluate", { method: "POST", body });
}

/** A guarantee this process runs with relaxed (docs/BYPASS_INVENTORY.md section 1). */
export type Relaxation = Schemas["RuntimeView"]["relaxations"][number];

/** `GET /v1/runtime`. */
export type RuntimeInfo = Schemas["RuntimeView"];

export type PackSummary = Schemas["PackSummary"];

export type PolicyPack = Schemas["PolicyPack"];

export type ModelSummary = Schemas["ModelSummary"];

export type ModelRecord = Schemas["ModelDetail"];

function governanceFetch<T>(path: string): Promise<T> {
  return request(path);
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

export type AuditEntry = Schemas["AuditEntry"];

export function fetchAuditLog(limit = 50): Promise<AuditEntry[]> {
  return governanceFetch(`/v1/admin/audit?limit=${limit}`);
}

export type IncidentRecord = Schemas["IncidentRecord"];

export function fetchIncidents(limit = 50): Promise<IncidentRecord[]> {
  return governanceFetch(`/v1/admin/incidents?limit=${limit}`);
}

export type BatchJob = Schemas["BatchJobRecord"];

export function fetchBatchJobs(limit = 50): Promise<BatchJob[]> {
  return governanceFetch(`/v1/admin/batch-jobs?limit=${limit}`);
}

export function fetchBatchJob(jobId: string): Promise<BatchJob> {
  return governanceFetch(`/v1/admin/batch-jobs/${encodeURIComponent(jobId)}`);
}

export type RetentionSettings = Schemas["RetentionSettings"];

export type TombstoneRecord = Schemas["TombstoneRecord"];

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

export type ChangeKind = Schemas["ChangeKind"];

export type ChangeStatus = Schemas["ChangeStatus"];

/** A maker-checker change request (ADR-009). */
export type ChangeRequest = Schemas["ChangeRequest"];

function changeFetch<T>(path: string, body?: unknown): Promise<T> {
  return request(path, { method: "POST", body });
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

export type AgentStateName = Schemas["AgentStateName"];

/** An agent's state and the last change to it (ADR-013). */
export type AgentStateView = Schemas["AgentStateView"];

/** One page of `GET /v1/agents`. */
export type AgentStatePage = Schemas["AgentStatePage"];

/** The query `GET /v1/agents` accepts: `state`, `limit` and `cursor`. */
export type AgentListQuery = NonNullable<operations["listAgents"]["parameters"]["query"]>;

/** `GET /v1/agent-decisions/{record_id}`: the signed record and its outcome, if any. */
export type AgentDecisionLookup = Ok<"getAgentDecision">;

/** `GET /v1/agent-revocations/{system}/{event_id}`: the signed revocation record. */
export type RevocationLookup = Ok<"getRevocationRecord">;

/** The path of one page of agents; only the members that are set go in the query. */
export function agentsPath(query: AgentListQuery = {}): string {
  const params = new URLSearchParams();
  if (query.state) params.set("state", query.state);
  if (query.limit !== undefined) params.set("limit", String(query.limit));
  if (query.cursor) params.set("cursor", query.cursor);
  const search = params.toString();
  return search ? `/v1/agents?${search}` : "/v1/agents";
}

export function fetchAgents(query: AgentListQuery = {}): Promise<AgentStatePage> {
  return request(agentsPath(query));
}

export function fetchAgent(agentId: string): Promise<AgentStateView> {
  return request(`/v1/agents/${encodeURIComponent(agentId)}`);
}

/** Audited and rate limited by the API: call it once per lookup the operator asks for. */
export function fetchAgentDecision(recordId: string): Promise<AgentDecisionLookup> {
  return request(`/v1/agent-decisions/${encodeURIComponent(recordId)}`);
}

/** Audited and rate limited by the API: call it once per lookup the operator asks for. */
export function fetchRevocationRecord(system: string, eventId: string): Promise<RevocationLookup> {
  return request(
    `/v1/agent-revocations/${encodeURIComponent(system)}/${encodeURIComponent(eventId)}`,
  );
}

/** Why an agent's state was changed, from the spec's closed set. */
export type AgentReasonCode = Schemas["AgentReasonCode"];

/** The body of a restrict, quarantine or revoke. */
export type StopAgentRequest = Schemas["StopAgentRequest"];

/** What a restrict, quarantine or revoke returns: the state now, and what was done. */
export type AgentStopResult = Schemas["AgentStopResult"];

/**
 * `restrict`, `quarantine` or `revoke`: the last segment of every
 * `/v1/agents/{agent_id}/<action>` path in the spec, so a path added or
 * renamed there changes this type.
 */
export type StopAction = Extract<keyof paths, `/v1/agents/{agent_id}/${string}`> extends
  `/v1/agents/{agent_id}/${infer Action}`
  ? Action
  : never;

/** The path of a stop: the agent id is encoded, the action is one the spec names. */
export function stopAgentPath(agentId: string, action: StopAction): string {
  return `/v1/agents/${encodeURIComponent(agentId)}/${action}`;
}

/** One principal with `stop_agent`; the API decides whether this caller may. */
export function stopAgent(
  agentId: string,
  action: StopAction,
  body: StopAgentRequest,
): Promise<AgentStopResult> {
  return request(stopAgentPath(agentId, action), { method: "POST", body });
}

/** What a reinstatement may bring an agent back to (never `revoked`, never past `active`). */
export type ReinstateTo = Extract<AgentStateName, "active" | "restricted">;

/**
 * The `params` of a `reinstate_agent` change request. The spec gives them
 * only in `ChangeProposal`'s description (`{agent_id, to: active |
 * restricted, reason_code?, note?}`): `params` itself is an open object, so
 * no generated type names these members (noted on #218).
 */
export type ReinstateAgentParams = {
  agent_id: AgentStateView["agent_id"];
  to: ReinstateTo;
  reason_code?: AgentReasonCode;
  note?: StopAgentRequest["note"];
};

/** `POST /v1/change-requests` for a reinstatement: the generated proposal with typed params. */
export type ReinstateProposal = Omit<Schemas["ChangeProposal"], "kind" | "params"> & {
  kind: Extract<ChangeKind, "reinstate_agent">;
  params: ReinstateAgentParams;
};

/**
 * Proposes bringing an agent back. Nothing changes until a different
 * principal approves the change request (ADR-013 §3, ADR-009).
 */
export function proposeReinstatement(proposal: ReinstateProposal): Promise<ChangeRequest> {
  return changeFetch("/v1/change-requests", proposal);
}

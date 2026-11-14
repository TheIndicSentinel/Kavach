// What the agent pages need beyond the API calls: the list's paging state,
// state labels, and the checks run on what the operator types.
import type { AgentListQuery, AgentStateName } from "./api";

/** Every state, in the order the filter offers them (the spec's enum order). */
export const AGENT_STATES = [
  "active",
  "restricted",
  "quarantined",
  "revoked",
] as const satisfies readonly AgentStateName[];

/** Badges always carry this text; colour only repeats it. */
export const AGENT_STATE_VARIANT: Record<AgentStateName, "active" | "warning" | "default"> = {
  active: "active",
  restricted: "warning",
  quarantined: "warning",
  revoked: "default",
};

/** Agents per page. The API clamps `limit` to 1-200. */
export const AGENTS_PAGE_SIZE = 50;

/**
 * Where the list is: the state filter, and the cursors that led to the page
 * shown (empty on the first page). Paging is keyset, so going back means
 * replaying an earlier cursor, never an offset.
 */
export type AgentPaging = {
  state?: AgentStateName;
  cursors: string[];
};

export type AgentPagingAction =
  | { type: "filter"; state?: AgentStateName }
  | { type: "next"; cursor: string }
  | { type: "previous" }
  | { type: "first" };

export const initialAgentPaging: AgentPaging = { cursors: [] };

export function agentPagingReducer(paging: AgentPaging, action: AgentPagingAction): AgentPaging {
  switch (action.type) {
    case "filter":
      // A cursor belongs to the filter it was issued under: start again.
      return { state: action.state, cursors: [] };
    case "next":
      return { ...paging, cursors: [...paging.cursors, action.cursor] };
    case "previous":
      return { ...paging, cursors: paging.cursors.slice(0, -1) };
    case "first":
      return { ...paging, cursors: [] };
  }
}

/** The query for the page `paging` points at: the `next_cursor` of the page before it. */
export function agentListQuery(paging: AgentPaging): AgentListQuery {
  const query: AgentListQuery = { limit: AGENTS_PAGE_SIZE };
  if (paging.state) query.state = paging.state;
  const cursor = paging.cursors.at(-1);
  if (cursor) query.cursor = cursor;
  return query;
}

// Input checks mirror the path parameter patterns in docs/openapi.yaml, so an
// obvious typo is caught before it spends an audited, rate-limited lookup.
// The API still validates everything.
const RECORD_ID = /^adr:[A-Za-z0-9._-]+:[0-9]{1,9}:[0-9]{1,19}$/;
const ID_SEGMENT = /^[A-Za-z0-9._:-]+$/;
export const LOOKUP_MAX_LENGTH = 128;

/** Why `value` cannot be a record id, or null when it can. */
export function recordIdProblem(value: string): string | null {
  if (!value) return "Enter a record id.";
  if (value.length > LOOKUP_MAX_LENGTH || !RECORD_ID.test(value)) {
    return "A record id looks like adr:<tenant>:<partition>:<sequence>.";
  }
  return null;
}

/** Why `value` cannot be an agent, system or event id, or null when it can. */
export function idProblem(label: string, value: string): string | null {
  if (!value) return `Enter the ${label}.`;
  if (value.length > LOOKUP_MAX_LENGTH || !ID_SEGMENT.test(value)) {
    return `The ${label} is up to ${LOOKUP_MAX_LENGTH} letters, digits and . _ : -`;
  }
  return null;
}

/** What the status region says about a loaded page. */
export function agentPageSummary(paging: AgentPaging, count: number, more: boolean): string {
  const page = `Page ${paging.cursors.length + 1}`;
  const scope = paging.state ? ` ${paging.state}` : "";
  const noun = count === 1 ? "agent" : "agents";
  return `${page}: ${count}${scope} ${noun}${more ? "; more may follow." : "; no more follow."}`;
}

/** What the table says when a page holds no agents. */
export function agentPageEmptyMessage(paging: AgentPaging, more: boolean): string {
  // The API may return a short or empty page before the last one.
  if (more) return "No agents on this page. More may follow: use Next page.";
  if (paging.cursors.length > 0) return "No more agents.";
  return paging.state ? `No ${paging.state} agents.` : "No agents yet.";
}

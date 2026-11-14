// The agent list's paging and filter state, and the lookup input checks.
import { describe, expect, it } from "vitest";
import {
  AGENTS_PAGE_SIZE,
  agentListQuery,
  agentPageEmptyMessage,
  agentPageSummary,
  agentPagingReducer,
  idProblem,
  initialAgentPaging,
  recordIdProblem,
  type AgentPaging,
} from "./agents";
import { agentsPath } from "./api";

function pathOf(paging: AgentPaging): string {
  return agentsPath(agentListQuery(paging));
}

describe("agent paging", () => {
  it("asks for the first page with no cursor and no state", () => {
    expect(pathOf(initialAgentPaging)).toBe(`/v1/agents?limit=${AGENTS_PAGE_SIZE}`);
  });

  it("asks for the next page with the next_cursor the last page returned", () => {
    const second = agentPagingReducer(initialAgentPaging, { type: "next", cursor: "agent-050" });
    expect(agentListQuery(second).cursor).toBe("agent-050");
    const third = agentPagingReducer(second, { type: "next", cursor: "agent-100" });
    expect(agentListQuery(third).cursor).toBe("agent-100");
    expect(pathOf(third)).toBe(`/v1/agents?limit=${AGENTS_PAGE_SIZE}&cursor=agent-100`);
  });

  it("goes back one page by replaying the earlier cursor, and to the first page with none", () => {
    let paging = agentPagingReducer(initialAgentPaging, { type: "next", cursor: "c1" });
    paging = agentPagingReducer(paging, { type: "next", cursor: "c2" });
    expect(agentListQuery(agentPagingReducer(paging, { type: "previous" })).cursor).toBe("c1");
    const first = agentPagingReducer(paging, { type: "first" });
    expect(agentListQuery(first).cursor).toBeUndefined();
  });

  it("puts the state filter in the query and starts again from the first page", () => {
    const deep = agentPagingReducer(initialAgentPaging, { type: "next", cursor: "c1" });
    const filtered = agentPagingReducer(deep, { type: "filter", state: "quarantined" });
    expect(filtered.cursors).toEqual([]);
    expect(pathOf(filtered)).toBe(`/v1/agents?state=quarantined&limit=${AGENTS_PAGE_SIZE}`);
    // Paging keeps the filter.
    const next = agentPagingReducer(filtered, { type: "next", cursor: "c9" });
    expect(pathOf(next)).toBe(`/v1/agents?state=quarantined&limit=${AGENTS_PAGE_SIZE}&cursor=c9`);
  });

  it("drops the state when the filter is cleared", () => {
    const filtered = agentPagingReducer(initialAgentPaging, { type: "filter", state: "revoked" });
    const all = agentPagingReducer(filtered, { type: "filter", state: undefined });
    expect(pathOf(all)).toBe(`/v1/agents?limit=${AGENTS_PAGE_SIZE}`);
  });
});

describe("agent page status and empty states", () => {
  it("says which page, how many, and whether more may follow", () => {
    expect(agentPageSummary(initialAgentPaging, 2, true)).toBe("Page 1: 2 agents; more may follow.");
    expect(agentPageSummary({ state: "revoked", cursors: ["c1"] }, 1, false)).toBe(
      "Page 2: 1 revoked agent; no more follow.",
    );
  });

  it("explains an empty page by what the API allows", () => {
    expect(agentPageEmptyMessage(initialAgentPaging, false)).toBe("No agents yet.");
    expect(agentPageEmptyMessage({ state: "restricted", cursors: [] }, false)).toBe(
      "No restricted agents.",
    );
    // An empty page that still has a next_cursor is not the end.
    expect(agentPageEmptyMessage(initialAgentPaging, true)).toMatch(/More may follow/);
    expect(agentPageEmptyMessage({ cursors: ["c1"] }, false)).toBe("No more agents.");
  });
});

describe("lookup input checks", () => {
  it("accepts a record id of the documented shape and refuses others", () => {
    expect(recordIdProblem("adr:bank-1:0:42")).toBeNull();
    expect(recordIdProblem("")).toMatch(/Enter/);
    expect(recordIdProblem("adr:bank-1:x:42")).toMatch(/adr:/);
    expect(recordIdProblem(`adr:${"t".repeat(130)}:0:1`)).not.toBeNull();
  });

  it("accepts agent, system and event ids of the documented shape and refuses others", () => {
    expect(idProblem("agent id", "agent:collections-bot.v2")).toBeNull();
    expect(idProblem("system", "")).toBe("Enter the system.");
    expect(idProblem("event id", "evt 1")).not.toBeNull();
    expect(idProblem("event id", "../admin")).not.toBeNull();
    expect(idProblem("event id", "e".repeat(129))).not.toBeNull();
  });
});

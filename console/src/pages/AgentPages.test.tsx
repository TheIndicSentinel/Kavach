// What the agent pages render before any data arrives (static markup runs no
// effects, so nothing is fetched here): loading in role=status, an empty
// role=alert, labelled controls, and no actions.
import { describe, expect, it } from "vitest";
import type { Resource } from "../hooks/useResource";
import type { AgentDecisionLookup, AgentStateView, RevocationLookup } from "../lib/api";
import { decisionLookup, neverChanged, revocationLookup } from "../test/fixtures";
import { byRole, render, renderAt, text } from "../test/markup";
import {
  badGateway,
  failed,
  forbidden,
  loading,
  lookupFailed,
  lookupLoading,
  notFound,
  ok,
  problem,
  serverError,
  unauthorized,
} from "../test/states";
import AgentDetailPage from "./AgentDetailPage";
import AgentEvidencePage from "./AgentEvidencePage";
import AgentsPage from "./AgentsPage";

const SKELETON = 'class="animate-pulse';

describe("AgentsPage", () => {
  const html = render(<AgentsPage />);

  it("announces loading in role=status and has an empty role=alert", () => {
    expect(byRole(html, "status")).toEqual(["Loading agents…"]);
    expect(byRole(html, "alert")).toEqual([""]);
  });

  it("labels the state filter and offers every state", () => {
    expect(html).toContain('<label for="agent-state-filter"');
    for (const state of ["All states", "active", "restricted", "quarantined", "revoked"]) {
      expect(html).toContain(`>${state}</option>`);
    }
  });

  it("labels the agent id lookup", () => {
    expect(html).toContain('<label for="agent-lookup"');
    expect(html).toContain('id="agent-lookup"');
  });

  it("starts on page 1 with only Next page able to move, once a cursor arrives", () => {
    expect(text(html)).toContain("Page 1");
    expect(html).toMatch(/aria-disabled="true"[^>]*>First page</);
    expect(html).toMatch(/aria-disabled="true"[^>]*>Next page</);
  });

  it("offers no stop or reinstate action", () => {
    expect(text(html)).not.toMatch(/restrict |quarantine |revoke |reinstate/i);
  });
});

describe("AgentEvidencePage", () => {
  const html = render(<AgentEvidencePage />);

  it("says each lookup is audited and rate limited", () => {
    const shown = text(html);
    expect(shown).toContain("audited");
    expect(shown).toContain("rate limited");
  });

  it("labels every lookup field and starts with empty status and alert regions", () => {
    for (const id of ["decision-record-id", "revocation-system", "revocation-event-id"]) {
      expect(html).toContain(`<label for="${id}"`);
    }
    expect(byRole(html, "status")).toEqual(["", ""]);
    expect(byRole(html, "alert")).toEqual(["", ""]);
  });
});

describe("AgentsPage states", () => {
  it("loading: a skeleton, not placeholder rows", () => {
    const html = render(<AgentsPage resource={loading} />);
    expect(html).toContain(SKELETON);
    expect(byRole(html, "status")).toEqual(["Loading agents…"]);
  });

  it("empty: says there are no agents yet", () => {
    const html = render(<AgentsPage resource={ok({ items: [], next_cursor: null })} />);
    expect(text(html)).toContain("No agents yet.");
    expect(byRole(html, "status")).toEqual(["Page 1: 0 agents; no more follow."]);
    expect(html).not.toContain(SKELETON);
  });

  it("loaded: the agents and a summary", () => {
    const html = render(<AgentsPage resource={ok({ items: [neverChanged], next_cursor: null })} />);
    expect(text(html)).toContain("agent:collections-bot");
    expect(byRole(html, "status")).toEqual(["Page 1: 1 agent; no more follow."]);
  });

  it("error: the detail, status and request_id, and Try again", () => {
    const html = render(<AgentsPage resource={failed(serverError)} />);
    expect(byRole(html, "alert")).toEqual(["storage unavailable HTTP 500 · request_id req-500"]);
    expect(byRole(html, "status")).toEqual([""]);
    expect(text(html)).toContain("Try again");
    expect(html).not.toContain(SKELETON);
  });

  it("a non-JSON 502: the status, and that no request_id came back", () => {
    const [alert] = byRole(render(<AgentsPage resource={failed(badGateway("/v1/agents"))} />), "alert");
    expect(alert).toContain("The Kavach API is not reachable");
    expect(alert).toContain("no request_id was returned");
  });

  it("401: sign in again, or set a token in Settings", () => {
    const [alert] = byRole(render(<AgentsPage resource={failed(unauthorized)} />), "alert");
    expect(alert).toContain("Sign in again, or set an access token in Settings");
    expect(alert).toContain("request_id req-401");
  });

  it("403: not permitted, and the server decides", () => {
    const [alert] = byRole(render(<AgentsPage resource={failed(forbidden)} />), "alert");
    expect(alert).toContain("Not permitted");
    expect(alert).toContain("The server decides");
  });

  // 404: not a state of this page. A list has no id to be unknown; the lookup
  // opens the detail page, whose 404 is tested below.
});

describe("AgentDetailPage states", () => {
  const at = (resource: Resource<AgentStateView>) =>
    renderAt("/agents/agent:x", "/agents/:agentId", <AgentDetailPage resource={resource} />);

  it("loading: the heading and id, a skeleton, and no actions", () => {
    const html = at(loading);
    expect(html).toMatch(/<h1[^>]*>Agent<\/h1>/);
    expect(text(html)).toContain("agent:x");
    expect(html).toContain(SKELETON);
    expect(byRole(html, "status")).toEqual(["Loading agent…"]);
    expect(byRole(html, "alert")).toEqual([""]);
    expect(text(html)).not.toMatch(/Quarantine|Restrict|Revoke/);
  });

  it("loaded: the state in role=status", () => {
    const html = at(ok(neverChanged));
    expect(byRole(html, "status")[0]).toBe("Agent agent:collections-bot is active.");
  });

  it("404: says the agent doesn't exist, keeps the server's detail, and offers no Try again", () => {
    for (const detail of ["no such agent in this configuration", "agent surfaces are not configured"]) {
      const html = at(failed(problem(404, detail)));
      expect(byRole(html, "alert")).toEqual([
        `Agent agent:x doesn't exist on this server. ${detail} · HTTP 404 · request_id req-404`,
      ]);
      expect(text(html)).not.toContain("Try again");
      expect(html).toMatch(/<h1[^>]*>Agent<\/h1>/);
    }
  });

  it("error and a non-JSON 502: the detail or status, and Try again", () => {
    const html = at(failed(serverError));
    expect(byRole(html, "alert")).toEqual(["storage unavailable HTTP 500 · request_id req-500"]);
    expect(text(html)).toContain("Try again");
    const [alert] = byRole(at(failed(badGateway("/v1/agents/agent:x"))), "alert");
    expect(alert).toContain("The Kavach API is not reachable");
    expect(alert).toContain("no request_id was returned");
  });

  it("401 and 403: how to sign in, or that the server refused", () => {
    expect(byRole(at(failed(unauthorized)), "alert")[0]).toContain("Sign in again");
    expect(byRole(at(failed(forbidden)), "alert")[0]).toContain("Not permitted");
  });

  // Empty: not a state of this page. The API answers one agent or a 404.
});

describe("AgentEvidencePage states", () => {
  const decision = (lookup: Parameters<typeof AgentEvidencePage>[0]["decision"]) =>
    render(<AgentEvidencePage decision={lookup} />);
  const revocation = (lookup: Parameters<typeof AgentEvidencePage>[0]["revocation"]) =>
    render(<AgentEvidencePage revocation={lookup} />);

  it("loading: what is being looked up, and a skeleton", () => {
    const html = decision(lookupLoading<AgentDecisionLookup>("Looking up record adr:t:p:1"));
    expect(byRole(html, "status")).toEqual(["Looking up record adr:t:p:1…", ""]);
    expect(html).toContain(SKELETON);
    expect(html).toMatch(/aria-disabled="true"[^>]*>Look up record</);
  });

  it("found: the record and its id in role=status", () => {
    const html = decision({ phase: "done", what: "x", result: decisionLookup });
    expect(byRole(html, "status")[0]).toBe(`Found record ${decisionLookup.record.record_id}.`);
    const rev = revocation({ phase: "done", what: "x", result: revocationLookup });
    expect(byRole(rev, "status")[1]).toBe(
      `Found the revocation for event ${revocationLookup.record.event_id} from ${revocationLookup.record.source_system}.`,
    );
  });

  it("404: says no such record exists, with the server's detail and request_id", () => {
    expect(byRole(decision(lookupFailed<AgentDecisionLookup>("x", notFound)), "alert")[0]).toBe(
      "No agent decision record with that id on this server. no such record · HTTP 404 · request_id req-404",
    );
    expect(byRole(revocation(lookupFailed<RevocationLookup>("x", notFound)), "alert")[1]).toBe(
      "No revocation record for that system and event id on this server. no such record · HTTP 404 · request_id req-404",
    );
  });

  it("error, a non-JSON 502, 401 and 403", () => {
    const alert = (error: unknown) =>
      byRole(decision(lookupFailed<AgentDecisionLookup>("x", error)), "alert")[0];
    expect(alert(serverError)).toBe("storage unavailable HTTP 500 · request_id req-500");
    expect(alert(badGateway("/v1/agent-decisions/x"))).toContain("no request_id was returned");
    expect(alert(unauthorized)).toContain("Sign in again");
    expect(alert(forbidden)).toContain("Not permitted");
  });

  // Empty: nothing is looked up until a submit, so the idle page (empty
  // regions, tested above) is the "nothing yet" state.
});

// request(): every way a call can end, checked against a stubbed fetch.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  ApiError,
  fetchAgent,
  fetchAgentDecision,
  fetchAgents,
  fetchRevocationRecord,
  proposeReinstatement,
  request,
  setAuthMode,
  stopAgent,
  stopAgentPath,
  type StopAction,
} from "./api";
import { reinstateProposalBody, stopRequestBody } from "./agentActions";

function stubStorage() {
  const store = new Map<string, string>();
  vi.stubGlobal("sessionStorage", {
    getItem: (k: string) => store.get(k) ?? null,
    setItem: (k: string, v: string) => void store.set(k, v),
    removeItem: (k: string) => void store.delete(k),
  });
}

function respond(status: number, body: string, contentType: string) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => new Response(body, { status, headers: { "Content-Type": contentType } })),
  );
}

async function failure(path: string): Promise<ApiError> {
  try {
    await request(path);
  } catch (err) {
    expect(err).toBeInstanceOf(ApiError);
    return err as ApiError;
  }
  throw new Error("request resolved; a failure was expected");
}

beforeEach(stubStorage);
afterEach(() => {
  setAuthMode(null);
  vi.unstubAllGlobals();
});

describe("request", () => {
  it("returns the parsed body of an ok JSON response", async () => {
    respond(200, JSON.stringify({ status: "ok" }), "application/json");
    await expect(request("/health")).resolves.toEqual({ status: "ok" });
  });

  it("reports an RFC 9457 problem by its detail, status and request_id", async () => {
    respond(
      403,
      JSON.stringify({
        type: "about:blank",
        title: "Forbidden",
        status: 403,
        detail: "not allowed to read agent state",
        request_id: "req-123",
      }),
      "application/problem+json",
    );
    const err = await failure("/v1/agents/a-1");
    expect(err.status).toBe(403);
    expect(err.requestId).toBe("req-123");
    expect(err.message).toContain("not allowed to read agent state");
    expect(err.message).toContain("req-123");
  });

  it("reports an HTML 502 from a proxy by its status, not as a parse error", async () => {
    respond(502, "<html><body>Bad Gateway</body></html>", "text/html");
    const err = await failure("/v1/runtime");
    expect(err.status).toBe(502);
    expect(err.requestId).toBeUndefined();
    expect(err.message).toContain("502");
    expect(err.message).not.toMatch(/JSON|Unexpected token/);
  });

  it("reports a network failure as unreachable, with status 0", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new TypeError("Failed to fetch");
      }),
    );
    const err = await failure("/v1/runtime");
    expect(err.status).toBe(0);
    expect(err.message).toBe("The API could not be reached");
  });

  it("sends the bearer token and never the principal header when a token is set (development fallback)", async () => {
    setAuthMode("dev_token");
    const seen = vi.fn(async (_path: string, _init?: RequestInit) =>
      new Response("{}", { status: 200, headers: { "Content-Type": "application/json" } }),
    );
    vi.stubGlobal("fetch", seen);
    sessionStorage.setItem("kavach.accessToken", "tok");
    sessionStorage.setItem("kavach.principal", "someone");
    await request("/v1/runtime");
    const headers = seen.mock.calls[0][1]?.headers as Record<string, string>;
    expect(headers.Authorization).toBe("Bearer tok");
    expect(headers["X-Kavach-Principal"]).toBeUndefined();
  });
});

describe("agent calls", () => {
  function capture(body: unknown) {
    const seen = vi.fn(async (_path: string, _init?: RequestInit) =>
      new Response(JSON.stringify(body), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", seen);
    return seen;
  }

  it("lists agents with the state, limit and cursor it is given", async () => {
    const seen = capture({ items: [], next_cursor: null });
    await fetchAgents({ state: "restricted", limit: 50, cursor: "agent-7" });
    expect(seen.mock.calls[0][0]).toBe("/v1/agents?state=restricted&limit=50&cursor=agent-7");
    expect(seen.mock.calls[0][1]?.method).toBe("GET");
  });

  it("leaves unset query members out", async () => {
    const seen = capture({ items: [], next_cursor: null });
    await fetchAgents();
    expect(seen.mock.calls[0][0]).toBe("/v1/agents");
  });

  it("encodes ids in the path, never in a query string", async () => {
    const seen = capture({});
    await fetchAgent("a/b?c");
    await fetchAgentDecision("adr:t:0:1");
    await fetchRevocationRecord("los:core", "evt/1");
    expect(seen.mock.calls.map((call) => call[0])).toEqual([
      "/v1/agents/a%2Fb%3Fc",
      "/v1/agent-decisions/adr%3At%3A0%3A1",
      "/v1/agent-revocations/los%3Acore/evt%2F1",
    ]);
  });

  it("keeps the problem detail apart from the request_id", async () => {
    respond(
      429,
      JSON.stringify({ title: "Too Many Requests", status: 429, detail: "slow down", request_id: "r-9" }),
      "application/problem+json",
    );
    const err = await failure("/v1/agent-decisions/adr:t:0:1");
    expect(err.detail).toBe("slow down");
    expect(err.requestId).toBe("r-9");
  });
});

describe("agent actions", () => {
  function capture(status: number, body: unknown) {
    const seen = vi.fn(async (_path: string, _init?: RequestInit) =>
      new Response(JSON.stringify(body), {
        status,
        headers: { "Content-Type": status < 400 ? "application/json" : "application/problem+json" },
      }),
    );
    vi.stubGlobal("fetch", seen);
    return seen;
  }

  it("posts each stop to its own path with the reason code and note", async () => {
    const actions: StopAction[] = ["restrict", "quarantine", "revoke"];
    const seen = capture(200, {});
    const body = stopRequestBody({ reasonCode: "policy_violation", note: "seen in the audit" });
    for (const action of actions) await stopAgent("agent:a/b", action, body);
    expect(seen.mock.calls.map((call) => call[0])).toEqual([
      "/v1/agents/agent%3Aa%2Fb/restrict",
      "/v1/agents/agent%3Aa%2Fb/quarantine",
      "/v1/agents/agent%3Aa%2Fb/revoke",
    ]);
    for (const call of seen.mock.calls) {
      expect(call[1]?.method).toBe("POST");
      expect(JSON.parse(String(call[1]?.body))).toEqual({
        reason_code: "policy_violation",
        note: "seen in the audit",
      });
      expect((call[1]?.headers as Record<string, string>)["Content-Type"]).toBe("application/json");
    }
    expect(stopAgentPath("x", "revoke")).toBe("/v1/agents/x/revoke");
  });

  it("proposes a reinstatement through the change-request API, never a reinstate path", async () => {
    const seen = capture(201, { id: "cr-1" });
    await proposeReinstatement(
      reinstateProposalBody("agent:a", "active", { reasonCode: "reviewed", note: "" }),
    );
    expect(seen.mock.calls[0][0]).toBe("/v1/change-requests");
    expect(seen.mock.calls[0][1]?.method).toBe("POST");
    expect(JSON.parse(String(seen.mock.calls[0][1]?.body))).toEqual({
      kind: "reinstate_agent",
      params: { agent_id: "agent:a", to: "active", reason_code: "reviewed" },
    });
  });

  it.each([
    [403, "forbidden", "req-403"],
    [409, "this would loosen the agent's state", "req-409"],
  ])("reports a %i refusal of a stop with its detail and request_id", async (status, detail, id) => {
    capture(status, { title: "refused", status, detail, request_id: id });
    const err = await stopAgent("agent:a", "restrict", { reason_code: "other" }).catch(
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).status).toBe(status);
    expect((err as ApiError).detail).toBe(detail);
    expect((err as ApiError).requestId).toBe(id);
  });
});

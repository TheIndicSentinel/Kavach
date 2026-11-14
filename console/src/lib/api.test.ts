// request(): every way a call can end, checked against a stubbed fetch.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError, request } from "./api";

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
afterEach(() => vi.unstubAllGlobals());

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

  it("sends the bearer token and never the principal header when a token is set", async () => {
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

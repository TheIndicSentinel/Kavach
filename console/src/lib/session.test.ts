// Console sign-in (ADR-018 option C), against a stubbed fetch: the mode the
// server's /auth/config selects, the headers every request carries, what is
// kept out of sessionStorage, the /signin error messages, a 401 ending the
// session, and where sign-out may navigate.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  getAccessToken,
  getPrincipal,
  request,
  setAccessToken,
  setAuthMode,
  setPrincipal,
} from "./api";
import {
  SIGNIN_PATH,
  authModeOf,
  fetchAuthConfig,
  fetchSession,
  getSessionState,
  postLogout,
  sessionViewer,
  setSessionStateForTest,
  signInErrorMessage,
  signOut,
  signOutTarget,
  startSession,
  type AuthConfig,
  type AuthSession,
} from "./session";

const TOKEN_KEY = "kavach.accessToken";
const PRINCIPAL_KEY = "kavach.principal";

const LOGIN: AuthConfig = { login_configured: true, pasted_token_allowed: false };
const DEV: AuthConfig = { login_configured: false, pasted_token_allowed: true };
const NONE: AuthConfig = { login_configured: false, pasted_token_allowed: false };

const SESSION: AuthSession = {
  principal: "oidc-user-7",
  groups: ["operators", "viewers"],
  expires_at: "2026-11-15T18:00:00Z",
  idle_expires_at: "2026-11-15T10:15:00Z",
};

let store: Map<string, string>;

function stubStorage() {
  store = new Map<string, string>();
  vi.stubGlobal("sessionStorage", {
    getItem: (k: string) => store.get(k) ?? null,
    setItem: (k: string, v: string) => void store.set(k, v),
    removeItem: (k: string) => void store.delete(k),
  });
}

const assign = vi.fn();
function stubWindow(origin = "https://console.bank.example") {
  assign.mockReset();
  vi.stubGlobal("window", {
    location: { origin, assign, reload: vi.fn() },
    addEventListener: vi.fn(),
  });
}

type Reply = { status: number; body?: unknown };

/** Answers each `METHOD /path` from `replies` (401 problem for anything else) and records every call. */
function stubFetch(replies: Record<string, Reply>) {
  const seen = vi.fn(async (path: string, init?: RequestInit) => {
    const reply = replies[`${init?.method ?? "GET"} ${path}`] ?? {
      status: 401,
      body: { title: "Unauthorized", status: 401, detail: "no live session", request_id: "r-401" },
    };
    return new Response(JSON.stringify(reply.body ?? {}), {
      status: reply.status,
      headers: {
        "Content-Type": reply.status < 400 ? "application/json" : "application/problem+json",
      },
    });
  });
  vi.stubGlobal("fetch", seen);
  return seen;
}

function headersOf(call: unknown[]): Record<string, string> {
  return (call[1] as RequestInit).headers as Record<string, string>;
}

beforeEach(() => {
  stubStorage();
  stubWindow();
  setAuthMode(null);
  setSessionStateForTest({ status: "checking" });
});
afterEach(() => vi.unstubAllGlobals());

describe("the mode /auth/config selects", () => {
  it("is login when login is configured, whatever pasted_token_allowed says", () => {
    expect(authModeOf(LOGIN)).toBe("login");
    expect(authModeOf({ login_configured: true, pasted_token_allowed: true })).toBe("login");
  });

  it("is the development fallback only without login and with pasted tokens allowed", () => {
    expect(authModeOf(DEV)).toBe("dev_token");
  });

  it("is not configured when neither is true", () => {
    expect(authModeOf(NONE)).toBe("not_configured");
  });

  it("login mode with a live session: signed in, principal and groups from /auth/session", async () => {
    stubFetch({
      "GET /auth/config": { status: 200, body: LOGIN },
      "GET /auth/session": { status: 200, body: SESSION },
    });
    await startSession();
    expect(getSessionState()).toEqual({ status: "signed_in", session: SESSION });
    expect(sessionViewer()).toEqual({ principal: "oidc-user-7", groups: ["operators", "viewers"] });
  });

  it("login mode with no session (401): signed out, without the session-ended message", async () => {
    stubFetch({ "GET /auth/config": { status: 200, body: LOGIN } });
    await startSession();
    expect(getSessionState()).toEqual({ status: "signed_out", ended: false });
    expect(sessionViewer()).toEqual({ principal: null, groups: null });
  });

  it("asks for no session outside login mode", async () => {
    for (const [config, status] of [
      [DEV, "dev_token"],
      [NONE, "not_configured"],
    ] as const) {
      setSessionStateForTest({ status: "checking" });
      const seen = stubFetch({ "GET /auth/config": { status: 200, body: config } });
      await startSession();
      expect(getSessionState().status).toBe(status);
      expect(seen.mock.calls.map((c) => c[0])).toEqual(["/auth/config"]);
      expect(sessionViewer()).toEqual({ principal: null, groups: null });
    }
  });

  it("offers nothing when /auth/config cannot be read (an older server answers with HTML)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("<html></html>", { status: 200, headers: { "Content-Type": "text/html" } })),
    );
    await startSession();
    expect(getSessionState().status).toBe("unavailable");
  });
});

describe("the headers on every request", () => {
  /** Sets the mode, then runs `seed` (after any clearing the mode does), then makes every kind of call. */
  async function everyCall(
    mode: "login" | "dev_token" | "not_configured" | null,
    seed: () => void = () => {},
  ) {
    setAuthMode(mode);
    seed();
    const seen = stubFetch({
      "GET /auth/config": { status: 200, body: LOGIN },
      "GET /auth/session": { status: 200, body: SESSION },
      "POST /auth/logout": { status: 200, body: { end_session_url: null } },
      "GET /v1/runtime": { status: 200, body: {} },
      "POST /v1/change-requests": { status: 200, body: {} },
    });
    await fetchAuthConfig();
    await fetchSession();
    await postLogout();
    await request("/v1/runtime");
    await request("/v1/change-requests", { method: "POST", body: { kind: "x" } });
    return seen;
  }

  it.each(["login", "dev_token", "not_configured", null] as const)(
    "sends X-Kavach-Console: 1 with same-origin credentials (mode %s)",
    async (mode) => {
      const seen = await everyCall(mode);
      expect(seen).toHaveBeenCalledTimes(5);
      for (const call of seen.mock.calls) {
        expect(headersOf(call)["X-Kavach-Console"]).toBe("1");
        expect((call[1] as RequestInit).credentials).toBe("same-origin");
      }
    },
  );

  it("never sends Authorization or X-Kavach-Principal in login mode, even with values in storage", async () => {
    // As if something wrote them after the clearing on load.
    const seen = await everyCall("login", () => {
      store.set(TOKEN_KEY, "eyJ.pasted.token");
      store.set(PRINCIPAL_KEY, "operator-1");
    });
    expect(store.get(TOKEN_KEY)).toBe("eyJ.pasted.token");
    for (const call of seen.mock.calls) {
      expect(headersOf(call).Authorization).toBeUndefined();
      expect(headersOf(call)["X-Kavach-Principal"]).toBeUndefined();
    }
    expect(getAccessToken()).toBe("");
    expect(getPrincipal()).toBe("");
  });

  it("sends no credential header before the mode is known, or when login is not configured", async () => {
    store.set(TOKEN_KEY, "eyJ.pasted.token");
    for (const mode of [null, "not_configured"] as const) {
      const seen = await everyCall(mode);
      for (const call of seen.mock.calls) {
        expect(headersOf(call).Authorization).toBeUndefined();
        expect(headersOf(call)["X-Kavach-Principal"]).toBeUndefined();
      }
    }
  });

  it("sends the pasted token in the development fallback, and the principal only without one", async () => {
    store.set(PRINCIPAL_KEY, "operator-1");
    let seen = await everyCall("dev_token");
    expect(headersOf(seen.mock.calls[3]).Authorization).toBeUndefined();
    expect(headersOf(seen.mock.calls[3])["X-Kavach-Principal"]).toBe("operator-1");
    store.set(TOKEN_KEY, "tok");
    seen = await everyCall("dev_token");
    expect(headersOf(seen.mock.calls[3]).Authorization).toBe("Bearer tok");
    expect(headersOf(seen.mock.calls[3])["X-Kavach-Principal"]).toBeUndefined();
  });
});

describe("sessionStorage in login mode", () => {
  it("removes the development token and principal once, on load", async () => {
    store.set(TOKEN_KEY, "eyJ.left.over");
    store.set(PRINCIPAL_KEY, "operator-1");
    store.set("unrelated", "kept");
    stubFetch({
      "GET /auth/config": { status: 200, body: LOGIN },
      "GET /auth/session": { status: 200, body: SESSION },
    });
    await startSession();
    expect(store.has(TOKEN_KEY)).toBe(false);
    expect(store.has(PRINCIPAL_KEY)).toBe(false);
    expect(store.get("unrelated")).toBe("kept");
  });

  it("never writes them", () => {
    setAuthMode("login");
    setAccessToken("eyJ.new.token");
    setPrincipal("operator-1");
    expect(store.size).toBe(0);
  });

  it("keeps them in the development fallback", async () => {
    store.set(TOKEN_KEY, "tok");
    store.set(PRINCIPAL_KEY, "operator-1");
    stubFetch({ "GET /auth/config": { status: 200, body: DEV } });
    await startSession();
    expect(store.get(TOKEN_KEY)).toBe("tok");
    expect(store.get(PRINCIPAL_KEY)).toBe("operator-1");
  });
});

describe("/signin?error= messages", () => {
  it.each([
    ["login_failed", /answer from the identity provider was refused/],
    ["login_expired", /expired or was already used/],
    ["sessions_full", /limit of open sessions/],
    ["login_unavailable", /could not reach the identity provider/],
  ])("maps %s to a plain message", (code, message) => {
    expect(signInErrorMessage(code)).toMatch(message);
  });

  it("gives an unknown code the generic message, never the value itself", () => {
    for (const code of ["<img src=x onerror=alert(1)>", "toString", "__proto__", "LOGIN_FAILED"]) {
      const message = signInErrorMessage(code);
      expect(message).toBe("Sign-in did not complete. Try again.");
      expect(message).not.toContain(code);
    }
  });

  it("shows nothing without an error", () => {
    expect(signInErrorMessage(null)).toBeNull();
    expect(signInErrorMessage("")).toBeNull();
  });
});

describe("a 401 after sign-in", () => {
  it("ends the session in memory, with the session-ended message", async () => {
    stubFetch({
      "GET /auth/config": { status: 200, body: LOGIN },
      "GET /auth/session": { status: 200, body: SESSION },
    });
    await startSession();
    expect(getSessionState().status).toBe("signed_in");
    await expect(request("/v1/agents")).rejects.toMatchObject({ status: 401 });
    expect(getSessionState()).toEqual({ status: "signed_out", ended: true });
    expect(sessionViewer()).toEqual({ principal: null, groups: null });
  });

  it("does not end anything for a 403", async () => {
    stubFetch({
      "GET /auth/config": { status: 200, body: LOGIN },
      "GET /auth/session": { status: 200, body: SESSION },
      "GET /v1/agents": { status: 403, body: { status: 403, detail: "no" } },
    });
    await startSession();
    await expect(request("/v1/agents")).rejects.toMatchObject({ status: 403 });
    expect(getSessionState().status).toBe("signed_in");
  });

  it("is an ordinary refusal in the development fallback", async () => {
    stubFetch({ "GET /auth/config": { status: 200, body: DEV } });
    await startSession();
    await expect(request("/v1/agents")).rejects.toMatchObject({ status: 401 });
    expect(getSessionState()).toEqual({ status: "dev_token" });
  });
});

describe("where sign-out goes", () => {
  const page = "https://console.bank.example";

  it("goes to /signin when the server returns no end-session URL", () => {
    expect(signOutTarget(null, page)).toBe(SIGNIN_PATH);
    expect(signOutTarget("", page)).toBe(SIGNIN_PATH);
  });

  it("follows an https end-session URL, on any origin", () => {
    const url = "https://idp.bank.example/logout?client_id=kavach-console&post_logout_redirect_uri=x";
    expect(signOutTarget(url, page)).toBe(url);
  });

  it.each([
    ["javascript:", "javascript:alert(document.cookie)"],
    ["JavaScript: with spaces", "  JaVaScRiPt:alert(1)"],
    ["data:", "data:text/html,<script>alert(1)</script>"],
    ["plain http to another origin", "http://idp.bank.example/logout"],
    ["a relative path", "/elsewhere"],
    ["a protocol-relative URL", "//idp.bank.example/logout"],
    ["credentials in the URL", "https://user:pass@idp.bank.example/logout"],
    ["unparsable", "https://"],
  ])("refuses %s and goes to /signin", (_label, url) => {
    expect(signOutTarget(url, page)).toBe(SIGNIN_PATH);
  });

  it("accepts plain http only on the console's own loopback origin (a development stack)", () => {
    expect(signOutTarget("http://127.0.0.1:8080/dev-logout", "http://127.0.0.1:8080")).toBe(
      "http://127.0.0.1:8080/dev-logout",
    );
    expect(signOutTarget("http://127.0.0.1:9000/logout", "http://127.0.0.1:8080")).toBe(SIGNIN_PATH);
    expect(signOutTarget("http://console.bank.example/x", "http://console.bank.example")).toBe(SIGNIN_PATH);
  });

  it("posts /auth/logout, then navigates in the app to /signin when no URL comes back", async () => {
    setSessionStateForTest({ status: "signed_in", session: SESSION });
    setAuthMode("login");
    const seen = stubFetch({ "POST /auth/logout": { status: 200, body: { end_session_url: null } } });
    const navigate = vi.fn();
    await expect(signOut(navigate)).resolves.toBe(SIGNIN_PATH);
    expect(seen.mock.calls[0][0]).toBe("/auth/logout");
    expect((seen.mock.calls[0][1] as RequestInit).method).toBe("POST");
    expect(navigate).toHaveBeenCalledWith(SIGNIN_PATH);
    expect(assign).not.toHaveBeenCalled();
    expect(getSessionState()).toEqual({ status: "signed_out", ended: false });
  });

  it("navigates by script to an accepted end-session URL", async () => {
    setSessionStateForTest({ status: "signed_in", session: SESSION });
    setAuthMode("login");
    const url = "https://idp.bank.example/logout?client_id=kavach-console";
    stubFetch({ "POST /auth/logout": { status: 200, body: { end_session_url: url } } });
    const navigate = vi.fn();
    await signOut(navigate);
    expect(assign).toHaveBeenCalledWith(url);
    expect(navigate).not.toHaveBeenCalled();
  });

  it("refuses a javascript: end-session URL and goes to /signin instead", async () => {
    setSessionStateForTest({ status: "signed_in", session: SESSION });
    setAuthMode("login");
    stubFetch({
      "POST /auth/logout": { status: 200, body: { end_session_url: "javascript:alert(1)" } },
    });
    const navigate = vi.fn();
    await expect(signOut(navigate)).resolves.toBe(SIGNIN_PATH);
    expect(assign).not.toHaveBeenCalled();
    expect(navigate).toHaveBeenCalledWith(SIGNIN_PATH);
  });

  it("stays signed in and reports the failure when the server does not confirm", async () => {
    setSessionStateForTest({ status: "signed_in", session: SESSION });
    setAuthMode("login");
    stubFetch({
      "POST /auth/logout": { status: 503, body: { status: 503, detail: "busy", request_id: "r-1" } },
    });
    const navigate = vi.fn();
    await expect(signOut(navigate)).rejects.toMatchObject({ status: 503, requestId: "r-1" });
    expect(getSessionState().status).toBe("signed_in");
    expect(navigate).not.toHaveBeenCalled();
  });
});

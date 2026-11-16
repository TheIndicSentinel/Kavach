// Every API call the console makes in a browser test is answered here, from
// the typed fixtures. Nothing reaches a real backend, and a request to any
// other origin is refused and fails the test.
import { expect, test as base, type Page, type Request } from "@playwright/test";
import * as body from "./fixtures";

export type Stub = { status?: number; json: unknown };

/** A stub, or a function of the request that returns one. */
export type Answer = Stub | ((request: Request) => Stub);

/** Keyed by method and decoded path, e.g. `GET /v1/agents/agent:kyc-bot`. */
export type Stubs = Record<string, Answer>;

const ok = (json: unknown): Stub => ({ json });

export const defaultStubs: Stubs = {
  "GET /health": ok({ status: "ok" }),
  "GET /v1/runtime": ok(body.runtime),
  "GET /v1/me": ok(body.meNoRoles),
  "GET /v1/principals": ok(body.principalPage),
  "GET /v1/role-bindings": ok(body.roleBindings),
  "GET /v1/packs": ok([body.packSummary]),
  "GET /v1/packs/finance-core": ok(body.pack),
  "GET /v1/models": ok([body.modelSummary]),
  "GET /v1/models/credit-risk": ok(body.model),
  "GET /v1/admin/audit": ok([body.auditEntry]),
  "GET /v1/admin/incidents": ok([body.incident]),
  "GET /v1/admin/batch-jobs": ok([body.batchJob]),
  "GET /v1/admin/batch-jobs/job-1": ok(body.batchJob),
  "GET /v1/admin/retention": ok(body.retention),
  "GET /v1/admin/tombstones": ok([body.tombstone]),
  "GET /v1/change-requests": ok([body.reinstateProposed]),
  "GET /v1/agents": ok(body.agentPage),
  "GET /v1/agents/agent:collections-bot": ok(body.neverChanged),
  "POST /v1/agents/agent:collections-bot/quarantine": ok(body.quarantineApplied),
  // No console login, --insecure-dev: the development fallback, as before login existed.
  // e2e/login.e2e.ts sets the other modes.
  "GET /auth/config": ok(body.authConfigDev),
};

const API_PREFIXES = ["/health", "/metrics", "/v1/", "/auth/"];

export type ApiStub = {
  /** Answers `key` with `answer` from now on (before or after navigation). */
  set(key: string, answer: Answer): void;
  /** Every API request answered, in order, as `METHOD /path`, with its JSON body. */
  calls: { key: string; body: unknown }[];
  /** Requests with no stub, or to another origin. Must stay empty. */
  unexpected: string[];
};

export async function stubApi(page: Page, origin: string): Promise<ApiStub> {
  const stubs: Stubs = { ...defaultStubs };
  const api: ApiStub = {
    set: (key, answer) => {
      stubs[key] = answer;
    },
    calls: [],
    unexpected: [],
  };

  await page.route("**/*", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (url.origin !== origin) {
      api.unexpected.push(`${request.method()} ${url.href} (another origin)`);
      await route.abort("blockedbyclient");
      return;
    }
    if (!API_PREFIXES.some((prefix) => url.pathname.startsWith(prefix))) {
      await route.continue(); // the console's own files, from vite preview
      return;
    }
    const key = `${request.method()} ${decodeURIComponent(url.pathname)}`;
    const answer = stubs[key];
    if (!answer) {
      api.unexpected.push(`${key} (no stub)`);
      await route.fulfill({
        status: 404,
        contentType: "application/problem+json",
        json: {
          ...body.forbidden,
          type: "/problems/not_found",
          status: 404,
          title: "Not Found",
          code: "not_found",
          detail: "no stub",
          error: "no stub",
        },
      });
      return;
    }
    api.calls.push({ key, body: request.postDataJSON() as unknown });
    const stub = typeof answer === "function" ? answer(request) : answer;
    const status = stub.status ?? 200;
    await route.fulfill({
      status,
      contentType: status >= 400 ? "application/problem+json" : "application/json",
      json: stub.json,
    });
  });
  return api;
}

/** `test` with every API call stubbed; a test fails if anything went unanswered. */
export const test = base.extend<{ api: ApiStub }>({
  api: [
    async ({ page, baseURL }, provide) => {
      const api = await stubApi(page, new URL(baseURL ?? "").origin);
      await provide(api);
      expect(api.unexpected, "requests with no stub, or to another origin").toEqual([]);
    },
    { auto: true },
  ],
});

export { expect };

/** The paths the stub answers; everything else on the origin is the console's own files. */
export { API_PREFIXES };

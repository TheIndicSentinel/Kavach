// The UI-3 API calls against a stubbed fetch: the path, method and body sent,
// and a refusal's request_id.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanReconciliation, decisionEvent, EVIDENCE_ID } from "../test/evidenceFixtures";
import { ApiError, fetchDecisionEvent, reconcileClosedRecords } from "./api";

function respond(status: number, body: unknown) {
  const fetch = vi.fn(
    async (_path: string, _init?: RequestInit) =>
      new Response(JSON.stringify(body), {
        status,
        headers: { "Content-Type": status < 400 ? "application/json" : "application/problem+json" },
      }),
  );
  vi.stubGlobal("fetch", fetch);
  return fetch;
}

beforeEach(() => {
  vi.stubGlobal("sessionStorage", { getItem: () => null, setItem: () => {}, removeItem: () => {} });
});
afterEach(() => vi.unstubAllGlobals());

describe("reconcileClosedRecords", () => {
  it("posts the list as JSON to the closed-records endpoint", async () => {
    const fetch = respond(200, cleanReconciliation);
    const body = {
      system: "lms",
      records: [{ record_ref: "lms:loan/L-1", state: "paid" as const, closed_at: "2026-10-01T06:00:00Z" }],
    };
    await expect(reconcileClosedRecords(body)).resolves.toEqual(cleanReconciliation);
    const [path, init] = fetch.mock.calls[0];
    expect(path).toBe("/v1/reconciliation/closed-records");
    expect(init?.method).toBe("POST");
    expect(JSON.parse(String(init?.body))).toEqual(body);
  });

  it("reports a rate-limit refusal with its request_id", async () => {
    respond(429, { status: 429, detail: "too many reconciliations", request_id: "req-429" });
    const err = await reconcileClosedRecords({ system: "lms", records: [] }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).status).toBe(429);
    expect((err as ApiError).detail).toBe("too many reconciliations");
    expect((err as ApiError).requestId).toBe("req-429");
  });
});

describe("fetchDecisionEvent", () => {
  it("reads one event by its evidence id", async () => {
    const fetch = respond(200, decisionEvent);
    await expect(fetchDecisionEvent(EVIDENCE_ID)).resolves.toEqual(decisionEvent);
    expect(fetch.mock.calls[0][0]).toBe(`/v1/decision-events/${EVIDENCE_ID}`);
    expect(fetch.mock.calls[0][1]?.method).toBe("GET");
  });

  it("encodes the id into the path", async () => {
    const fetch = respond(200, decisionEvent);
    await fetchDecisionEvent("../x");
    expect(fetch.mock.calls[0][0]).toBe("/v1/decision-events/..%2Fx");
  });

  it("reports not found with its request_id", async () => {
    respond(404, { status: 404, detail: "no such decision event", request_id: "req-404" });
    const err = (await fetchDecisionEvent(EVIDENCE_ID).catch((e: unknown) => e)) as ApiError;
    expect(err.status).toBe(404);
    expect(err.message).toBe("no such decision event (request req-404)");
  });
});

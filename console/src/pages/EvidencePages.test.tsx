// What the UI-3 pages render before anything is sent (static markup runs no
// effects, and both pages call the API only on submit): labelled inputs, the
// notices, and empty status and alert regions.
import { describe, expect, it } from "vitest";
import type { ClosedRecordsResult } from "../lib/api";
import { EVIDENCE_ID, cleanReconciliation, decisionEvent } from "../test/evidenceFixtures";
import { byRole, render, text } from "../test/markup";
import {
  badGateway,
  forbidden,
  lookupFailed,
  lookupLoading,
  notFound,
  problem,
  serverError,
  unauthorized,
} from "../test/states";
import DecisionEventsPage, { type FoundEvent } from "./DecisionEventsPage";
import ReconciliationPage from "./ReconciliationPage";

const SKELETON = 'class="animate-pulse';

describe("DecisionEventsPage", () => {
  const html = render(<DecisionEventsPage />);
  const shown = text(html);

  it("labels the evidence id field and says the format it needs", () => {
    expect(html).toContain('<label for="decision-event-id"');
    expect(html).toContain('id="decision-event-id"');
    expect(shown).toContain("A lowercase UUID");
  });

  it("says lookups are audited and rate limited, and events are not signed", () => {
    expect(shown).toContain("audited");
    expect(shown).toContain("rate limited");
    expect(shown).toContain("not signed");
  });

  it("starts with empty status and alert regions, and nothing looked up", () => {
    expect(byRole(html, "status")).toEqual([""]);
    expect(byRole(html, "alert")).toEqual([""]);
    expect(html).toMatch(/<button[^>]*type="submit"[^>]*aria-disabled="false"[^>]*>Look up event</);
    expect(shown).not.toContain("Verify it yourself");
  });
});

describe("ReconciliationPage", () => {
  const html = render(<ReconciliationPage />);
  const shown = text(html);

  it("labels the file input and the list", () => {
    expect(html).toContain('<label for="closed-records-file"');
    expect(html).toContain('<label for="closed-records-list"');
    expect(html).toContain('aria-describedby="closed-records-list-hint"');
    expect(html).not.toContain("aria-invalid");
  });

  it("says the call revokes nothing and is audited and rate limited", () => {
    expect(shown).toContain("This call revokes nothing.");
    expect(shown).toContain("audited");
    expect(shown).toContain("rate limited");
  });

  it("starts with empty status and alert regions, and a Reconcile button", () => {
    expect(byRole(html, "status")).toEqual([""]);
    expect(byRole(html, "alert")).toEqual([""]);
    expect(html).toMatch(/<button[^>]*type="submit"[^>]*>Reconcile</);
    expect(html).toMatch(/<button[^>]*type="button"[^>]*>Clear the list and results</);
  });
});

describe("DecisionEventsPage states", () => {
  const at = (lookup: Parameters<typeof DecisionEventsPage>[0]["lookup"]) =>
    render(<DecisionEventsPage lookup={lookup} />);
  const alert = (error: unknown) => byRole(at(lookupFailed<FoundEvent>("x", error)), "alert")[0];

  it("loading: what is being looked up, a skeleton, and the button aria-disabled", () => {
    const html = at(lookupLoading<FoundEvent>(`Looking up decision event ${EVIDENCE_ID}`));
    expect(byRole(html, "status")).toEqual([`Looking up decision event ${EVIDENCE_ID}…`]);
    expect(html).toContain(SKELETON);
    expect(html).toMatch(/aria-disabled="true"[^>]*>Look up event</);
  });

  it("found: the event id in role=status", () => {
    const html = at({ phase: "done", what: "x", result: { evidenceId: EVIDENCE_ID, lookup: decisionEvent } });
    expect(byRole(html, "status")[0]).toBe(`Found decision event ${EVIDENCE_ID}.`);
  });

  it("404: says no such event exists, with the server's detail and request_id", () => {
    expect(alert(notFound)).toBe(
      "No decision event with that evidence id on this server. no such record · HTTP 404 · request_id req-404",
    );
  });

  it("error, a non-JSON 502, 401 and 403", () => {
    expect(alert(serverError)).toBe("storage unavailable HTTP 500 · request_id req-500");
    expect(alert(badGateway("/v1/decision-events/x"))).toContain("no request_id was returned");
    expect(alert(unauthorized)).toContain("Sign in again");
    expect(alert(forbidden)).toContain("Not permitted");
  });

  // Empty: nothing is looked up until a submit; the idle page above is the
  // "nothing yet" state.
});

describe("ReconciliationPage states", () => {
  const at = (lookup: Parameters<typeof ReconciliationPage>[0]["lookup"]) =>
    render(<ReconciliationPage lookup={lookup} />);
  const alert = (error: unknown) =>
    byRole(at(lookupFailed<ClosedRecordsResult>("x", error)), "alert")[0];

  it("loading: how many loans, a skeleton, and Reconcile aria-disabled", () => {
    const html = at(lookupLoading<ClosedRecordsResult>("Reconciling 2 loans"));
    expect(byRole(html, "status")).toEqual(["Reconciling 2 loans…"]);
    expect(html).toContain(SKELETON);
    expect(html).toMatch(/aria-disabled="true"[^>]*>Reconcile</);
  });

  it("empty: no loan holds a live mandate, and nothing was revoked", () => {
    const html = at({ phase: "done", what: "x", result: cleanReconciliation });
    expect(byRole(html, "status")).toEqual([
      "Checked 2 loans: none holds a live mandate. Nothing was revoked.",
    ]);
    expect(text(html)).toContain("No loan in the list holds a live mandate.");
  });

  it("error, a non-JSON 502, 401 and 403", () => {
    expect(alert(problem(422, "records: too many"))).toBe("records: too many HTTP 422 · request_id req-422");
    expect(alert(badGateway("/v1/reconciliation/closed-records"))).toContain("no request_id was returned");
    expect(alert(unauthorized)).toContain("Sign in again");
    expect(alert(forbidden)).toContain("Not permitted");
  });

  // 404: not a state of this page. It sends a list and takes no id.
});

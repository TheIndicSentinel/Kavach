// What the UI-3 pages render before anything is sent (static markup runs no
// effects, and both pages call the API only on submit): labelled inputs, the
// notices, and empty status and alert regions.
import { describe, expect, it } from "vitest";
import { byRole, render, text } from "../test/markup";
import DecisionEventsPage from "./DecisionEventsPage";
import ReconciliationPage from "./ReconciliationPage";

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

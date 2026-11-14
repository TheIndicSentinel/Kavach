// What the agent pages render before any data arrives (static markup runs no
// effects, so nothing is fetched here): loading in role=status, an empty
// role=alert, labelled controls, and no actions.
import { describe, expect, it } from "vitest";
import { byRole, render, text } from "../test/markup";
import AgentEvidencePage from "./AgentEvidencePage";
import AgentsPage from "./AgentsPage";

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

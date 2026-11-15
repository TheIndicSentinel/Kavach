import { createElement } from "react";
import { describe, expect, it } from "vitest";
import { CREDIT_TRACK_PATHS, isCreditTrackPath } from "../../lib/creditTrack";
import { render, text } from "../../test/markup";
import { Sidebar } from "./Sidebar";

const nav = (agentOnly: boolean | null) =>
  text(render(createElement(Sidebar, { open: true, onNavigate: () => {}, agentOnly })));

const CREDIT_LABELS = ["Evaluate", "Policies", "Models", "Batch jobs", "Incidents", "Retention", "Decision events"];
const BOTH_TRACKS = ["Overview", "Settings", "Agents", "Agent evidence", "Closed loans", "Change requests", "Audit"];

describe("isCreditTrackPath", () => {
  it("matches each credit-track page and its detail pages", () => {
    for (const path of CREDIT_TRACK_PATHS) {
      expect(isCreditTrackPath(path)).toBe(true);
      expect(isCreditTrackPath(`${path}/some-id`)).toBe(true);
    }
  });

  it("does not match the agent pages, change requests, audit or a longer name", () => {
    for (const path of ["/overview", "/agents", "/agents/agent:x", "/changes", "/audit", "/settings", "/modelsx"]) {
      expect(isCreditTrackPath(path)).toBe(false);
    }
  });
});

describe("Sidebar", () => {
  it("leaves the credit track out when the server runs agent-only", () => {
    const shown = nav(true);
    for (const label of CREDIT_LABELS) expect(shown).not.toMatch(new RegExp(`\\b${label}\\b`));
    for (const label of BOTH_TRACKS) expect(shown).toContain(label);
    expect(shown).toContain("Authorization and runtime control for AI agents.");
  });

  it("shows every page when the server serves the credit track, or has not said", () => {
    for (const agentOnly of [false, null]) {
      const shown = nav(agentOnly);
      for (const label of [...CREDIT_LABELS, ...BOTH_TRACKS]) expect(shown).toContain(label);
    }
  });
});

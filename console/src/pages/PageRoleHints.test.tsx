// The role hint on each page's action, rendered to static markup: groups known
// to allow the action keep the control, groups known to lack it get one line
// that the server decides, and unknown groups keep every control.
import { describe, expect, it } from "vitest";
import type { ReactElement } from "react";
import { UNKNOWN_VIEWER, type Viewer } from "../lib/permissions";
import { render, text } from "../test/markup";
import AgentEvidencePage from "./AgentEvidencePage";
import DecisionEventsPage from "./DecisionEventsPage";
import EvaluatePage from "./EvaluatePage";
import ReconciliationPage from "./ReconciliationPage";

type Surface = {
  name: string;
  page: (viewer: Viewer) => ReactElement;
  /** The submit buttons the action has. */
  buttons: string[];
  allowed: string[];
  denied: string[];
  line: string;
  /** How many times the line shows (one per action on the page). */
  lines: number;
};

const surfaces: Surface[] = [
  {
    name: "AgentEvidencePage",
    page: (viewer) => <AgentEvidencePage viewer={viewer} />,
    buttons: ["Look up record", "Look up revocation"],
    allowed: ["admins"],
    denied: ["operators", "change-approvers"],
    line: "may read evidence records. The server decides",
    lines: 2,
  },
  {
    name: "DecisionEventsPage",
    page: (viewer) => <DecisionEventsPage viewer={viewer} />,
    buttons: ["Look up event"],
    allowed: ["admins"],
    denied: ["viewers"],
    line: "may read decision events. The server decides",
    lines: 1,
  },
  {
    name: "ReconciliationPage",
    page: (viewer) => <ReconciliationPage viewer={viewer} />,
    buttons: ["Reconcile"],
    allowed: ["admins"],
    denied: ["operators"],
    line: "may reconcile closed loans. The server decides",
    lines: 1,
  },
  {
    name: "EvaluatePage",
    page: (viewer) => <EvaluatePage viewer={viewer} />,
    buttons: ["Run evaluate"],
    allowed: ["operators"],
    denied: ["viewers", "change-approvers"],
    line: "may run evaluate. The server decides",
    lines: 1,
  },
];

const count = (haystack: string, needle: string) => haystack.split(needle).length - 1;

describe.each(surfaces)("$name: role hint", (surface) => {
  it("known allowed: the control shows and there is no hint", () => {
    const html = render(surface.page({ principal: null, groups: surface.allowed }));
    for (const label of surface.buttons) expect(html).toContain(`${label}</button>`);
    expect(text(html)).not.toContain("Your groups");
  });

  it("known denied: no control, and one line per action saying the server decides", () => {
    const html = render(surface.page({ principal: null, groups: surface.denied }));
    expect(html).not.toContain('type="submit"');
    for (const label of surface.buttons) expect(html).not.toContain(`${label}</button>`);
    expect(count(text(html), surface.line)).toBe(surface.lines);
    expect(text(html)).toContain(`Your groups (${surface.denied.join(", ")})`);
  });

  it("unknown groups: the control shows and there is no hint", () => {
    const html = render(surface.page(UNKNOWN_VIEWER));
    for (const label of surface.buttons) expect(html).toContain(`${label}</button>`);
    expect(text(html)).not.toContain("Your groups");
  });
});

describe("EvaluatePage: keyboard and alerts", () => {
  const html = render(<EvaluatePage viewer={UNKNOWN_VIEWER} />);

  it("keeps the submit button focusable (aria-disabled, not disabled)", () => {
    expect(html).toMatch(/<button[^>]*type="submit"[^>]*aria-disabled="false"/);
    expect(html).not.toMatch(/<button[^>]*\sdisabled=""/);
  });

  it("starts with empty alert and status regions and a labelled request field", () => {
    expect(html).toContain('<label for="request-json"');
    expect(html).toMatch(/<div role="alert"[^>]*><\/div>/);
    expect(html).toMatch(/<p role="status"[^>]*><\/p>/);
    expect(html).not.toContain("aria-invalid");
  });
});

// The change-request buttons rendered to static markup, for each principal and
// set of groups the console can or cannot identify.
import { describe, expect, it } from "vitest";
import { reinstateProposed } from "../test/fixtures";
import { render, text } from "../test/markup";
import { UNKNOWN_VIEWER, type Viewer } from "../lib/permissions";
import { RequestButtons } from "./ChangeRequestsPage";

function markup(viewer: Viewer, request = reinstateProposed, busy = false) {
  return render(<RequestButtons request={request} viewer={viewer} busy={busy} onAct={() => {}} />);
}

function buttons(viewer: Viewer, request = reinstateProposed) {
  return text(markup(viewer, request));
}

describe("RequestButtons: the proposer rule", () => {
  it("gives the proposer no approve or reject button", () => {
    const shown = buttons({ principal: "operator-1", groups: null });
    expect(shown).not.toContain("Approve and apply");
    expect(shown).not.toContain("Reject");
    expect(shown).toContain("Cancel (proposer)");
    expect(shown).toContain("a different principal approves or rejects it");
  });

  it("gives another principal approve and reject", () => {
    const shown = buttons({ principal: "admin-2", groups: null });
    expect(shown).toContain("Approve and apply");
    expect(shown).toContain("Reject");
    expect(shown).not.toContain("Cancel (proposer)");
  });

  it("leaves every button to the API when the principal is unknown", () => {
    const shown = buttons(UNKNOWN_VIEWER);
    expect(shown).toContain("Approve and apply");
    expect(shown).toContain("Reject");
    expect(shown).toContain("Cancel (proposer)");
    expect(shown).not.toContain("Your groups");
  });

  it("renders nothing for a decided request", () => {
    expect(buttons(UNKNOWN_VIEWER, { ...reinstateProposed, status: "applied" })).toBe("");
  });

  it("keeps focusable buttons while a request is in flight (aria-disabled, not disabled)", () => {
    const html = markup(UNKNOWN_VIEWER, reinstateProposed, true);
    expect(html).not.toMatch(/<button[^>]*\sdisabled=""/);
    expect(html).toMatch(/aria-disabled="true"[^>]*>Approve and apply</);
  });
});

describe("RequestButtons: role hints", () => {
  it("known allowed: admins and change-approvers get every button and no hint", () => {
    const shown = buttons({ principal: null, groups: ["admins", "change-approvers"] });
    expect(shown).toContain("Approve and apply");
    expect(shown).toContain("Reject");
    expect(shown).toContain("Cancel (proposer)");
    expect(shown).not.toContain("Your groups");
  });

  it("known denied: viewers get one line in place of the buttons", () => {
    const html = markup({ principal: null, groups: ["viewers"] });
    expect(html).not.toContain("<button");
    expect(text(html)).toBe(
      "Your groups (viewers) don't include one that may approve, reject or cancel this change. The server decides; ask an admin if you need this.",
    );
  });

  it("partly denied: change-approvers keep approve and reject, with a line about cancel", () => {
    const shown = buttons({ principal: null, groups: ["change-approvers"] });
    expect(shown).toContain("Approve and apply");
    expect(shown).not.toContain("Cancel (proposer)");
    expect(shown).toContain("don't include one that may cancel this change");
  });

  it("unknown groups: no hint, whatever the principal", () => {
    for (const principal of [null, "operator-1", "admin-2"]) {
      expect(buttons({ principal, groups: null })).not.toContain("Your groups");
    }
  });
});

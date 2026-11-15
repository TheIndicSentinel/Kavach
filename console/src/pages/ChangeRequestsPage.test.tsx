// The change-request buttons rendered to static markup, for each principal the
// console can or cannot identify.
import { describe, expect, it } from "vitest";
import { reinstateProposed } from "../test/fixtures";
import { render, text } from "../test/markup";
import type { Viewer } from "../lib/changeRequests";
import { RequestButtons } from "./ChangeRequestsPage";

function buttons(viewer: Viewer, request = reinstateProposed) {
  return text(render(<RequestButtons request={request} viewer={viewer} busy={false} onAct={() => {}} />));
}

describe("RequestButtons", () => {
  it("gives the proposer no approve or reject button", () => {
    const shown = buttons({ kind: "principal", id: "operator-1" });
    expect(shown).not.toContain("Approve and apply");
    expect(shown).not.toContain("Reject");
    expect(shown).toContain("Cancel (proposer)");
    expect(shown).toContain("a different principal approves or rejects it");
  });

  it("gives another principal approve and reject", () => {
    const shown = buttons({ kind: "principal", id: "admin-2" });
    expect(shown).toContain("Approve and apply");
    expect(shown).toContain("Reject");
    expect(shown).not.toContain("Cancel (proposer)");
  });

  it("leaves every button to the API when the principal is unknown", () => {
    const shown = buttons({ kind: "unknown" });
    expect(shown).toContain("Approve and apply");
    expect(shown).toContain("Reject");
    expect(shown).toContain("Cancel (proposer)");
  });

  it("renders nothing for a decided request", () => {
    expect(buttons({ kind: "unknown" }, { ...reinstateProposed, status: "applied" })).toBe("");
  });
});

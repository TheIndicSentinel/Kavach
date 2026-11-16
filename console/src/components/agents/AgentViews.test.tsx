// The agent list, agent detail and evidence views, rendered to static markup.
import { describe, expect, it } from "vitest";
import { byRole, render, text } from "../../test/markup";
import {
  decisionLookup,
  neverChanged,
  quarantined,
  reinstated,
  revocationLookup,
} from "../../test/fixtures";
import { AgentStateDetails, AgentTable } from "./AgentViews";
import { DecisionRecordView, EvidenceNotice, RevocationRecordView } from "./EvidenceViews";

describe("AgentTable", () => {
  it("lists each agent with a link to it and its state as text", () => {
    const html = render(<AgentTable agents={[neverChanged, quarantined]} emptyMessage="none" />);
    expect(html).toContain('href="/agents/agent%3Acollections-bot"');
    expect(html).toContain('href="/agents/agent%3Apayments-bot"');
    const shown = text(html);
    expect(shown).toContain("quarantined");
    expect(shown).toContain("compromise_suspected");
    expect(shown).toContain("0 (never changed)");
  });

  it("shows the empty message when the page holds no agents", () => {
    const html = render(<AgentTable agents={[]} emptyMessage="No revoked agents." />);
    expect(text(html)).toBe("No revoked agents.");
    expect(html).not.toContain("<table");
  });
});

describe("AgentStateDetails", () => {
  it("says an agent never changed is active, never changed", () => {
    const shown = text(render(<AgentStateDetails agent={neverChanged} />));
    expect(shown).toContain("active, never changed");
    expect(shown).not.toContain("Reason code");
  });

  it("shows every field of a changed agent, and none for what is unset", () => {
    const shown = text(render(<AgentStateDetails agent={quarantined} />));
    for (const expected of [
      "State quarantined",
      "Change number 3",
      "Reason code compromise_suspected",
      "Note key seen on a paste site",
      "Changed by operator-1",
      "Approved by none",
      "Change request none",
    ]) {
      expect(shown).toContain(expected);
    }
    expect(shown).not.toContain("never changed");
  });

  it("shows the approver and change request of a reinstatement", () => {
    const html = render(<AgentStateDetails agent={reinstated} />);
    const shown = text(html);
    expect(shown).toContain("Approved by admin-2");
    expect(shown).toContain("Change request cr-0042");
    expect(html).toContain('dateTime="2026-11-14T11:30:00Z"');
  });
});

describe("evidence views", () => {
  it("says lookups are audited and rate limited, and claims nothing beyond the verifier", () => {
    const shown = text(render(<EvidenceNotice />));
    expect(shown).toContain("audited");
    expect(shown).toContain("rate limited");
    expect(shown).toContain("signature verified against the listed keys");
    expect(shown).toContain("One record proves nothing about the chain.");
    expect(shown).not.toMatch(/compliant|production-grade|latency/i);
  });

  it("shows a decision record and says when no outcome is recorded", () => {
    const shown = text(render(<DecisionRecordView result={decisionLookup} />));
    expect(shown).toContain("adr:bank-1:0:42");
    expect(shown).toContain("Returned decision BLOCK");
    expect(shown).toContain("sha256-jcs-v1 recordhash42");
    expect(shown).toContain("No outcome is recorded for this record.");
  });

  it("shows a decision record's outcome when there is one", () => {
    const withOutcome = {
      ...decisionLookup,
      outcome: {
        tenant_id: "bank-1",
        credential_id: "cred-1",
        record_hash: "recordhash42",
        outcome: "delivered" as const,
        ts: "2026-11-14T09:00:05Z",
        key_id: "evidence-key-1",
        sig: "sigout",
      },
    };
    const shown = text(render(<DecisionRecordView result={withOutcome} />));
    expect(shown).toContain("Outcome Delivered: The provider accepted the call.");
    expect(shown).not.toContain("No outcome is recorded");
  });

  it("shows a revocation record with every mandate it revoked", () => {
    const shown = text(render(<RevocationRecordView result={revocationLookup} />));
    expect(shown).toContain("los-core");
    expect(shown).toContain("evt-9");
    expect(shown).toContain("mandate-7");
    expect(shown).toContain("mandate-8");
    expect(shown).toContain("sha256-jcs-v1:abc");
  });

  it("renders no role=alert of its own, and only the empty copy-feedback status regions", () => {
    const html = render(<RevocationRecordView result={revocationLookup} />);
    // One role=status per verify command (UI-3), each empty until Copy is pressed.
    expect(byRole(html, "status")).toEqual(["", ""]);
    expect(byRole(html, "alert")).toEqual([]);
  });
});

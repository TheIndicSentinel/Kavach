// The UI-3 evidence views, rendered to static markup: decision events, the
// verify commands, a lookup's states and the reconciliation results.
import { describe, expect, it } from "vitest";
import { ApiError } from "../../lib/api";
import { byRole, render, text } from "../../test/markup";
import { decisionLookup, revocationLookup } from "../../test/fixtures";
import {
  cleanReconciliation,
  decisionEvent,
  EVIDENCE_ID,
  reconciliation,
  shadowEvent,
  tombstonedEvent,
} from "../../test/evidenceFixtures";
import { DecisionRecordView, RevocationRecordView } from "../agents/EvidenceViews";
import type { Lookup } from "../../hooks/useLookup";
import { ClosedRecordsCounts, ClosedRecordsFindings, ClosedRecordsNotice } from "./ClosedRecordsViews";
import { DecisionEventNotice, DecisionEventView } from "./DecisionEventView";
import { LookupPanel, lookupStatus } from "./LookupPanel";
import { VerifyCommands } from "./VerifyCommands";

/** The text of every verify-command code block (the selectable ones), in order. */
function codeBlocks(html: string): string[] {
  return [...html.matchAll(/<code id="[^"]*" class="select-all[^>]*>([\s\S]*?)<\/code>/g)].map((m) =>
    text(m[1]),
  );
}

describe("VerifyCommands", () => {
  const commands = [
    { label: "Check the chain", command: "kavach-evidence verify --file ./x.ndjson", note: "Exits non-zero on a break." },
  ];
  const html = render(<VerifyCommands commands={commands} />);

  it("puts each command in a selectable code block with a labelled Copy button", () => {
    expect(codeBlocks(html)).toEqual(["kavach-evidence verify --file ./x.ndjson"]);
    expect(html).toMatch(/<code id="([^"]+)" class="select-all/);
    const codeId = /<code id="([^"]+)"/.exec(html)?.[1];
    expect(html).toContain(`aria-label="Copy: Check the chain"`);
    expect(html).toContain(`aria-describedby="${codeId}"`);
    expect(html).toMatch(/<button[^>]*type="button"[^>]*>Copy<\/button>/);
  });

  it("says the console verifies nothing, and starts with an empty copy status", () => {
    expect(text(html)).toContain("The console does not verify signatures or hashes");
    expect(byRole(html, "status")).toEqual([""]);
  });
});

describe("DecisionEventNotice", () => {
  const shown = text(render(<DecisionEventNotice />));

  it("says lookups are audited and rate limited", () => {
    expect(shown).toContain("audited");
    expect(shown).toContain("rate limited");
  });

  it("says events are not signed and one event proves nothing about the chain", () => {
    expect(shown).toContain("hash-chained but not signed");
    expect(shown).toContain("One event proves nothing about the chain.");
  });
});

describe("DecisionEventView", () => {
  const html = render(<DecisionEventView result={decisionEvent} evidenceId={EVIDENCE_ID} />);
  const shown = text(html);

  it("shows the event's decision, reasons, pack, model and chain links", () => {
    for (const value of [
      EVIDENCE_ID,
      "evt-77",
      "DTI_ABOVE_LIMIT",
      "dti.max",
      "rbi-digital-lending 1.2.0",
      "pd-model 3.1 (in_house)",
      "sha256:inputdigest",
      "eventhash77",
      "prevhash76",
      "enforce",
    ]) {
      expect(shown, value).toContain(value);
    }
  });

  it("leaves out PII tokens, the idempotency key and latency", () => {
    expect(shown).not.toContain("tok-1");
    expect(shown).not.toContain("idem-1");
    expect(shown).not.toMatch(/latency/i);
  });

  it("says plainly that this response carries no outcome", () => {
    expect(shown).toContain("Not part of this response");
    expect(shown).toContain("no outcome field");
  });

  it("offers the decision-event verify commands, and never says signature verified", () => {
    expect(codeBlocks(html)).toEqual([
      "kavach-evidence verify --file ./decision-events.ndjson",
      `kavach why ${EVIDENCE_ID} --export ./decision-events.ndjson`,
    ]);
    expect(shown).toContain("decision events carry no signature to verify");
    expect(shown).not.toMatch(/signature verified/i);
    expect(byRole(html, "status")).toEqual(["", ""]);
  });

  it("shows no banner for an enforced, live event", () => {
    expect(shown).not.toContain("Tombstoned");
    expect(shown).not.toContain("Shadow mode");
  });

  it("says when shadow mode hid a would-be decision", () => {
    expect(text(render(<DecisionEventView result={shadowEvent} evidenceId={EVIDENCE_ID} />))).toContain(
      "Shadow mode: the PASS return hides a would-be BLOCK.",
    );
  });

  it("marks a tombstoned event and still builds commands from the id looked up", () => {
    const erased = render(<DecisionEventView result={tombstonedEvent} evidenceId={EVIDENCE_ID} />);
    expect(text(erased)).toContain("Tombstoned: this is the redacted form.");
    expect(text(erased)).toContain("ERASED");
    expect(codeBlocks(erased)[1]).toBe(`kavach why ${EVIDENCE_ID} --export ./decision-events.ndjson`);
  });
});

describe("UI-1 record views", () => {
  it("adds the bundle verify commands and outcome wording to an agent decision record", () => {
    const html = render(<DecisionRecordView result={decisionLookup} />);
    expect(text(html)).toContain("No outcome is recorded for this record.");
    expect(codeBlocks(html)).toContain(
      "kavach why adr:bank-1:0:42 --bundle ./bundle --keys ./trusted-keys.json",
    );
    expect(text(html)).not.toMatch(/signature verified/i);
  });

  it("words a recorded outcome", () => {
    const delivered = {
      ...decisionLookup,
      outcome: {
        tenant_id: "bank-1",
        credential_id: "cred-1",
        record_hash: "recordhash42",
        outcome: "refused" as const,
        reason: "provider_4xx",
        ts: "2026-11-14T09:00:01Z",
        key_id: "evidence-key-1",
        sig: "outsig",
      },
    };
    expect(text(render(<DecisionRecordView result={delivered} />))).toContain("Refused:");
  });

  it("adds the bundle verify commands to a revocation record", () => {
    const html = render(<RevocationRecordView result={revocationLookup} />);
    expect(codeBlocks(html)).toContain(
      "kavach-evidence verify-bundle ./bundle --keys ./trusted-keys.json --expect-checkpoint ./kept-checkpoints.jsonl",
    );
  });
});

describe("LookupPanel", () => {
  const done = (result: string) => `Found ${result}.`;
  const panel = (lookup: Lookup<string>) =>
    render(<LookupPanel lookup={lookup} done={done} render={(result) => <p>result: {result}</p>} />);

  it("keeps empty status and alert regions before any lookup", () => {
    const html = panel({ phase: "idle" });
    expect(byRole(html, "status")).toEqual([""]);
    expect(byRole(html, "alert")).toEqual([""]);
    expect(text(html)).toBe("");
  });

  it("announces loading in role=status", () => {
    const html = panel({ phase: "loading", what: "Looking up decision event x" });
    expect(byRole(html, "status")).toEqual(["Looking up decision event x…"]);
    expect(byRole(html, "alert")).toEqual([""]);
  });

  it("shows a refusal's detail, status and request_id in role=alert", () => {
    const error = new ApiError("too many lookups (request req-429)", 429, "req-429", "too many lookups");
    const html = panel({ phase: "error", what: "x", error });
    const [alert] = byRole(html, "alert");
    expect(alert).toContain("too many lookups");
    expect(alert).toContain("HTTP 429");
    expect(alert).toContain("request_id req-429");
    expect(byRole(html, "status")).toEqual([""]);
    expect(text(html)).not.toContain("result:");
  });

  it("summarises a result in role=status and renders it", () => {
    const html = panel({ phase: "done", what: "x", result: "the event" });
    expect(byRole(html, "status")).toEqual(["Found the event."]);
    expect(text(html)).toContain("result: the event");
  });

  it("words each phase for the status region", () => {
    expect(lookupStatus({ phase: "idle" }, done)).toBe("");
    expect(lookupStatus({ phase: "error", what: "x", error: null }, done)).toBe("");
  });
});

describe("ClosedRecordsNotice", () => {
  const shown = text(render(<ClosedRecordsNotice />));

  it("says the call revokes nothing, and is rate limited and audited by counts", () => {
    expect(shown).toContain("This call revokes nothing.");
    expect(shown).toContain("rate limited");
    expect(shown).toContain("audited");
    expect(shown).toContain("never loan references");
  });

  it("asks for references only and says the console keeps none of the list", () => {
    expect(shown).toContain("never by a borrower's name");
    expect(shown).toContain("the console stores none of it");
    expect(shown).toContain("Up to 1000 loans per run.");
  });
});

describe("closed-records results", () => {
  it("shows the counts, and the remedy only when a mandate should have been revoked", () => {
    const withMismatch = text(render(<ClosedRecordsCounts result={reconciliation} />));
    expect(withMismatch).toContain("Loans checked 3");
    expect(withMismatch).toContain("Should have been revoked 1");
    expect(withMismatch).toContain("To confirm 1");
    expect(withMismatch).toContain("resend the signed event");
    expect(text(render(<ClosedRecordsCounts result={cleanReconciliation} />))).not.toContain(
      "resend the signed event",
    );
  });

  it("lists mismatches first, each with its kind in words", () => {
    const shown = text(render(<ClosedRecordsFindings result={reconciliation} />));
    expect(shown.indexOf("mandate-11")).toBeLessThan(shown.indexOf("mandate-21"));
    expect(shown).toContain("Should have been revoked");
    expect(shown).toContain("To confirm");
    expect(shown).toContain("lms:loan/L-1");
    expect(shown).toContain("agent:payments-bot");
  });

  it("says so when no loan holds a live mandate", () => {
    const html = render(<ClosedRecordsFindings result={cleanReconciliation} />);
    expect(text(html)).toBe("No loan in the list holds a live mandate.");
    expect(html).not.toContain("<table");
  });
});

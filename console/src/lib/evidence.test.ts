// The evidence pages' pure parts: input checks, the verify commands, the
// copy feedback, and the words for outcomes and reconciliation findings.
import { describe, expect, it, vi } from "vitest";
import { cleanReconciliation, EVIDENCE_ID, reconciliation } from "../test/evidenceFixtures";
import type { Outcome } from "./api";
import {
  COPIED,
  COPY_FAILED,
  CLOSED_RECORDS_LIMITS,
  FINDING_WORDING,
  OUTCOME_WORDING,
  agentDecisionCommands,
  copyCommand,
  decisionEventCommands,
  evidenceIdProblem,
  outcomeText,
  parseClosedRecords,
  reconciliationSummary,
  revocationCommands,
  shellWord,
  sortFindings,
} from "./evidence";

describe("evidenceIdProblem", () => {
  it("accepts a canonical lowercase UUID", () => {
    expect(evidenceIdProblem(EVIDENCE_ID)).toBeNull();
  });

  it("asks for lowercase rather than spend a read on the API's refusal", () => {
    expect(evidenceIdProblem(EVIDENCE_ID.toUpperCase())).toMatch(/lowercase/);
  });

  it("refuses empty, short, unhyphenated, non-hex and path-like values", () => {
    expect(evidenceIdProblem("")).toBe("Enter an evidence id.");
    for (const bad of [
      "9771a6c1-edc5-4b2b-b38d-ffb397b7df5",
      "9771a6c1edc54b2bb38dffb397b7df55",
      "9771a6c1-edc5-4b2b-b38d-ffb397b7df5g",
      "../../etc/passwd",
      ` ${EVIDENCE_ID}`,
    ]) {
      expect(evidenceIdProblem(bad), bad).toMatch(/UUID/);
    }
  });
});

describe("shellWord", () => {
  it("leaves plain ids alone and single-quotes anything else", () => {
    expect(shellWord("adr:bank-1:0:42")).toBe("adr:bank-1:0:42");
    expect(shellWord(EVIDENCE_ID)).toBe(EVIDENCE_ID);
    expect(shellWord("a b")).toBe("'a b'");
    expect(shellWord("$(rm -rf ~)")).toBe("'$(rm -rf ~)'");
    expect(shellWord("it's")).toBe(`'it'\\''s'`);
    expect(shellWord("")).toBe("''");
  });
});

describe("verify commands", () => {
  it("checks a decision event with kavach-evidence verify and kavach why --export", () => {
    expect(decisionEventCommands(EVIDENCE_ID).map((c) => c.command)).toEqual([
      "kavach-evidence verify --file ./decision-events.ndjson",
      `kavach why ${EVIDENCE_ID} --export ./decision-events.ndjson`,
    ]);
  });

  it("never claims a signature check for decision events, which are not signed", () => {
    for (const { label, note } of decisionEventCommands(EVIDENCE_ID)) {
      expect(`${label} ${note}`).not.toMatch(/signature/i);
    }
  });

  it("checks an agent decision record's bundle, explains it, and offers the independent verifier", () => {
    expect(agentDecisionCommands("adr:bank-1:0:42").map((c) => c.command)).toEqual([
      "kavach-evidence verify-bundle ./bundle --keys ./trusted-keys.json --expect-checkpoint ./kept-checkpoints.jsonl",
      "kavach why adr:bank-1:0:42 --bundle ./bundle --keys ./trusted-keys.json",
      "python3 conformance/kavach_verify.py bundle ./bundle --keys ./trusted-keys.json --expect-checkpoint ./kept-checkpoints.jsonl",
    ]);
  });

  it("quotes a record id that is not plain", () => {
    expect(agentDecisionCommands("adr:x;y:0:1")[1].command).toContain("kavach why 'adr:x;y:0:1' --bundle");
  });

  it("checks a revocation record by its bundle only (kavach why explains decisions)", () => {
    expect(revocationCommands().map((c) => c.command)).toEqual([
      "kavach-evidence verify-bundle ./bundle --keys ./trusted-keys.json --expect-checkpoint ./kept-checkpoints.jsonl",
      "python3 conformance/kavach_verify.py bundle ./bundle --keys ./trusted-keys.json --expect-checkpoint ./kept-checkpoints.jsonl",
    ]);
  });
});

describe("copyCommand", () => {
  it("writes the command and says Copied", async () => {
    const writeText = vi.fn(async () => {});
    await expect(copyCommand("kavach why x", { writeText })).resolves.toBe(COPIED);
    expect(writeText).toHaveBeenCalledWith("kavach why x");
  });

  it("says to select the text when the clipboard refuses or is missing", async () => {
    const writeText = vi.fn(async () => {
      throw new Error("denied");
    });
    await expect(copyCommand("x", { writeText })).resolves.toBe(COPY_FAILED);
    await expect(copyCommand("x", undefined)).resolves.toBe(COPY_FAILED);
    expect(COPY_FAILED).toBe("Copy failed: select the text");
  });
});

describe("outcome wording", () => {
  it("words every outcome in the spec", () => {
    const all: Outcome[] = ["delivered", "failed", "refused", "not_executed", "unknown"];
    expect(Object.keys(OUTCOME_WORDING).sort()).toEqual([...all].sort());
    expect(outcomeText("delivered")).toBe("Delivered: The provider accepted the call.");
    expect(outcomeText("refused")).toContain("not delivered");
    expect(outcomeText("failed")).toContain("nothing was sent");
    expect(outcomeText("not_executed")).toContain("allowed but nothing was sent");
    expect(outcomeText("unknown")).toContain("never retries");
  });

  it("says plainly when no outcome is recorded", () => {
    expect(outcomeText(null)).toBe("No outcome is recorded for this record.");
  });

  it("never calls a delivery proven", () => {
    for (const { meaning } of Object.values(OUTCOME_WORDING)) {
      expect(meaning).not.toMatch(/proof|proven|guarantee/i);
    }
  });
});

describe("parseClosedRecords", () => {
  const loan = { record_ref: "lms:loan/L-1", state: "paid", closed_at: "2026-10-01T06:00:00Z" };
  const list = (body: unknown) => JSON.stringify(body);

  it("accepts the documented format and returns the body to send", () => {
    const parsed = parseClosedRecords(list({ system: "lms", records: [loan] }));
    expect(parsed).toEqual({ ok: true, body: { system: "lms", records: [loan] } });
  });

  it("refuses empty text, invalid JSON and a non-object", () => {
    expect(parseClosedRecords("  ")).toEqual({ ok: false, problems: ["Paste or load the list of closed loans."] });
    expect(parseClosedRecords("{nope")).toEqual({ ok: false, problems: ["The list is not valid JSON."] });
    expect(parseClosedRecords("[]").ok).toBe(false);
  });

  it("refuses members the schema does not allow, at either level", () => {
    const parsed = parseClosedRecords(
      list({ system: "lms", records: [{ ...loan, borrower: "x" }], note: "y" }),
    );
    expect(parsed).toEqual({
      ok: false,
      problems: [
        "Unexpected member: note. Only system and records are allowed.",
        "Record 1: unexpected member borrower.",
      ],
    });
  });

  it("checks system, the record count, state and closed_at", () => {
    const tooMany = Array.from({ length: CLOSED_RECORDS_LIMITS.recordsMax + 1 }, () => loan);
    expect(parseClosedRecords(list({ system: "lms", records: tooMany }))).toEqual({
      ok: false,
      problems: ["records must be a list of 1-1000 loans."],
    });
    expect(parseClosedRecords(list({ system: "", records: [] }))).toEqual({
      ok: false,
      problems: [
        "system must be 1-64 characters, with no control characters.",
        "records must be a list of 1-1000 loans.",
      ],
    });
    const parsed = parseClosedRecords(
      list({
        system: "lms",
        records: [
          { ...loan, state: "closed" },
          { ...loan, closed_at: "2026-10-01" },
          { ...loan, record_ref: "a\u0007b" },
        ],
      }),
    );
    expect(parsed).toEqual({
      ok: false,
      problems: [
        "Record 1: state must be paid or disputed.",
        "Record 2: closed_at must be an RFC 3339 time, like 2026-10-01T06:00:00Z.",
        "Record 3: record_ref must be 1-256 characters, with no control characters.",
      ],
    });
  });

  it("counts lengths in bytes, as the API does", () => {
    const system = "क".repeat(22); // 66 bytes in UTF-8, 22 characters
    expect(parseClosedRecords(list({ system, records: [loan] })).ok).toBe(false);
  });

  it("shows five problems at most and never echoes a reference", () => {
    const bad = Array.from({ length: 8 }, (_, i) => ({ ...loan, record_ref: `secret-${i}`, state: "x" }));
    const parsed = parseClosedRecords(list({ system: "lms", records: bad }));
    expect(parsed.ok).toBe(false);
    if (parsed.ok) return;
    expect(parsed.problems).toHaveLength(6);
    expect(parsed.problems.at(-1)).toBe("…and 3 more.");
    expect(parsed.problems.join(" ")).not.toContain("secret");
  });
});

describe("reconciliation results", () => {
  it("words each finding kind, and says only one of them is a defect", () => {
    expect(FINDING_WORDING.should_have_been_revoked.label).toBe("Should have been revoked");
    expect(FINDING_WORDING.should_have_been_revoked.meaning).toContain("Resend the signed event");
    expect(FINDING_WORDING.issued_after_closure.label).toBe("To confirm");
    expect(FINDING_WORDING.issued_after_closure.meaning).toContain("not a defect");
  });

  it("puts mismatches first and keeps the API's order otherwise", () => {
    expect(sortFindings(reconciliation.findings).map((f) => f.mandate_id)).toEqual([
      "mandate-11",
      "mandate-21",
    ]);
  });

  it("summarises counts and always says nothing was revoked", () => {
    expect(reconciliationSummary(reconciliation)).toBe(
      "Checked 3 loans: 1 mandate should have been revoked, 1 to confirm. Nothing was revoked.",
    );
    expect(reconciliationSummary(cleanReconciliation)).toBe(
      "Checked 2 loans: none holds a live mandate. Nothing was revoked.",
    );
  });
});

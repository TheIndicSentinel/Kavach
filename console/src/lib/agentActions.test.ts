// The agent actions as pure functions: which ones each state offers, the
// note and reason-code checks, the request bodies, and the flight guard.
import { describe, expect, it } from "vitest";
import {
  actionFormErrors,
  changeRequestHref,
  clampNote,
  createFlightGuard,
  hasErrors,
  NOTE_MAX_CHARS,
  noteCounter,
  noteLength,
  noteProblem,
  REASON_CODES,
  reasonCodeProblem,
  recordText,
  reinstateProposalBody,
  reinstateTargetsFor,
  stopActionsFor,
  stopButtonLabel,
  stopEffect,
  stopRequestBody,
  stopResultState,
  stopResultSummary,
} from "./agentActions";
import { quarantineApplied, revokeHalfway } from "../test/fixtures";

describe("legal transitions", () => {
  it("offers only the stops that tighten the state, and a repeat revoke once revoked", () => {
    expect(stopActionsFor("active")).toEqual(["restrict", "quarantine", "revoke"]);
    expect(stopActionsFor("restricted")).toEqual(["quarantine", "revoke"]);
    expect(stopActionsFor("quarantined")).toEqual(["revoke"]);
    expect(stopActionsFor("revoked")).toEqual(["revoke"]);
    expect(stopButtonLabel("revoke", "revoked")).toBe("Repeat revoke");
  });

  it("offers reinstatement only to a weaker state, never past active, never from revoked", () => {
    expect(reinstateTargetsFor("active")).toEqual([]);
    expect(reinstateTargetsFor("restricted")).toEqual(["active"]);
    expect(reinstateTargetsFor("quarantined")).toEqual(["active", "restricted"]);
    expect(reinstateTargetsFor("revoked")).toEqual([]);
  });

  it("says revoke is permanent and quarantine suspends rather than revokes", () => {
    expect(stopEffect("revoke", "active")).toMatch(/^Permanent\./);
    expect(stopEffect("revoke", "active")).toContain("cannot be reinstated");
    expect(stopEffect("quarantine", "active")).toContain("suspended, not revoked");
    expect(stopEffect("restrict", "active")).toContain("No external effects");
    expect(stopEffect("revoke", "revoked")).toContain("half-way");
  });
});

describe("note", () => {
  it("counts characters as the API does, not UTF-16 units", () => {
    expect(noteLength("नमस्ते")).toBe(6);
    expect(noteLength("🙂🙂")).toBe(2);
  });

  it("is cut to the limit as it is typed, and the counter says so", () => {
    const long = "a".repeat(NOTE_MAX_CHARS + 10);
    expect(clampNote(long)).toHaveLength(NOTE_MAX_CHARS);
    expect(noteLength(clampNote("🙂".repeat(300)))).toBe(NOTE_MAX_CHARS);
    expect(clampNote("short")).toBe("short");
    expect(noteCounter("abc")).toMatch(/^3 of 256 characters/);
    expect(noteCounter("")).toContain("never in the evidence chain");
  });

  it("accepts up to 256 characters and refuses more, or control characters", () => {
    expect(noteProblem("")).toBeNull();
    expect(noteProblem("x".repeat(256))).toBeNull();
    expect(noteProblem("x".repeat(257))).toMatch(/at most 256/);
    expect(noteProblem("line\nbreak")).toMatch(/control characters/);
    expect(noteProblem("tab\there")).toMatch(/control characters/);
  });
});

describe("reason code", () => {
  it("is the spec's closed set", () => {
    expect(REASON_CODES).toEqual([
      "rogue_behaviour",
      "compromise_suspected",
      "policy_violation",
      "customer_complaint",
      "operator_request",
      "reviewed",
      "other",
    ]);
  });

  it("is required and must be one of the set", () => {
    expect(reasonCodeProblem("")).toBe("Choose a reason code.");
    expect(reasonCodeProblem("because")).toMatch(/listed reason codes/);
    expect(reasonCodeProblem("policy_violation")).toBeNull();
    const errors = actionFormErrors({ reasonCode: "", note: "" });
    expect(hasErrors(errors)).toBe(true);
    expect(hasErrors(actionFormErrors({ reasonCode: "other", note: "" }))).toBe(false);
  });
});

describe("request bodies", () => {
  it("sends the reason code and the trimmed note, and leaves a blank note out", () => {
    expect(stopRequestBody({ reasonCode: "rogue_behaviour", note: "  odd calls  " })).toEqual({
      reason_code: "rogue_behaviour",
      note: "odd calls",
    });
    expect(stopRequestBody({ reasonCode: "other", note: "   " })).toEqual({ reason_code: "other" });
  });

  it("refuses to build a body with an unchecked reason code", () => {
    expect(() => stopRequestBody({ reasonCode: "nope", note: "" })).toThrow();
  });

  it("proposes reinstate_agent with the agent, the target state, the reason code and note", () => {
    expect(
      reinstateProposalBody("agent:payments-bot", "restricted", {
        reasonCode: "reviewed",
        note: " checked with the lender ",
      }),
    ).toEqual({
      kind: "reinstate_agent",
      params: {
        agent_id: "agent:payments-bot",
        to: "restricted",
        reason_code: "reviewed",
        note: "checked with the lender",
      },
    });
    expect(reinstateProposalBody("a", "active", { reasonCode: "reviewed", note: "" })).toEqual({
      kind: "reinstate_agent",
      params: { agent_id: "a", to: "active", reason_code: "reviewed" },
    });
  });

  it("links to the change request's card", () => {
    expect(changeRequestHref("cr-0099")).toBe("/changes#change-cr-0099");
  });
});

describe("results", () => {
  it("says the new state, and when nothing changed", () => {
    expect(stopResultSummary("quarantine", quarantineApplied)).toBe(
      "Agent agent:collections-bot is now quarantined (change 1).",
    );
    expect(stopResultSummary("quarantine", { ...quarantineApplied, applied: false })).toContain(
      "already quarantined; nothing changed",
    );
    expect(stopResultSummary("revoke", { ...revokeHalfway, applied: false })).toContain(
      "repeated",
    );
  });

  it("says what each record value means", () => {
    expect(recordText("pending")).toContain("the reconciler writes");
    expect(recordText("written")).toContain("in the chain");
    expect(recordText("unchanged")).toContain("no record");
  });

  it("turns a stop result into the agent's state, without the result-only members", () => {
    const state = stopResultState(revokeHalfway);
    expect(state.state).toBe("revoked");
    expect(state).not.toHaveProperty("applied");
    expect(state).not.toHaveProperty("mandates_not_revoked");
  });
});

describe("createFlightGuard", () => {
  it("ignores a second run while the first is in flight, and allows one after", async () => {
    const guard = createFlightGuard();
    let release = () => {};
    let calls = 0;
    const task = () => {
      calls += 1;
      return new Promise<void>((resolve) => {
        release = resolve;
      });
    };
    const first = guard.run(task);
    expect(guard.busy).toBe(true);
    expect(guard.run(task)).toBeNull();
    expect(calls).toBe(1);
    release();
    await first;
    expect(guard.busy).toBe(false);
    const again = guard.run(task);
    expect(again).not.toBeNull();
    expect(calls).toBe(2);
    release();
    await again;
  });

  it("is free again after a refusal", async () => {
    const guard = createFlightGuard();
    await expect(guard.run(() => Promise.reject(new Error("403")))).rejects.toThrow("403");
    expect(guard.busy).toBe(false);
  });
});

import { describe, expect, it } from "vitest";
import { reinstateProposed } from "../test/fixtures";
import { changeRequestButtons, currentViewer } from "./changeRequests";

describe("currentViewer", () => {
  it("knows the principal only when it is sent as the header, with no token", () => {
    expect(currentViewer("", "operator-1")).toEqual({ kind: "principal", id: "operator-1" });
  });

  it("does not claim to know who a token belongs to", () => {
    expect(currentViewer("eyJ.token.sig", "operator-1")).toEqual({ kind: "unknown" });
    expect(currentViewer("eyJ.token.sig", "")).toEqual({ kind: "unknown" });
  });

  it("knows nobody when nothing is configured", () => {
    expect(currentViewer("", "")).toEqual({ kind: "unknown" });
  });
});

describe("changeRequestButtons", () => {
  const pending = reinstateProposed; // proposed by operator-1

  it("offers the proposer cancel only, and says why approve is missing", () => {
    const buttons = changeRequestButtons(pending, { kind: "principal", id: "operator-1" });
    expect(buttons.actions).toEqual(["cancel"]);
    expect(buttons.note).toMatch(/different principal approves or rejects/);
  });

  it("offers another principal approve and reject, not cancel", () => {
    const buttons = changeRequestButtons(pending, { kind: "principal", id: "admin-2" });
    expect(buttons.actions).toEqual(["approve", "reject"]);
    expect(buttons.note).toBeNull();
  });

  it("offers everything when it cannot tell who it is: the API decides", () => {
    expect(changeRequestButtons(pending, { kind: "unknown" }).actions).toEqual([
      "approve",
      "reject",
      "cancel",
    ]);
  });

  it("offers nothing once the request is decided", () => {
    for (const status of ["applied", "rejected", "cancelled", "expired", "failed"] as const) {
      expect(changeRequestButtons({ ...pending, status }, { kind: "unknown" }).actions).toEqual([]);
    }
  });
});

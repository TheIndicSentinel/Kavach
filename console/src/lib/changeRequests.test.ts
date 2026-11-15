import { describe, expect, it } from "vitest";
import { reinstateProposed } from "../test/fixtures";
import { changeRequestButtons, currentViewer } from "./changeRequests";
import { UNKNOWN_VIEWER } from "./permissions";

describe("currentViewer", () => {
  it("knows the principal only when it is sent as the header, with no token", () => {
    expect(currentViewer("", "operator-1")).toEqual({ principal: "operator-1", groups: null });
  });

  it("does not claim to know who a token belongs to", () => {
    expect(currentViewer("eyJ.token.sig", "operator-1")).toEqual(UNKNOWN_VIEWER);
    expect(currentViewer("eyJ.token.sig", "")).toEqual(UNKNOWN_VIEWER);
  });

  it("knows nobody when nothing is configured", () => {
    expect(currentViewer("", "")).toEqual(UNKNOWN_VIEWER);
  });

  it("never invents groups: they are unknown unless passed in", () => {
    expect(currentViewer("", "admin-1").groups).toBeNull();
    expect(currentViewer("eyJ.token.sig", "", ["admins"]).groups).toEqual(["admins"]);
  });

  it("is unknown where there is no sessionStorage (static rendering)", () => {
    expect(currentViewer()).toEqual(UNKNOWN_VIEWER);
  });
});

describe("changeRequestButtons: the proposer rule", () => {
  const pending = reinstateProposed; // proposed by operator-1

  it("offers the proposer cancel only, and says why approve is missing", () => {
    const buttons = changeRequestButtons(pending, { principal: "operator-1", groups: null });
    expect(buttons.actions).toEqual(["cancel"]);
    expect(buttons.note).toMatch(/different principal approves or rejects/);
    expect(buttons.hint).toBeNull();
  });

  it("offers another principal approve and reject, not cancel", () => {
    const buttons = changeRequestButtons(pending, { principal: "admin-2", groups: null });
    expect(buttons.actions).toEqual(["approve", "reject"]);
    expect(buttons.note).toBeNull();
  });

  it("offers everything when it cannot tell who it is: the API decides", () => {
    expect(changeRequestButtons(pending, UNKNOWN_VIEWER)).toEqual({
      actions: ["approve", "reject", "cancel"],
      note: null,
      hint: null,
    });
  });

  it("offers nothing once the request is decided", () => {
    for (const status of ["applied", "rejected", "cancelled", "expired", "failed"] as const) {
      expect(changeRequestButtons({ ...pending, status }, UNKNOWN_VIEWER).actions).toEqual([]);
    }
  });
});

describe("changeRequestButtons: the group rule", () => {
  const pending = reinstateProposed;

  it("known allowed: change-approvers keep approve and reject, admins keep cancel", () => {
    const approver = changeRequestButtons(pending, { principal: null, groups: ["change-approvers"] });
    expect(approver.actions).toEqual(["approve", "reject"]);
    expect(approver.hint).toMatch(/may cancel this change/);

    const both = changeRequestButtons(pending, {
      principal: null,
      groups: ["admins", "change-approvers"],
    });
    expect(both).toEqual({ actions: ["approve", "reject", "cancel"], note: null, hint: null });
  });

  it("known denied: viewers get no button and one line that the server decides", () => {
    const buttons = changeRequestButtons(pending, { principal: null, groups: ["viewers"] });
    expect(buttons.actions).toEqual([]);
    expect(buttons.hint).toBe(
      "Your groups (viewers) don't include one that may approve, reject or cancel this change. The server decides; ask an admin if you need this.",
    );
  });

  it("unknown groups: every button the proposer rule leaves", () => {
    expect(changeRequestButtons(pending, { principal: "admin-2", groups: null }).actions).toEqual([
      "approve",
      "reject",
    ]);
  });

  it("keeps the proposer rule with known groups", () => {
    const proposer = changeRequestButtons(pending, {
      principal: "operator-1",
      groups: ["admins", "change-approvers"],
    });
    expect(proposer.actions).toEqual(["cancel"]);
    expect(proposer.note).toMatch(/different principal/);
    expect(proposer.hint).toBeNull();

    const proposerNotAdmin = changeRequestButtons(pending, {
      principal: "operator-1",
      groups: ["change-approvers"],
    });
    expect(proposerNotAdmin.actions).toEqual([]);
    expect(proposerNotAdmin.hint).toMatch(/may cancel this change/);
  });

  it("checks the kind's own actions", () => {
    const pack = { ...pending, kind: "activate_pack" as const };
    expect(changeRequestButtons(pack, { principal: null, groups: ["admins"] }).actions).toEqual([
      "cancel",
    ]);
  });
});

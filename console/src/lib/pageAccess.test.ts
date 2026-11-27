import { describe, expect, it } from "vitest";
import { PAGE_ACTIONS, showsPage } from "./pageAccess";
import { ROLES, UNKNOWN_VIEWER } from "./permissions";

const viewer = (groups: string[] | null, roles: (typeof ROLES)[number][] | null) => ({
  principal: "p-1",
  groups,
  roles,
});

const shown = (groups: string[] | null, roles: (typeof ROLES)[number][] | null) =>
  ["/overview", "/settings", ...Object.keys(PAGE_ACTIONS)].filter((path) => showsPage(viewer(groups, roles), path));

describe("which pages the navigation shows", () => {
  it("shows every page when nothing is known", () => {
    for (const path of Object.keys(PAGE_ACTIONS)) expect(showsPage(UNKNOWN_VIEWER, path)).toBe(true);
  });

  it("shows a superadmin every page", () => {
    expect(shown([], ["superadmin"])).toHaveLength(Object.keys(PAGE_ACTIONS).length + 2);
  });

  it.each<[(typeof ROLES)[number], string[]]>([
    ["user_admin", ["/overview", "/settings", "/changes", "/users"]],
    ["viewer", ["/overview", "/settings", "/policies", "/models"]],
    [
      "auditor",
      [
        "/overview",
        "/settings",
        "/agents",
        "/agent-evidence",
        "/decision-events",
        "/policies",
        "/models",
        "/batch",
        "/changes",
        "/audit",
        "/incidents",
        "/retention",
        "/users",
      ],
    ],
    [
      "operator",
      ["/overview", "/settings", "/evaluate", "/agents", "/reconciliation", "/policies", "/models", "/batch", "/incidents"],
    ],
    ["approver", ["/overview", "/settings", "/policies", "/models", "/changes", "/retention"]],
    [
      "policy_admin",
      ["/overview", "/settings", "/agents", "/policies", "/models", "/batch", "/changes", "/incidents", "/retention"],
    ],
  ])("%s alone sees %j", (role, pages) => {
    expect(shown([], [role]).sort()).toEqual([...pages].sort());
  });

  it("adds the alias groups' pages to the roles' pages", () => {
    expect(shown(["viewers"], ["user_admin"]).sort()).toEqual(
      ["/overview", "/settings", "/policies", "/models", "/changes", "/users"].sort(),
    );
  });

  it("keeps Users & roles while the roles are unknown, and leaves it to the server", () => {
    expect(showsPage(viewer(["admins"], null), "/users")).toBe(true);
    expect(showsPage(viewer(["admins"], []), "/users")).toBe(false);
  });
});

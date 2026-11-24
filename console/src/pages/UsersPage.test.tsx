// Users & roles, rendered to static markup with given reads: which sections
// and controls each role is shown, and the wait for GET /v1/me.
import { describe, expect, it } from "vitest";
import type { PrincipalPage, RoleBinding } from "../lib/api";
import type { Viewer } from "../lib/permissions";
import { render, text } from "../test/markup";
import UsersPage from "./UsersPage";

const ISSUER = "https://idp.example.test";
const principals: PrincipalPage = {
  items: [
    {
      issuer: ISSUER,
      subject: "oidc-auditor-5",
      display_name: "Ravi",
      first_seen_at: "2026-11-02T09:00:00Z",
      last_seen_at: "2026-11-14T16:00:00Z",
    },
  ],
  next_cursor: "c2",
};
const bindings: RoleBinding[] = [
  {
    id: "rb-1",
    role: "superadmin",
    subject: { kind: "principal", issuer: ISSUER, value: "oidc-admin-2" },
    granted_by_change_request: null,
    granted_at: "2026-11-01T08:00:00Z",
    ended_by_change_request: null,
    ended_at: null,
  },
  {
    id: "rb-2",
    role: "auditor",
    subject: { kind: "group", issuer: ISSUER, value: "risk-team" },
    granted_by_change_request: "cr-roles-1",
    granted_at: "2026-11-02T10:00:00Z",
    ended_by_change_request: "cr-roles-4",
    ended_at: "2026-11-10T10:00:00Z",
  },
];

const as = (roles: Viewer["roles"], groups: string[] = [], rolesPending = false): Viewer => ({
  principal: "oidc-someone",
  groups,
  roles,
  rolesPending,
});

const shown = (viewer: Viewer) =>
  text(
    render(
      <UsersPage
        viewer={viewer}
        principals={{ phase: "ok", data: principals }}
        bindings={{ phase: "ok", data: bindings }}
      />,
    ),
  );

describe("UsersPage", () => {
  it("superadmin: the directory with grant buttons, the form, revoke on active bindings only, the review", () => {
    const page = shown(as(["superadmin"]));
    expect(page).toContain("Ravi");
    expect(page).toContain("Grant a role");
    expect(page).toContain("Propose grant");
    expect(page).toContain("Next page");
    expect(page.match(/Propose revoke/g)).toHaveLength(2); // one binding, rendered for mobile and desktop
    expect(page).toContain("Group risk-team");
    expect(page).toContain("(bootstrap)");
    expect(page).toContain("Show review");
    expect(page).toContain("Download CSV");
    expect(page).not.toContain("don't include one");
  });

  it("user_admin: proposes grants and revokes, and is told a second person approves", () => {
    const page = shown(as(["user_admin"]));
    expect(page).toContain("Propose grant");
    expect(page).toContain("Propose revoke");
    expect(page).toContain("wait on the Change requests page for a second person");
    expect(page).toContain("Show review");
  });

  it("auditor: reads the directory, the bindings and the review; proposes nothing", () => {
    const page = shown(as(["auditor"]));
    expect(page).toContain("Ravi");
    expect(page).toContain("Show review");
    expect(page).not.toContain("Propose grant");
    expect(page).not.toContain("Propose revoke");
    expect(page).toContain("don't include one that may propose role grants.");
    expect(page).toContain("don't include one that may propose role revokes.");
  });

  it("an alias group with no role: hints only, nothing read", () => {
    const page = shown(as([], ["admins"]));
    expect(page).not.toContain("Ravi");
    expect(page).not.toContain("Show review");
    expect(page).toContain(
      "Your roles (none) and groups (admins) don't include one that may read users and role bindings.",
    );
    expect(page).toContain("may export the access review.");
  });

  it("while GET /v1/me has not answered, with the groups known, it waits instead of reading", () => {
    const page = shown(as(null, ["viewers"], true));
    expect(page).toContain("Checking your roles…");
    expect(page).not.toContain("Ravi");
    expect(page).not.toContain("don't include one");
  });

  it("with no groups known (development fallback), everything shows: the server decides", () => {
    const page = shown({ principal: null, groups: null, roles: null, rolesPending: true });
    expect(page).toContain("Ravi");
    expect(page).toContain("Propose grant");
    expect(page).toContain("Show review");
  });
});

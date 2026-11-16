import { describe, expect, it } from "vitest";
import type { PrincipalPage, RoleBinding } from "../lib/api";
import { byRole, render, text } from "../test/markup";
import { badGateway, failed, forbidden, loading, ok } from "../test/states";
import UsersPage from "./UsersPage";

const principal: PrincipalPage["items"][number] = {
  issuer: "https://idp.example.test",
  subject: "oidc-admin-2",
  display_name: "Asha Rao",
  first_seen_at: "2026-11-01T09:00:00Z",
  last_seen_at: "2026-11-15T09:30:00Z",
};

const binding: RoleBinding = {
  id: "rb-1",
  role: "auditor",
  subject: { kind: "principal", issuer: "https://idp.example.test", value: "oidc-auditor-5" },
  granted_by_change_request: "cr-role-1",
  granted_at: "2026-11-02T10:00:00Z",
  ended_by_change_request: null,
  ended_at: null,
};

describe("UsersPage directory", () => {
  it("announces loading while principals are being read", () => {
    const html = render(<UsersPage resource={loading} bindingsResource={ok([])} />);
    expect(byRole(html, "status")).toEqual(["Loading people…", "0 active bindings."]);
    expect(byRole(html, "alert")).toEqual(["", ""]);
    expect(html).toContain('class="animate-pulse');
  });

  it("shows the empty directory state", () => {
    const html = render(<UsersPage resource={ok({ items: [], next_cursor: null })} bindingsResource={ok([])} />);
    expect(text(html)).toContain("No people match this directory view.");
    expect(byRole(html, "status")).toEqual(["0 people on this page.", "0 active bindings."]);
  });

  it("shows the principal identity and last-seen details", () => {
    const html = render(
      <UsersPage resource={ok({ items: [principal], next_cursor: null })} bindingsResource={ok([])} />,
    );
    expect(text(html)).toContain("Asha Rao");
    expect(text(html)).toContain("oidc-admin-2");
    expect(text(html)).toContain("https://idp.example.test");
    expect(byRole(html, "status")).toEqual(["1 person on this page.", "0 active bindings."]);
  });

  it("shows the API refusal and retry for a forbidden read", () => {
    const html = render(<UsersPage resource={failed(forbidden)} bindingsResource={ok([])} />);
    expect(byRole(html, "alert")[0]).toContain("Not permitted");
    expect(text(html)).toContain("Try again");
  });

  it("shows a proxy failure without hiding its status", () => {
    const html = render(
      <UsersPage resource={failed(badGateway("/v1/principals"))} bindingsResource={ok([])} />,
    );
    expect(byRole(html, "alert")[0]).toContain("no request_id was returned");
    expect(byRole(html, "alert")[0]).toContain("HTTP 502");
  });

  it("lists active role bindings by role and subject", () => {
    const html = render(
      <UsersPage resource={ok({ items: [], next_cursor: null })} bindingsResource={ok([binding])} />,
    );
    expect(text(html)).toContain("auditor");
    expect(text(html)).toContain("oidc-auditor-5");
    expect(text(html)).toContain("https://idp.example.test");
    expect(byRole(html, "status")).toEqual(["0 people on this page.", "1 active binding."]);
  });

  it("shows the empty active-binding state", () => {
    const html = render(
      <UsersPage resource={ok({ items: [], next_cursor: null })} bindingsResource={ok([])} />,
    );
    expect(text(html)).toContain("No active role bindings.");
  });

  it("announces a failed role-binding read separately", () => {
    const html = render(
      <UsersPage
        resource={ok({ items: [], next_cursor: null })}
        bindingsResource={failed(forbidden)}
      />,
    );
    expect(byRole(html, "alert")[1]).toContain("Not permitted");
    expect(byRole(html, "status")).toEqual(["0 people on this page.", ""]);
  });
});

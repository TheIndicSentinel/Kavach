import { describe, expect, it } from "vitest";
import type { PrincipalPage } from "../lib/api";
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

describe("UsersPage directory", () => {
  it("announces loading while principals are being read", () => {
    const html = render(<UsersPage resource={loading} />);
    expect(byRole(html, "status")).toEqual(["Loading people…"]);
    expect(byRole(html, "alert")).toEqual([""]);
    expect(html).toContain('class="animate-pulse');
  });

  it("shows the empty directory state", () => {
    const html = render(<UsersPage resource={ok({ items: [], next_cursor: null })} />);
    expect(text(html)).toContain("No people match this directory view.");
    expect(byRole(html, "status")).toEqual(["0 people on this page."]);
  });

  it("shows the principal identity and last-seen details", () => {
    const html = render(<UsersPage resource={ok({ items: [principal], next_cursor: null })} />);
    expect(text(html)).toContain("Asha Rao");
    expect(text(html)).toContain("oidc-admin-2");
    expect(text(html)).toContain("https://idp.example.test");
    expect(byRole(html, "status")).toEqual(["1 person on this page."]);
  });

  it("shows the API refusal and retry for a forbidden read", () => {
    const html = render(<UsersPage resource={failed(forbidden)} />);
    expect(byRole(html, "alert")[0]).toContain("Not permitted");
    expect(text(html)).toContain("Try again");
  });

  it("shows a proxy failure without hiding its status", () => {
    const html = render(<UsersPage resource={failed(badGateway("/v1/principals"))} />);
    expect(byRole(html, "alert")[0]).toContain("no request_id was returned");
    expect(byRole(html, "alert")[0]).toContain("HTTP 502");
  });
});

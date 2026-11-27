// The superadmin banner shows only while GET /v1/me names superadmin.
import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { text } from "../../test/markup";
import { SuperadminBanner } from "./SuperadminBanner";

describe("SuperadminBanner", () => {
  it("shows for superadmin, labelled, saying a second person still approves", () => {
    const html = renderToStaticMarkup(<SuperadminBanner roles={["auditor", "superadmin"]} />);
    expect(html).toContain('aria-label="Acting as superadmin"');
    expect(text(html)).toContain("a second person still approves every change request");
  });

  it("shows for no other role, and not while the roles are unknown", () => {
    for (const roles of [null, [], ["user_admin", "policy_admin", "approver", "operator", "auditor", "viewer"]] as const) {
      expect(renderToStaticMarkup(<SuperadminBanner roles={roles} />)).toBe("");
    }
  });
});

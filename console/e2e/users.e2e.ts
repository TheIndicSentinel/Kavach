// Users & roles (ADR-019): the page and the navigation follow GET /v1/me's
// roles, a grant is only proposed (a second person approves it), and the
// access review, whose every export the server audits, loads only on a click.
import { readFileSync } from "node:fs";
import type { Page } from "@playwright/test";
import type { ApiStub } from "./api";
import { expectNoViolations } from "./axe";
import * as body from "./fixtures";
import { expect, test } from "./page";

const sent = (api: ApiStub, key: string) => api.calls.filter((call) => call.key === key);
const nav = (page: Page) => page.getByRole("navigation", { name: "Main navigation" });
const banner = (page: Page) => page.getByRole("complementary", { name: "Acting as superadmin" });

/** Signed in through login mode as `session`, with `roles` from GET /v1/me. */
function signedIn(api: ApiStub, session: typeof body.authSession, me: typeof body.meNoRoles) {
  api.set("GET /auth/config", { json: body.authConfigLogin });
  api.set("GET /auth/session", { json: session });
  api.set("GET /v1/me", { json: me });
}

test.describe("a superadmin by role, with no group", () => {
  test.beforeEach(({ api }) => signedIn(api, body.superadminSession, body.meSuperadmin));

  test("the banner shows, and every section of the navigation with Users & roles", async ({ page }) => {
    await page.goto("/overview");
    await expect(banner(page)).toContainText("Acting as superadmin.");
    await expect(banner(page)).toContainText("a second person still approves every change request");
    for (const name of ["Agents", "Change requests", "Audit", "Users & roles"]) {
      await expect(nav(page).getByRole("link", { name, exact: true })).toBeVisible();
    }
    await expectNoViolations(page);
  });

  test("grant a role from the directory: a proposal that names the second approver", async ({ page, api }) => {
    api.set("POST /v1/change-requests", { json: body.grantProposed });
    await page.goto("/users");
    await page.getByRole("button", { name: "Grant a role to oidc-auditor-5" }).click();
    const role = page.getByLabel("Role", { exact: true });
    await expect(role).toBeFocused();
    await expect(page.getByLabel("Issuer", { exact: true })).toHaveValue("https://idp.example.test");
    await expect(page.getByLabel("Subject", { exact: true })).toHaveValue("oidc-auditor-5");
    await role.selectOption("auditor");
    await expect(page.getByText("Reads everything, changes nothing.")).toBeVisible();
    await page.getByRole("button", { name: "Propose grant" }).click();

    await expect(
      page.getByRole("status").filter({
        hasText:
          "Change request cr-roles-2 proposed. A second person with superadmin or user_admin must approve it on the Change requests page; nothing changes until then.",
      }),
    ).toBeVisible();
    expect(sent(api, "POST /v1/change-requests").map((call) => call.body)).toEqual([
      {
        kind: "grant_role",
        params: {
          role: "auditor",
          subject: { kind: "principal", issuer: "https://idp.example.test", value: "oidc-auditor-5" },
        },
      },
    ]);
    await expectNoViolations(page);
  });

  test("an empty grant names each missing field and sends nothing", async ({ page, api }) => {
    await page.goto("/users");
    await page.getByRole("button", { name: "Propose grant" }).click();
    await expect(page.getByText("Choose a role.")).toBeVisible();
    await expect(page.getByText("Enter the issuer.")).toBeVisible();
    await expect(page.getByText("Enter the subject.")).toBeVisible();
    await expect(page.getByLabel("Role", { exact: true })).toHaveAttribute("aria-invalid", "true");
    await expect(page.getByLabel("Role", { exact: true }), "focus moves to the first field in error").toBeFocused();
    expect(sent(api, "POST /v1/change-requests")).toEqual([]);
  });

  test("revoke an active binding: a revoke_role proposal by binding id", async ({ page, api }) => {
    api.set("POST /v1/change-requests", {
      json: { ...body.grantProposed, id: "cr-roles-3", kind: "revoke_role", params: { binding_id: "rb-2" } },
    });
    await page.goto("/users");
    await page.getByRole("button", { name: "Propose revoking auditor from oidc-auditor-5" }).click();
    await expect(page.getByRole("status").filter({ hasText: "Change request cr-roles-3 proposed." })).toBeVisible();
    expect(sent(api, "POST /v1/change-requests").map((call) => call.body)).toEqual([
      { kind: "revoke_role", params: { binding_id: "rb-2" } },
    ]);
  });

  test("ended bindings are asked for only when the box is ticked", async ({ page, api }) => {
    const queries: string[] = [];
    api.set("GET /v1/role-bindings", (request) => {
      queries.push(new URL(request.url()).search);
      return { json: body.roleBindings };
    });
    await page.goto("/users");
    await expect(page.getByText("2 bindings.")).toBeVisible();
    expect(queries).toEqual([""]);
    await page.getByLabel("Include ended bindings").check();
    await expect.poll(() => queries).toEqual(["", "?include=ended"]);
  });

  test("the access review loads only on a click, and says the export is audited", async ({ page, api }) => {
    await page.goto("/users");
    await expect(page.getByText("oidc-auditor-5").filter({ visible: true }).first()).toBeVisible();
    expect(sent(api, "GET /v1/access-review"), "nothing exported before a click").toEqual([]);

    await page.getByRole("button", { name: "Show review" }).click();
    await expect(page.getByRole("status").filter({ hasText: "The export is recorded in the admin audit." })).toBeVisible();
    await expect(page.getByRole("cell", { name: "oidc-admin-9" })).toBeVisible();
    expect(sent(api, "GET /v1/access-review")).toHaveLength(1);
    await expectNoViolations(page);
  });

  test("Download CSV saves access-review.csv from the server's CSV", async ({ page }) => {
    const csv = '"role","subject"\r\n"auditor","oidc-auditor-5"\r\n';
    await page.route("**/v1/access-review?format=csv", (route) =>
      route.fulfill({ status: 200, contentType: "text/csv; charset=utf-8", body: csv }),
    );
    await page.goto("/users");
    const download = page.waitForEvent("download");
    await page.getByRole("button", { name: "Download CSV" }).click();
    const file = await download;
    expect(file.suggestedFilename()).toBe("access-review.csv");
    expect(readFileSync(await file.path(), "utf8")).toBe(csv);
    await expect(page.getByRole("status").filter({ hasText: "Downloaded access-review.csv." })).toBeVisible();
  });
});

test.describe("viewers with no role", () => {
  test.beforeEach(({ api }) => signedIn(api, body.viewerSession, body.meNoRoles));

  test("no banner, no Users & roles link, and the page shows hints without reading", async ({ page, api }) => {
    await page.goto("/overview");
    await expect(nav(page).getByRole("link", { name: "Overview", exact: true })).toBeVisible();
    await expect(nav(page).getByRole("link", { name: "Users & roles", exact: true })).toHaveCount(0);
    await expect(banner(page)).toHaveCount(0);

    // The address still opens the page; the server would refuse the reads.
    await page.goto("/users");
    await expect(
      page.getByText(
        "Your roles (none) and groups (viewers) don't include one that may read users and role bindings.",
      ).first(),
    ).toBeVisible();
    await expect(
      page.getByText("Your roles (none) and groups (viewers) don't include one that may export the access review."),
    ).toBeVisible();
    await expect(page.getByRole("button", { name: "Show review" })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Propose grant" })).toHaveCount(0);
    expect(sent(api, "GET /v1/principals")).toEqual([]);
    expect(sent(api, "GET /v1/role-bindings")).toEqual([]);
    await expectNoViolations(page);
  });
});

test("an auditor by role reads the directory and the review but proposes nothing", async ({ page, api }) => {
  signedIn(api, { ...body.viewerSession, principal: "oidc-auditor-5" }, { principal: "oidc-auditor-5", roles: ["auditor"] });
  await page.goto("/users");
  await expect(page.getByText("Asha Rao").filter({ visible: true }).first()).toBeVisible();
  await expect(page.getByRole("button", { name: "Show review" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Propose grant" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: /^Grant a role to/ })).toHaveCount(0);
  await expect(page.getByRole("button", { name: /^Propose revoking/ })).toHaveCount(0);
  await expect(page.getByText("may propose role grants.")).toBeVisible();
  await expect(banner(page)).toHaveCount(0);
});

import type { Request } from "@playwright/test";
import type { ApiStub } from "./api";
import * as body from "./fixtures";
import { expect, test } from "./page";

function recordQueries(api: ApiStub): string[] {
  const queries: string[] = [];
  api.set("GET /v1/principals", (request: Request) => {
    const url = new URL(request.url());
    const query = url.searchParams.get("q") ?? "";
    const cursor = url.searchParams.get("cursor") ?? "";
    queries.push(`${query}|${cursor}`);
    return { json: cursor ? body.principalPageTwo : body.principalPage };
  });
  return queries;
}

test("the directory searches by name or subject and pages by cursor", async ({ page, api }) => {
  const queries = recordQueries(api);
  await page.goto("/users");
  await expect(page.getByRole("row", { name: /Asha Rao/ })).toBeVisible();
  await expect(page.getByRole("row", { name: /superadmin.*oidc-admin-2/ })).toBeVisible();
  await expect(page.getByRole("status").filter({ hasText: "2 active bindings." })).toBeVisible();
  expect(queries).toEqual(["|"]);

  await page.getByLabel("Name or subject").fill("Asha");
  await page.getByRole("button", { name: "Search" }).click();
  await expect(page.getByRole("row", { name: /Asha Rao/ })).toBeVisible();
  await expect.poll(() => queries).toEqual(["|", "Asha|"]);

  await page.getByRole("button", { name: "Next page" }).click();
  await expect(page.getByRole("row", { name: /Asha Rao \(contractor\)/ })).toBeVisible();
  await expect.poll(() => queries).toEqual(["|", "Asha|", "Asha|principal-page-2"]);
  await expect(page.getByRole("status")).toContainText("1 person on this page.");
});

test("a role grant is proposed for the selected directory principal", async ({ page, api }) => {
  api.set("GET /v1/me", { json: { principal: "admin-1", roles: ["user_admin"] } });
  let proposal: unknown;
  api.set("POST /v1/change-requests", (request) => {
    proposal = request.postDataJSON();
    return { json: { ...body.reinstateProposed, id: "cr-grant-1", kind: "grant_role", params: proposal } };
  });

  await page.goto("/users");
  await page.getByRole("button", { name: "Grant role to Asha Rao" }).click();
  await page.getByLabel("Role", { exact: true }).selectOption("auditor");
  await page.getByRole("button", { name: "Propose grant" }).click();

  await expect(page.getByRole("status")).toContainText("cr-grant-1 is pending");
  await expect(page.getByRole("status")).toContainText("different authorized person approves it");
  expect(proposal).toEqual({
    kind: "grant_role",
    params: {
      role: "auditor",
      subject: { kind: "principal", issuer: "https://idp.example.test", value: "oidc-admin-2" },
    },
  });
});

test("a role revoke is proposed for the selected active binding", async ({ page, api }) => {
  api.set("GET /v1/me", { json: { principal: "admin-1", roles: ["user_admin"] } });
  let proposal: unknown;
  api.set("POST /v1/change-requests", (request) => {
    proposal = request.postDataJSON();
    return { json: { ...body.reinstateProposed, id: "cr-revoke-1", kind: "revoke_role", params: proposal } };
  });

  await page.goto("/users");
  await page.getByRole("button", { name: "Propose revoke for auditor role held by oidc-auditor-5" }).click();
  await page.getByRole("alertdialog").getByRole("button", { name: "Propose revoke" }).click();

  await expect(page.getByRole("status")).toContainText("cr-revoke-1 is pending");
  await expect(page.getByRole("status")).toContainText("binding remains active");
  expect(proposal).toEqual({ kind: "revoke_role", params: { binding_id: "rb-demo-2" } });
});

test("the access review loads only on request and downloads the audited CSV", async ({ page, api }) => {
  api.set("GET /v1/me", { json: { principal: "auditor-1", roles: ["auditor"] } });
  await page.goto("/users");
  expect(api.calls.filter((call) => call.key === "GET /v1/access-review")).toHaveLength(0);

  await page.getByRole("button", { name: "Load access review" }).click();
  await expect(page.getByRole("row", { name: /auditor.*Asha Rao \(contractor\)/ })).toBeVisible();
  await expect(page.getByText(/Policy alias groups: admins, change-approvers/)).toBeVisible();
  await expect(page.getByText("Not assessed (group membership is in the identity provider)")).toBeVisible();
  await expect(page.getByText(/Each review load and CSV export is recorded/)).toBeVisible();

  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download CSV" }).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBe("access-review.csv");
  await expect(page.getByRole("status")).toContainText("recorded in the audit log");
  expect(api.calls.filter((call) => call.key === "GET /v1/access-review")).toHaveLength(2);
});

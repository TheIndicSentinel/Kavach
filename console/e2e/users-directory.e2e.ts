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

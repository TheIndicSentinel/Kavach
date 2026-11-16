// Against a running scripts/demo.sh (playwright.demo.config.ts): each demo
// user signs in the way a person does, by picking their name on the OIDC
// test double's "Sign in as" page, and opens every page. The admin sees no
// error anywhere. The others may see "Not permitted" where Cedar refuses
// their group, but never a server error or an unreachable API.
import type { Page } from "@playwright/test";
import { PAGES, signOut } from "./real";
import { expect, test } from "./stack";

test.describe.configure({ mode: "serial" });

/** scripts/demo.sh's USERS. */
const USERS = ["demo-admin", "demo-approver", "demo-operator", "demo-viewer"] as const;

async function signInAs(page: Page, sub: string): Promise<void> {
  await page.goto("/overview");
  await expect(page).toHaveURL(/\/signin$/);
  await page.getByRole("link", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Sign in as" })).toBeVisible();
  await page.getByRole("link", { name: sub, exact: true }).click();
  await expect(page).toHaveURL(/\/overview$/);
  await expect(page.getByRole("banner")).toContainText(sub);
}

/** Opens `path`, waits for its heading and for every request to settle; returns the error alerts' text. */
async function visit(page: Page, path: string, heading: string): Promise<string[]> {
  await page.goto(path);
  await expect(page.getByRole("heading", { level: 1, name: heading })).toBeVisible();
  await page.waitForLoadState("networkidle");
  return (await page.getByRole("alert").filter({ hasText: /\S/ }).allTextContents()).map((t) => t.trim());
}

for (const sub of USERS) {
  test(`${sub} signs in through the picker and every page loads`, async ({ page }) => {
    await signInAs(page, sub);
    for (const [path, heading] of PAGES) {
      const alerts = await visit(page, path, heading);
      if (sub === "demo-admin") {
        expect(alerts, `${path} shows no error`).toEqual([]);
        continue;
      }
      for (const alert of alerts) {
        expect(alert, `${path}: only a refusal`).toContain("HTTP 403");
        expect(alert).not.toContain("not reachable");
      }
    }
    await signOut(page);
  });
}

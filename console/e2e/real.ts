// Helpers for the real-stack specs (playwright.real.config.ts).
import type { BrowserContext, Page } from "@playwright/test";
import { IDP_ORIGIN, type RealUser, USER_COOKIE } from "./realStack";
import { expect } from "./stack";

/** Every page of a full kavach-api, by path, with its heading. */
export const PAGES: [string, string][] = [
  ["/overview", "Overview"],
  ["/evaluate", "Evaluate"],
  ["/agents", "Agents"],
  ["/agent-evidence", "Agent evidence"],
  ["/reconciliation", "Closed loans"],
  ["/decision-events", "Decision events"],
  ["/policies", "Policies"],
  ["/models", "Models"],
  ["/batch", "Batch jobs"],
  ["/changes", "Change requests"],
  ["/audit", "Admin audit"],
  ["/incidents", "Incidents"],
  ["/retention", "Retention & erasure"],
  ["/settings", "Settings"],
];

/** Signs in as `user` through the OIDC double; lands on /overview. */
export async function signInAs(page: Page, context: BrowserContext, user: RealUser): Promise<void> {
  await context.addCookies([{ name: USER_COOKIE, value: user.sub, url: IDP_ORIGIN }]);
  await page.goto("/overview");
  await expect(page).toHaveURL(/\/signin$/);
  await page.getByRole("link", { name: "Sign in" }).click();
  await expect(page).toHaveURL(/\/overview$/);
  await expect(page.getByRole("banner")).toContainText(user.sub);
}

/** Signs out from the header; lands on /signin. */
export async function signOut(page: Page): Promise<void> {
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page).toHaveURL(/\/signin$/);
}

/**
 * Opens `path` and waits for its heading and for every request to settle;
 * then the page must show no error alert.
 */
export async function open(page: Page, path: string, heading: string | RegExp): Promise<void> {
  await page.goto(path);
  await expect(page.getByRole("heading", { level: 1, name: heading })).toBeVisible();
  await page.waitForLoadState("networkidle");
  // Pages keep an empty alert region for announcements; an error has text.
  await expect(page.getByRole("alert").filter({ hasText: /\S/ }), `${path} shows no error`).toHaveCount(0);
}

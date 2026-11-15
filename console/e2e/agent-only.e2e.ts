// A server started with --agent-only (GET /v1/runtime says `agent_only: true`)
// serves no credit-track route. The console leaves those pages out of its
// navigation, shows "not served" on their paths without calling the API, and
// keeps Overview to what the server serves.
import { expectNoViolations } from "./axe";
import { runtime } from "./fixtures";
import { expect, test } from "./page";

const CREDIT_LINKS = ["Evaluate", "Policies", "Models", "Batch jobs", "Incidents", "Retention", "Decision events"];
const CREDIT_PATHS = ["/evaluate", "/policies", "/policies/finance-core", "/models/credit-risk", "/batch", "/incidents", "/retention", "/decision-events"];
const CREDIT_API = /^GET \/v1\/(packs|models|admin\/(batch-jobs|incidents|retention|tombstones)|decision-events)/;

test.beforeEach(({ api }) => {
  api.set("GET /v1/runtime", { json: { ...runtime, agent_only: true } });
});

test("the sidebar leaves out the credit track, Overview shows what is served", async ({ page, api }) => {
  await page.goto("/overview");
  const nav = page.getByRole("navigation", { name: "Main navigation" });
  await expect(nav.getByRole("link", { name: "Agents", exact: true })).toBeVisible();
  for (const name of CREDIT_LINKS) await expect(nav.getByRole("link", { name, exact: true })).toHaveCount(0);
  for (const name of ["Change requests", "Audit", "Closed loans"]) {
    await expect(nav.getByRole("link", { name, exact: true })).toBeVisible();
  }
  await expect(page.getByRole("heading", { name: "Runtime posture" })).toBeVisible();
  await expect(page.getByText("Active model", { exact: true })).toHaveCount(0);
  await expect(page.getByText("Sync evaluate", { exact: true })).toHaveCount(0);
  await expectNoViolations(page);
  expect(api.calls.filter((call) => CREDIT_API.test(call.key))).toEqual([]);
});

test("a credit-track path says it is not served and calls none of its routes", async ({ page, api }) => {
  for (const path of CREDIT_PATHS) {
    await page.goto(path);
    await expect(page.getByRole("heading", { level: 1, name: "Not served on this server" })).toBeVisible();
  }
  await expectNoViolations(page);
  expect(api.calls.filter((call) => CREDIT_API.test(call.key))).toEqual([]);
});

test("keyboard: from a not-served page to Agents", async ({ page }) => {
  await page.goto("/models");
  await expect(page.getByRole("heading", { level: 1, name: "Not served on this server" })).toBeVisible();
  const link = page.getByRole("main").getByRole("link", { name: "Go to Agents" });
  await link.focus();
  await expect(link).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/\/agents$/);
  await expect(page.getByRole("heading", { level: 1, name: "Agents" })).toBeVisible();
});

test("a server that serves the credit track keeps every page", async ({ page, api }) => {
  api.set("GET /v1/runtime", { json: { ...runtime, agent_only: false } });
  await page.goto("/models");
  await expect(page.getByRole("heading", { level: 1, name: "Models" })).toBeVisible();
  const nav = page.getByRole("navigation", { name: "Main navigation" });
  for (const name of CREDIT_LINKS) await expect(nav.getByRole("link", { name, exact: true })).toBeVisible();
});

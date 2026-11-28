// The console on an `--agent-only` kavach-api (playwright.real.config.ts,
// project "agent-only"), seeded by realSetup.ts: sign-in, the agent pages
// and their actions; the credit-track pages are not offered or served.
import type { Page } from "@playwright/test";
import { open, signInAs, signOut } from "./real";
import { REVOKING_EVENT, SEEDED, seededRecords } from "./realSetup";
import { ADMIN, AGENT, AGENT_ONLY, OTHER_AGENT } from "./realStack";
import { expect, test } from "./stack";

test.describe.configure({ mode: "serial" });

const CREDIT_LINKS = ["Evaluate", "Policies", "Models", "Batch jobs", "Incidents", "Retention", "Decision events"];
const CREDIT_PATHS = ["/evaluate", "/policies", "/models", "/batch", "/incidents", "/retention", "/decision-events"];

const status = (page: Page, text: string | RegExp) => page.getByRole("status").filter({ hasText: text });

test("an admin signs in; the nav and every agent page load without an error", async ({ page, context }) => {
  await signInAs(page, context, ADMIN);
  const nav = page.getByRole("navigation", { name: "Main navigation" });
  await expect(nav.getByRole("link", { name: "Agents", exact: true })).toBeVisible();
  for (const name of CREDIT_LINKS) await expect(nav.getByRole("link", { name, exact: true })).toHaveCount(0);

  for (const [path, heading] of [
    ["/overview", "Overview"],
    ["/agents", "Agents"],
    ["/agent-evidence", "Agent evidence"],
    ["/reconciliation", "Closed loans"],
    ["/changes", "Change requests"],
    ["/audit", "Admin audit"],
    ["/settings", "Settings"],
  ]) {
    await open(page, path, heading);
  }
  for (const path of CREDIT_PATHS) {
    await page.goto(path);
    await expect(page.getByRole("heading", { level: 1, name: "Not served on this server" })).toBeVisible();
  }
  await signOut(page);
});

test("agents, evidence and a stop", async ({ page, context }) => {
  await signInAs(page, context, ADMIN);
  await open(page, "/agents", "Agents");
  await expect(status(page, /^Page 1: 2 agents; no more follow\.$/)).toBeVisible();

  const records = seededRecords(AGENT_ONLY);
  const recordId = records[SEEDED.forged] ?? Object.values(records)[0];
  expect(recordId, "the seed saved a record id").toBeTruthy();
  await open(page, "/agent-evidence", "Agent evidence");
  await page.getByLabel("Record id", { exact: true }).fill(recordId);
  await page.getByRole("button", { name: "Look up record" }).click();
  await expect(status(page, `Found record ${recordId}.`)).toBeVisible();
  await page.getByLabel("System").fill("lms");
  await page.getByLabel("Event id").fill(REVOKING_EVENT);
  await page.getByRole("button", { name: "Look up revocation" }).click();
  await expect(status(page, `Found the revocation for event ${REVOKING_EVENT} from lms.`)).toBeVisible();

  await page.goto(`/agents/${OTHER_AGENT}`);
  await expect(status(page, `Agent ${OTHER_AGENT} is active.`)).toBeVisible();
  await page.getByRole("button", { name: "Restrict", exact: true }).click();
  const dialog = page.getByRole("alertdialog");
  await dialog.getByLabel("Reason code (required)").selectOption({ index: 1 });
  await dialog.getByRole("button", { name: "Restrict agent" }).click();
  await expect(status(page, "is now restricted")).toBeVisible();

  await page.goto(`/agents/${AGENT}`);
  await expect(status(page, `Agent ${AGENT} is active.`)).toBeVisible();
});

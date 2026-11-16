// axe on every page of the console, with the API stubbed and the server's
// Content-Security-Policy applied (e2e/page.ts). The tags are the WCAG 2.0,
// 2.1 and 2.2 level A and AA rules axe implements: a pass here is not a WCAG
// conformance claim, only that axe found nothing it checks for.
import { expectNoViolations } from "./axe";
import { forbidden } from "./fixtures";
import { expect, test } from "./page";

type PageCase = {
  path: string;
  title: string;
  /** Text that appears once the page's data has loaded. */
  ready?: string | RegExp;
};

const PAGES: PageCase[] = [
  { path: "/overview", title: "Overview", ready: "credit-risk" },
  { path: "/evaluate", title: "Evaluate" },
  { path: "/agents", title: "Agents", ready: "agent:kyc-bot" },
  { path: "/agents/agent:collections-bot", title: "Agent", ready: "Agent agent:collections-bot is active." },
  { path: "/agent-evidence", title: "Agent evidence" },
  { path: "/decision-events", title: "Decision events" },
  { path: "/reconciliation", title: "Closed loans" },
  { path: "/policies", title: "Policies", ready: "finance-core" },
  { path: "/policies/finance-core", title: "finance-core", ready: "income-floor" },
  { path: "/models", title: "Models", ready: "credit-risk" },
  { path: "/models/credit-risk", title: "credit-risk", ready: "Credit decision support" },
  { path: "/batch", title: "Batch jobs", ready: "9/10 ok · 1 fail" },
  { path: "/batch/job-1", title: "job-1", ready: "in/job-1.ndjson" },
  { path: "/changes", title: "Change requests", ready: "Reinstate agent" },
  { path: "/audit", title: "Admin audit", ready: "pack/finance-core" },
  { path: "/incidents", title: "Incidents", ready: "corr-77" },
  { path: "/retention", title: "Retention & erasure", ready: "ev-123" },
  { path: "/users", title: "Users & roles", ready: "Asha Rao" },
  { path: "/settings", title: "Settings" },
];

test.describe("axe, WCAG 2.2 AA tags", () => {
  for (const { path, title, ready } of PAGES) {
    test(`${path}`, async ({ page }) => {
      await page.goto(path);
      await expect(page.getByRole("heading", { level: 1, name: title })).toBeVisible();
      if (ready) await expect(page.getByText(ready).filter({ visible: true }).first()).toBeVisible();
      await expectNoViolations(page);
    });
  }

  test("an unknown path: a 404 page that names the path and links to Overview", async ({ page }) => {
    await page.goto("/no-such-page");
    await expect(page).toHaveURL(/\/no-such-page$/);
    await expect(page.getByRole("heading", { level: 1, name: "Page not found" })).toBeVisible();
    await expect(page.getByText("The console has no page at /no-such-page.")).toBeVisible();
    await expect(page.getByRole("link", { name: "Go to Overview" })).toBeVisible();
    await expectNoViolations(page);
  });

  test("an API refusal (problem detail in an alert)", async ({ page, api }) => {
    api.set("GET /v1/agents/agent:collections-bot", { status: 403, json: forbidden });
    await page.goto("/agents/agent:collections-bot");
    await expect(page.getByRole("alert")).toContainText("req-e2e-403");
    await expectNoViolations(page);
  });

  test("the stop dialog, open", async ({ page }) => {
    await page.goto("/agents/agent:collections-bot");
    await page.getByRole("button", { name: "Quarantine", exact: true }).click();
    await expect(page.getByRole("alertdialog")).toBeVisible();
    await expectNoViolations(page);
  });

  test("the stop dialog, with a field error", async ({ page }) => {
    await page.goto("/agents/agent:collections-bot");
    await page.getByRole("button", { name: "Quarantine", exact: true }).click();
    await page.getByRole("button", { name: "Quarantine agent" }).click();
    await expect(page.getByLabel("Reason code (required)")).toHaveAttribute("aria-invalid", "true");
    await expectNoViolations(page);
  });

  test("the navigation drawer, open on a narrow screen", async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto("/overview");
    await page.getByRole("button", { name: "Open navigation" }).click();
    await expect(page.getByRole("button", { name: "Close navigation" })).toBeVisible();
    await expectNoViolations(page);
  });
});

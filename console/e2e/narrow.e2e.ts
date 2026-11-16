// Every page at 375 by 800 CSS pixels, the narrowest width DESIGN.md asks
// for, with the API stubbed: the page does not scroll sideways, its main
// heading is visible, and axe finds nothing (same tags as a11y.e2e.ts).
import { expectNoViolations } from "./axe";
import { expect, test } from "./page";

type PageCase = {
  path: string;
  /** The page's level-1 heading. */
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
  { path: "/settings", title: "Settings" },
];

test.describe("375px wide", () => {
  test.use({ viewport: { width: 375, height: 800 } });

  for (const { path, title, ready } of PAGES) {
    test(path, async ({ page }) => {
      await page.goto(path);
      await expect(page.getByRole("heading", { level: 1, name: title })).toBeVisible();
      if (ready) await expect(page.getByText(ready).filter({ visible: true }).first()).toBeVisible();
      const overflow = await page.evaluate(() => {
        const root = document.documentElement;
        return { scrollWidth: root.scrollWidth, clientWidth: root.clientWidth };
      });
      expect(overflow.scrollWidth, "the page scrolls sideways").toBeLessThanOrEqual(overflow.clientWidth);
      await expectNoViolations(page);
    });
  }
});

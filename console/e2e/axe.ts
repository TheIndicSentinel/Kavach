// axe with the WCAG 2.0, 2.1 and 2.2 level A and AA tags. A pass is not a
// WCAG conformance claim, only that axe found nothing it checks for. No rule
// is ever disabled here: a violation is fixed in the console.
import AxeBuilder from "@axe-core/playwright";
import type { Page } from "@playwright/test";
import { expect } from "./page";

export const WCAG_TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"];

/** Fails with each rule, its impact and the elements it flagged. */
export async function expectNoViolations(page: Page) {
  const results = await new AxeBuilder({ page }).withTags(WCAG_TAGS).analyze();
  const found = results.violations.map(
    (v) => `${v.id} (${v.impact}): ${v.nodes.map((n) => n.target.join(" ")).join(" | ")}`,
  );
  expect(found).toEqual([]);
}

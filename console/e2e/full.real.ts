// The console on a full kavach-api (playwright.real.config.ts, project
// "full"), seeded by realSetup.ts. Every page and action, as the users of
// e2e/real-users.json. The tests share one server and run in order: the
// stops and change requests of one are the state the next one reads.
import type { Page } from "@playwright/test";
import { open, PAGES, signInAs, signOut } from "./real";
import { REVOKING_EVENT, SEEDED, seededRecords } from "./realSetup";
import { ADMIN, AGENT, APPROVER, FULL, OTHER_AGENT, VIEWER } from "./realStack";
import { expect, test } from "./stack";

test.describe.configure({ mode: "serial" });

const status = (page: Page, text: string | RegExp) => page.getByRole("status").filter({ hasText: text });

/** Opens an agent and waits for its state line. */
async function openAgent(page: Page, agent: string, state: string): Promise<void> {
  await page.goto(`/agents/${agent}`);
  await expect(status(page, `Agent ${agent} is ${state}.`)).toBeVisible();
}

/** Restrict, Quarantine or Revoke, with the first reason code the dialog offers. */
async function stop(page: Page, button: "Restrict" | "Quarantine" | "Revoke", confirm: string): Promise<void> {
  await page.getByRole("button", { name: button, exact: true }).click();
  const dialog = page.getByRole("alertdialog");
  await dialog.getByLabel("Reason code (required)").selectOption({ index: 1 });
  await dialog.getByRole("button", { name: confirm }).click();
  await expect(dialog).toHaveCount(0);
}

/** Proposes bringing `agent` back to active; returns the change request's id. */
async function proposeReinstatement(page: Page, agent: string): Promise<string> {
  await openAgent(page, agent, "quarantined");
  await page.getByRole("button", { name: "Request reinstatement" }).click();
  const dialog = page.getByRole("alertdialog");
  await dialog.getByLabel("Bring back to").selectOption("active");
  await dialog.getByLabel("Reason code (required)").selectOption({ index: 1 });
  await dialog.getByRole("button", { name: "Propose reinstatement" }).click();
  await expect(dialog).toHaveCount(0);
  const proposed = status(page, /Change request \S+ proposed/);
  await expect(proposed).toBeVisible();
  const id = (await proposed.textContent())?.match(/Change request (\S+) proposed/)?.[1];
  if (!id) throw new Error("no change request id in the status");
  return id;
}

/** Decides the one pending request on /changes; the status names the outcome. */
async function decide(page: Page, button: string, outcome: RegExp): Promise<void> {
  await open(page, "/changes", "Change requests");
  await page.getByRole("button", { name: button }).click();
  await expect(status(page, outcome)).toBeVisible();
  await expect(page.getByRole("button", { name: button })).toHaveCount(0);
}

test("an admin signs in and every page loads without an error", async ({ page, context }) => {
  await signInAs(page, context, ADMIN);
  for (const [path, heading] of PAGES) await open(page, path, heading);
  await signOut(page);
  await expect(page.getByRole("heading", { level: 1, name: "Sign in to Kavach" })).toBeVisible();
});

test("evaluate the sample request, then look up its decision event", async ({ page, context }) => {
  await signInAs(page, context, ADMIN);
  await open(page, "/evaluate", "Evaluate");
  await page.getByRole("button", { name: "Run evaluate" }).click();
  await expect(status(page, /^Evaluated: returned decision \S+\.$/)).toBeVisible();

  const evidenceId = (await page.locator("dt", { hasText: "Evidence ID" }).locator("+ dd").textContent())?.trim();
  expect(evidenceId, "the evaluation was recorded").toMatch(/\S/);
  expect(evidenceId).not.toBe("—");

  await open(page, "/decision-events", "Decision events");
  await page.getByLabel("Evidence id").fill(evidenceId ?? "");
  await page.getByRole("button", { name: "Look up event" }).click();
  await expect(status(page, `Found decision event ${evidenceId}.`)).toBeVisible();
});

test("the agents list shows both agents; the id field opens one", async ({ page, context }) => {
  await signInAs(page, context, ADMIN);
  await open(page, "/agents", "Agents");
  await expect(status(page, /^Page 1: 2 agents; no more follow\.$/)).toBeVisible();
  for (const agent of [AGENT, OTHER_AGENT]) {
    await expect(page.getByRole("link", { name: agent, exact: true })).toBeVisible();
  }

  await page.getByLabel("Agent id").fill(AGENT);
  await page.getByLabel("Agent id").press("Enter");
  await expect(page).toHaveURL(new RegExp(`/agents/${AGENT}$`));
  await expect(status(page, `Agent ${AGENT} is active.`)).toBeVisible();
});

test("agent evidence: a seeded decision record and the revocation", async ({ page, context }) => {
  const records = seededRecords(FULL);
  const recordId = records[SEEDED.forged] ?? Object.values(records)[0];
  expect(recordId, "the seed saved a record id").toBeTruthy();

  await signInAs(page, context, ADMIN);
  await open(page, "/agent-evidence", "Agent evidence");
  await page.getByLabel("Record id").fill(recordId);
  await page.getByRole("button", { name: "Look up record" }).click();
  await expect(status(page, `Found record ${recordId}.`)).toBeVisible();

  await page.getByLabel("System").fill("lms");
  await page.getByLabel("Event id").fill(REVOKING_EVENT);
  await page.getByRole("button", { name: "Look up revocation" }).click();
  await expect(status(page, `Found the revocation for event ${REVOKING_EVENT} from lms.`)).toBeVisible();
});

test("an admin restricts and quarantines an agent", async ({ page, context }) => {
  await signInAs(page, context, ADMIN);
  await openAgent(page, OTHER_AGENT, "active");
  await stop(page, "Restrict", "Restrict agent");
  await expect(status(page, "is now restricted")).toBeVisible();
  await stop(page, "Quarantine", "Quarantine agent");
  await expect(status(page, "is now quarantined")).toBeVisible();
});

test("the proposer cancels a reinstatement", async ({ page, context }) => {
  await signInAs(page, context, ADMIN);
  await proposeReinstatement(page, OTHER_AGENT);
  await decide(page, "Cancel (proposer)", /^Reinstate agent: cancelled/);
});

test("a change approver rejects a reinstatement", async ({ page, context }) => {
  await signInAs(page, context, ADMIN);
  await proposeReinstatement(page, OTHER_AGENT);
  await signOut(page);

  await signInAs(page, context, APPROVER);
  await decide(page, "Reject", /^Reinstate agent: rejected/);
});

test("a change approver approves a reinstatement and the agent is active again", async ({ page, context }) => {
  await signInAs(page, context, ADMIN);
  await proposeReinstatement(page, OTHER_AGENT);
  await signOut(page);

  await signInAs(page, context, APPROVER);
  await decide(page, "Approve and apply", /^Reinstate agent: approved/);
  await signOut(page);

  await signInAs(page, context, ADMIN);
  await openAgent(page, OTHER_AGENT, "active");
  // The admin audit names who approved it.
  await open(page, "/audit", "Admin audit");
  await expect(page.getByRole("cell", { name: APPROVER.sub, exact: true }).first()).toBeVisible();
});

test("an admin revokes an agent", async ({ page, context }) => {
  await signInAs(page, context, ADMIN);
  await openAgent(page, AGENT, "active");
  await stop(page, "Revoke", "Revoke agent permanently");
  // Revoked at once, or halfway with mandates left to finish.
  await expect(status(page, /is now revoked|repeat the revoke/).or(page.getByText("repeat the revoke to finish"))).toBeVisible();
});

test("reconcile the lender's closed loans", async ({ page, context }) => {
  await signInAs(page, context, ADMIN);
  await open(page, "/reconciliation", "Closed loans");
  await page
    .getByLabel("Closed loans (JSON)")
    .fill(
      JSON.stringify({
        system: "lms",
        records: [{ record_ref: "lms:loan/B-9382", state: "paid", closed_at: "2026-10-01T06:00:00Z" }],
      }),
    );
  await page.getByRole("button", { name: "Reconcile", exact: true }).click();
  await expect(status(page, /^Checked 1 loan: .*Nothing was revoked\.$/)).toBeVisible();
});

test("an admin proposes a model promotion and a retention change", async ({ page, context }) => {
  const proposed = "Change request proposed. A change approver must approve it on the Change requests page.";
  await signInAs(page, context, ADMIN);

  await open(page, "/models/credit-underwriting-v1", "credit-underwriting-v1");
  await page.getByRole("button", { name: "Propose promotion to production" }).click();
  await expect(page.getByText(proposed)).toBeVisible();

  await open(page, "/retention", "Retention & erasure");
  await page.getByRole("button", { name: "Propose policy change" }).click();
  await expect(page.getByText(proposed)).toBeVisible();

  await open(page, "/changes", "Change requests");
  await expect(page.getByRole("button", { name: "Cancel (proposer)" })).toHaveCount(2);
});

test("a viewer sees what their groups may not do", async ({ page, context }) => {
  await signInAs(page, context, VIEWER);
  await open(page, "/overview", "Overview");
  await page.goto("/reconciliation");
  await expect(page.getByRole("heading", { level: 1, name: "Closed loans" })).toBeVisible();
  await expect(
    page.getByText(`Your groups (${VIEWER.groups.join(", ")}) don't include one that may reconcile closed loans.`),
  ).toBeVisible();
  await signOut(page);
});

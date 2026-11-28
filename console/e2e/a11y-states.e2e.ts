// axe on the states a page reaches after an action: each lookup with a result,
// a not-found problem and a rate-limit problem; reconciliation with and
// without findings; an evaluate result; a pending reinstatement for each
// viewer the console can tell apart; an agent in every state; and a revoke
// that left mandates to finish. Same tags as a11y.e2e.ts, no rule disabled.
import type { Page } from "@playwright/test";
import type { Stub } from "./api";
import { expectNoViolations } from "./axe";
import * as body from "./fixtures";
import { asPrincipal } from "./keys";
import { expect, test } from "./page";

const RECORD_ID = body.decisionLookup.record.record_id;
const SYSTEM = body.revocationLookup.record.source_system;
const EVENT_ID = body.revocationLookup.record.event_id;

const PROBLEMS: [string, Stub][] = [
  ["not found", { status: 404, json: body.notFound }],
  ["rate limited", { status: 429, json: body.rateLimited }],
];

type Lookup = {
  name: string;
  path: string;
  key: string;
  result: unknown;
  /** Fills the form and submits it. */
  submit: (page: Page) => Promise<void>;
  /** The status line once the result is in. */
  found: string | RegExp;
};

const LOOKUPS: Lookup[] = [
  {
    name: "agent decision lookup",
    path: "/agent-evidence",
    key: `GET /v1/agent-decisions/${RECORD_ID}`,
    result: body.decisionLookup,
    submit: async (page) => {
      await page.getByLabel("Record id", { exact: true }).fill(RECORD_ID);
      await page.getByRole("button", { name: "Look up record" }).click();
    },
    found: `Found record ${RECORD_ID}.`,
  },
  {
    name: "revocation lookup",
    path: "/agent-evidence",
    key: `GET /v1/agent-revocations/${SYSTEM}/${EVENT_ID}`,
    result: body.revocationLookup,
    submit: async (page) => {
      await page.getByLabel("System").fill(SYSTEM);
      await page.getByLabel("Event id").fill(EVENT_ID);
      await page.getByRole("button", { name: "Look up revocation" }).click();
    },
    found: `Found the revocation for event ${EVENT_ID} from ${SYSTEM}.`,
  },
  {
    name: "decision-event lookup",
    path: "/decision-events",
    key: `GET /v1/decision-events/${body.EVIDENCE_ID}`,
    result: body.decisionEvent,
    submit: async (page) => {
      await page.getByLabel("Evidence id").fill(body.EVIDENCE_ID);
      await page.getByRole("button", { name: "Look up event" }).click();
    },
    found: `Found decision event ${body.EVIDENCE_ID}.`,
  },
  {
    name: "agent lookup (agent detail)",
    path: "/agents",
    key: "GET /v1/agents/agent:collections-bot",
    result: body.neverChanged,
    submit: async (page) => {
      await expect(page.getByRole("status").filter({ hasText: "Page 1" })).toBeVisible();
      await page.getByLabel("Agent id").fill("agent:collections-bot");
      await page.getByRole("button", { name: "Look up", exact: true }).click();
    },
    found: "Agent agent:collections-bot is active.",
  },
];

test.describe("axe after a lookup", () => {
  for (const lookup of LOOKUPS) {
    test(`${lookup.name}: a result`, async ({ page, api }) => {
      api.set(lookup.key, { json: lookup.result });
      await page.goto(lookup.path);
      await lookup.submit(page);
      await expect(page.getByRole("status").filter({ hasText: lookup.found })).toBeVisible();
      await expectNoViolations(page);
    });

    for (const [problem, stub] of PROBLEMS) {
      test(`${lookup.name}: ${problem}`, async ({ page, api }) => {
        api.set(lookup.key, stub);
        await page.goto(lookup.path);
        await lookup.submit(page);
        const alert = page.getByRole("alert").filter({ hasText: `req-e2e-${stub.status}` });
        await expect(alert).toContainText(`HTTP ${stub.status}`);
        await expectNoViolations(page);
      });
    }
  }
});

test.describe("axe after reconciling closed loans", () => {
  const LIST = JSON.stringify({
    system: "lms",
    records: [{ record_ref: "lms:loan/L-1", state: "paid", closed_at: "2026-10-01T06:00:00Z" }],
  });

  for (const [name, result, summary] of [
    ["with findings", body.reconciliation, "1 mandate should have been revoked"],
    ["with none", body.cleanReconciliation, "none holds a live mandate"],
  ] as const) {
    test(name, async ({ page, api }) => {
      api.set("POST /v1/reconciliation/closed-records", { json: result });
      await page.goto("/reconciliation");
      await page.getByLabel("Closed loans (JSON)").fill(LIST);
      await page.getByRole("button", { name: "Reconcile", exact: true }).click();
      await expect(page.getByRole("status").filter({ hasText: summary })).toBeVisible();
      await expectNoViolations(page);
    });
  }

  test("with a field error", async ({ page }) => {
    await page.goto("/reconciliation");
    await page.getByLabel("Closed loans (JSON)").fill("{");
    await page.getByRole("button", { name: "Reconcile", exact: true }).click();
    await expect(page.getByLabel("Closed loans (JSON)")).toHaveAttribute("aria-invalid", "true");
    await expectNoViolations(page);
  });
});

test.describe("axe after evaluate", () => {
  test("a result", async ({ page, api }) => {
    api.set("POST /v1/evaluate", { json: body.evaluateResult });
    await page.goto("/evaluate");
    await page.getByRole("button", { name: "Run evaluate" }).click();
    await expect(page.getByRole("status").filter({ hasText: "returned decision BLOCK" })).toBeVisible();
    await expectNoViolations(page);
  });

  test("a refusal", async ({ page, api }) => {
    api.set("POST /v1/evaluate", { status: 403, json: body.forbidden });
    await page.goto("/evaluate");
    await page.getByRole("button", { name: "Run evaluate" }).click();
    await expect(page.getByRole("alert").filter({ hasText: "req-e2e-403" })).toBeVisible();
    await expectNoViolations(page);
  });

  test("a JSON error on the field", async ({ page }) => {
    await page.goto("/evaluate");
    await page.getByLabel("EvaluateRequest JSON").fill("{");
    await page.getByRole("button", { name: "Run evaluate" }).click();
    await expect(page.getByLabel("EvaluateRequest JSON")).toHaveAttribute("aria-invalid", "true");
    await expectNoViolations(page);
  });
});

test.describe("axe on a pending reinstate_agent change request", () => {
  // In the development fallback the groups are unknown, so the browser can tell
  // apart only the principal: none (or a token), the proposer, and another
  // principal. Login mode, where the session names the groups, is in login.e2e.ts.
  for (const [viewer, principal, button] of [
    ["unknown viewer", null, "Approve and apply"],
    ["the proposer", "operator-1", "Cancel (proposer)"],
    ["another principal", "admin-2", "Reject"],
  ] as const) {
    test(viewer, async ({ page }) => {
      if (principal) await asPrincipal(page, principal);
      await page.goto("/changes");
      await expect(page.getByRole("button", { name: button })).toBeVisible();
      await expectNoViolations(page);
    });
  }
});

test("axe on the result line after a change request is decided", async ({ page, api }) => {
  const id = body.reinstateProposed.id;
  let decided = false;
  api.set(`POST /v1/change-requests/${id}/approve`, () => {
    decided = true;
    return { json: body.reinstateDecided("applied") };
  });
  api.set("GET /v1/change-requests", () => ({ json: decided ? [] : [body.reinstateProposed] }));
  await asPrincipal(page, "admin-2");
  await page.goto("/changes");
  await page.getByRole("button", { name: "Approve and apply" }).click();
  await expect(page.getByRole("status").filter({ hasText: "Reinstate agent: approved (applied)." })).toBeVisible();
  await expectNoViolations(page);
});

test.describe("axe on agent detail in every state", () => {
  for (const agent of [body.neverChanged, body.reinstated, body.quarantined, body.revokedAgent]) {
    test(agent.state, async ({ page, api }) => {
      api.set(`GET /v1/agents/${agent.agent_id}`, { json: agent });
      await page.goto(`/agents/${agent.agent_id}`);
      await expect(
        page.getByRole("status").filter({ hasText: `Agent ${agent.agent_id} is ${agent.state}.` }),
      ).toBeVisible();
      await expectNoViolations(page);
    });
  }

  test("a revoke that left mandates: repeat the revoke to finish", async ({ page, api }) => {
    const agent = body.quarantined;
    api.set(`GET /v1/agents/${agent.agent_id}`, { json: agent });
    api.set(`POST /v1/agents/${agent.agent_id}/revoke`, { json: body.revokeHalfway });
    await page.goto(`/agents/${agent.agent_id}`);
    await page.getByRole("button", { name: "Revoke", exact: true }).click();
    await page.getByLabel("Reason code (required)").selectOption("compromise_suspected");
    await page.getByRole("button", { name: "Revoke agent permanently" }).click();
    await expect(page.getByText("repeat the revoke to finish")).toBeVisible();
    await expectNoViolations(page);
  });
});

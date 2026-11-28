// Every action in the console finished from the keyboard alone: Tab to the
// control, Enter, type into the fields (type-ahead for a select), Enter. Each
// flow checks the request body the API got and where focus is after the result.
import type { Page, Request } from "@playwright/test";
import * as body from "./fixtures";
import { asPrincipal, tabTo } from "./keys";
import { expect, test, type CspGuard } from "./page";
import type { ApiStub } from "./api";

type Fixtures = { page: Page; api: ApiStub; csp: CspGuard };

const sent = (api: ApiStub, key: string) => api.calls.filter((call) => call.key === key);

async function openAgent(page: Page, api: ApiStub, agent: { agent_id: string; state: string }) {
  api.set(`GET /v1/agents/${agent.agent_id}`, { json: agent });
  await page.goto(`/agents/${agent.agent_id}`);
  await expect(
    page.getByRole("status").filter({ hasText: `Agent ${agent.agent_id} is ${agent.state}.` }),
  ).toBeVisible();
}

test.describe("agent actions from the keyboard", () => {
  test("restrict", async ({ page, api }: Fixtures) => {
    const agent = body.neverChanged;
    const key = `POST /v1/agents/${agent.agent_id}/restrict`;
    api.set(key, { json: body.restrictApplied });
    await openAgent(page, api, agent);

    await tabTo(page, page.getByRole("button", { name: "Restrict", exact: true }));
    await page.keyboard.press("Enter");
    await expect(page.getByLabel("Reason code (required)")).toBeFocused();
    await page.keyboard.type("Operator");
    await expect(page.getByLabel("Reason code (required)")).toHaveValue("operator_request");
    await page.keyboard.press("Tab");
    await page.keyboard.press("Enter"); // in the note: submits the form

    await expect(page.getByRole("alertdialog")).toHaveCount(0);
    await expect(page.getByRole("status").filter({ hasText: "is now restricted" })).toBeVisible();
    expect(sent(api, key).map((call) => call.body)).toEqual([{ reason_code: "operator_request" }]);
    // The Restrict button went with the state it applied to: focus is on the agent.
    await expect(page.getByRole("heading", { name: agent.agent_id })).toBeFocused();
  });

  test("revoke, with mandates left to finish", async ({ page, api }: Fixtures) => {
    const agent = body.quarantined;
    const key = `POST /v1/agents/${agent.agent_id}/revoke`;
    api.set(key, { json: body.revokeHalfway });
    await openAgent(page, api, agent);

    await tabTo(page, page.getByRole("button", { name: "Revoke", exact: true }));
    await page.keyboard.press("Enter");
    await page.keyboard.type("Compromise");
    await expect(page.getByLabel("Reason code (required)")).toHaveValue("compromise_suspected");
    await page.keyboard.press("Tab");
    await page.keyboard.type("key leaked");
    await page.keyboard.press("Enter");

    await expect(page.getByRole("alertdialog")).toHaveCount(0);
    await expect(page.getByText("repeat the revoke to finish")).toBeVisible();
    expect(sent(api, key).map((call) => call.body)).toEqual([
      { reason_code: "compromise_suspected", note: "key leaked" },
    ]);
    // The same button now repeats the revoke, which is the way to finish.
    await expect(page.getByRole("button", { name: "Repeat revoke" })).toBeFocused();
  });

  test("propose reinstatement", async ({ page, api }: Fixtures) => {
    const agent = body.quarantined;
    const key = "POST /v1/change-requests";
    api.set(key, { json: body.reinstateProposed });
    await openAgent(page, api, agent);

    const opener = page.getByRole("button", { name: "Request reinstatement" });
    await tabTo(page, opener);
    await page.keyboard.press("Enter");
    await expect(page.getByLabel("Bring back to")).toBeFocused();
    await page.keyboard.type("restricted");
    await expect(page.getByLabel("Bring back to")).toHaveValue("restricted");
    await page.keyboard.press("Tab");
    await page.keyboard.type("Reviewed");
    await expect(page.getByLabel("Reason code (required)")).toHaveValue("reviewed");
    await page.keyboard.press("Tab");
    await page.keyboard.type("checked by risk");
    await page.keyboard.press("Enter");

    await expect(page.getByRole("alertdialog")).toHaveCount(0);
    await expect(page.getByRole("status").filter({ hasText: "Change request cr-0099 proposed" })).toBeVisible();
    expect(sent(api, key).map((call) => call.body)).toEqual([
      {
        kind: "reinstate_agent",
        params: {
          agent_id: agent.agent_id,
          to: "restricted",
          reason_code: "reviewed",
          note: "checked by risk",
        },
      },
    ]);
    await expect(opener).toBeFocused();
  });
});

test.describe("change requests from the keyboard", () => {
  const ID = body.reinstateProposed.id;
  const DONE = { approve: "approved", reject: "rejected", cancel: "cancelled" } as const;

  /** The list shows the request pending until it is decided, then nothing pending. */
  function decideWith(api: ApiStub, action: string, status: Parameters<typeof body.reinstateDecided>[0]) {
    let decided = false;
    api.set(`POST /v1/change-requests/${ID}/${action}`, () => {
      decided = true;
      return { json: body.reinstateDecided(status) };
    });
    api.set("GET /v1/change-requests", () => ({ json: decided ? [] : [body.reinstateProposed] }));
  }

  for (const [action, principal, button, status, expected] of [
    ["approve", "admin-2", "Approve and apply", "applied", { change_digest: "sha256:abc" }],
    ["reject", "admin-2", "Reject", "rejected", {}],
    ["cancel", "operator-1", "Cancel (proposer)", "cancelled", null],
  ] as const) {
    test(action, async ({ page, api }: Fixtures) => {
      decideWith(api, action, status);
      await asPrincipal(page, principal);
      await page.goto("/changes");
      await tabTo(page, page.getByRole("button", { name: button }));
      await page.keyboard.press("Enter");

      const result = page.getByRole("status").filter({ hasText: `Reinstate agent: ` });
      await expect(result).toHaveText(`Reinstate agent: ${DONE[action]} (${status}).`);
      expect(sent(api, `POST /v1/change-requests/${ID}/${action}`).map((call) => call.body)).toEqual([
        expected,
      ]);
      // The buttons went with the pending request: focus is on the result.
      await expect(result).toBeFocused();
      await expect(page.getByRole("button", { name: button })).toHaveCount(0);
    });
  }
});

test.describe("lookups from the keyboard", () => {
  test("agent decision record", async ({ page, api }: Fixtures) => {
    const id = body.decisionLookup.record.record_id;
    const key = `GET /v1/agent-decisions/${id}`;
    api.set(key, { json: body.decisionLookup });
    await page.goto("/agent-evidence");
    await tabTo(page, page.getByLabel("Record id", { exact: true }));
    await page.keyboard.type(id);
    await page.keyboard.press("Tab");
    const button = page.getByRole("button", { name: "Look up record" });
    await expect(button).toBeFocused();
    await page.keyboard.press("Enter");

    await expect(page.getByRole("status").filter({ hasText: `Found record ${id}.` })).toBeVisible();
    expect(sent(api, key)).toHaveLength(1);
    await expect(button).toBeFocused();
  });

  test("revocation record", async ({ page, api }: Fixtures) => {
    const { source_system: system, event_id: event } = body.revocationLookup.record;
    const key = `GET /v1/agent-revocations/${system}/${event}`;
    api.set(key, { json: body.revocationLookup });
    await page.goto("/agent-evidence");
    await tabTo(page, page.getByLabel("System"));
    await page.keyboard.type(system);
    await page.keyboard.press("Tab");
    await expect(page.getByLabel("Event id")).toBeFocused();
    await page.keyboard.type(event);
    await page.keyboard.press("Enter"); // in the field: submits the form

    await expect(
      page.getByRole("status").filter({ hasText: `Found the revocation for event ${event} from ${system}.` }),
    ).toBeVisible();
    expect(sent(api, key)).toHaveLength(1);
    await expect(page.getByLabel("Event id")).toBeFocused();
  });

  test("a refused id puts focus on its field and sends nothing", async ({ page, api }: Fixtures) => {
    await page.goto("/agent-evidence");
    await tabTo(page, page.getByLabel("Record id", { exact: true }));
    await page.keyboard.type("not a record id");
    await page.keyboard.press("Enter");
    await expect(page.getByLabel("Record id", { exact: true })).toHaveAttribute("aria-invalid", "true");
    await expect(page.getByLabel("Record id", { exact: true })).toBeFocused();
    expect(api.calls.filter((call) => call.key.startsWith("GET /v1/agent-decisions/"))).toEqual([]);
  });

  test("decision event", async ({ page, api }: Fixtures) => {
    const key = `GET /v1/decision-events/${body.EVIDENCE_ID}`;
    api.set(key, { json: body.decisionEvent });
    await page.goto("/decision-events");
    await tabTo(page, page.getByLabel("Evidence id"));
    await page.keyboard.type(body.EVIDENCE_ID);
    await page.keyboard.press("Tab");
    const button = page.getByRole("button", { name: "Look up event" });
    await expect(button).toBeFocused();
    await page.keyboard.press("Enter");

    await expect(
      page.getByRole("status").filter({ hasText: `Found decision event ${body.EVIDENCE_ID}.` }),
    ).toBeVisible();
    expect(sent(api, key)).toHaveLength(1);
    await expect(button).toBeFocused();
  });
});

test.describe("reconciliation from the keyboard", () => {
  const LIST = {
    system: "lms",
    records: [{ record_ref: "lms:loan/L-1", state: "paid", closed_at: "2026-10-01T06:00:00Z" }],
  };

  test("paste the list and submit", async ({ page, api }: Fixtures) => {
    const key = "POST /v1/reconciliation/closed-records";
    api.set(key, { json: body.reconciliation });
    await page.goto("/reconciliation");
    await tabTo(page, page.getByLabel("Closed loans (JSON)"));
    // A paste: the text arrives in one input event, as from the clipboard.
    await page.keyboard.insertText(JSON.stringify(LIST));
    await page.keyboard.press("Tab");
    const button = page.getByRole("button", { name: "Reconcile", exact: true });
    await expect(button).toBeFocused();
    await page.keyboard.press("Enter");

    await expect(
      page.getByRole("status").filter({ hasText: "1 mandate should have been revoked" }),
    ).toBeVisible();
    expect(sent(api, key).map((call) => call.body)).toEqual([LIST]);
    await expect(button).toBeFocused();
  });

  test("a list that does not parse puts focus on the list and sends nothing", async ({
    page,
    api,
  }: Fixtures) => {
    await page.goto("/reconciliation");
    await tabTo(page, page.getByLabel("Closed loans (JSON)"));
    await page.keyboard.insertText("{");
    await page.keyboard.press("Tab");
    await page.keyboard.press("Enter");
    await expect(page.getByLabel("Closed loans (JSON)")).toBeFocused();
    await expect(page.getByLabel("Closed loans (JSON)")).toHaveAttribute("aria-invalid", "true");
    expect(sent(api, "POST /v1/reconciliation/closed-records")).toEqual([]);
  });
});

test.describe("evaluate from the keyboard", () => {
  test("run the sample request", async ({ page, api }: Fixtures) => {
    const key = "POST /v1/evaluate";
    api.set(key, { json: body.evaluateResult });
    await page.goto("/evaluate");
    const button = page.getByRole("button", { name: "Run evaluate" });
    await tabTo(page, button);
    await page.keyboard.press("Enter");

    await expect(page.getByRole("status").filter({ hasText: "returned decision BLOCK" })).toBeVisible();
    const calls = sent(api, key);
    expect(calls).toHaveLength(1);
    expect(calls[0].body).toMatchObject({
      model_id: "credit-underwriting-v1",
      purpose: "credit_decision",
      input: { loan_amount: 450000, monthly_income_inr: 92000 },
    });
    await expect(button).toBeFocused();
  });

  test("JSON that does not parse puts focus on the request and sends nothing", async ({
    page,
    api,
  }: Fixtures) => {
    await page.goto("/evaluate");
    const field = page.getByLabel("EvaluateRequest JSON");
    await tabTo(page, field);
    await page.keyboard.press("ControlOrMeta+A");
    await page.keyboard.insertText("{");
    await tabTo(page, page.getByRole("button", { name: "Run evaluate" }));
    await page.keyboard.press("Enter");
    await expect(field).toBeFocused();
    await expect(field).toHaveAttribute("aria-invalid", "true");
    await expect(field).toHaveAccessibleDescription(/not valid JSON/);
    expect(sent(api, "POST /v1/evaluate")).toEqual([]);
  });
});

test.describe("the agents list from the keyboard", () => {
  /** Answers by query, and keeps each query the console sent. */
  function pagedAgents(api: ApiStub): URLSearchParams[] {
    const queries: URLSearchParams[] = [];
    api.set("GET /v1/agents", (request: Request) => {
      const query = new URL(request.url()).searchParams;
      queries.push(query);
      if (query.get("state") === "quarantined") return { json: body.agentPageTwo };
      return { json: query.get("cursor") === "cursor-page-2" ? body.agentPageTwo : body.agentPageOne };
    });
    return queries;
  }

  test("next and previous page", async ({ page, api }: Fixtures) => {
    const queries = pagedAgents(api);
    await page.goto("/agents");
    await expect(page.getByRole("status").filter({ hasText: "Page 1: 2 agents; more may follow." })).toBeVisible();

    const next = page.getByRole("button", { name: "Next page" });
    await tabTo(page, next);
    await page.keyboard.press("Enter");
    await expect(page.getByRole("status").filter({ hasText: "Page 2: 1 agent; no more follow." })).toBeVisible();
    expect(queries.at(-1)?.get("cursor")).toBe("cursor-page-2");
    // Next page is now aria-disabled, and keeps focus.
    await expect(next).toBeFocused();
    await expect(next).toHaveAttribute("aria-disabled", "true");

    const previous = page.getByRole("button", { name: "Previous page" });
    await page.keyboard.press("Shift+Tab");
    await expect(previous).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(page.getByRole("status").filter({ hasText: "Page 1: 2 agents" })).toBeVisible();
    expect(queries.at(-1)?.get("cursor")).toBeNull();
    await expect(previous).toBeFocused();
  });

  test("the state filter", async ({ page, api }: Fixtures) => {
    const queries = pagedAgents(api);
    await page.goto("/agents");
    await expect(page.getByRole("status").filter({ hasText: "Page 1" })).toBeVisible();

    const filter = page.getByLabel("State");
    await tabTo(page, filter);
    await page.keyboard.type("quarantined");
    await expect(filter).toHaveValue("quarantined");
    await expect(
      page.getByRole("status").filter({ hasText: "Page 1: 1 quarantined agent; no more follow." }),
    ).toBeVisible();
    expect(queries.at(-1)?.get("state")).toBe("quarantined");
    expect(queries.at(-1)?.get("limit")).toBe("50");
    await expect(filter).toBeFocused();
  });
});

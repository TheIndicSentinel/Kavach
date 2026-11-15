// Console sign-in (ADR-018 option C) in a browser, against the stubbed API:
// each mode /auth/config selects, a stubbed sign-in and sign-out, a session
// that ends, the keyboard, axe on every state, what the browser holds
// afterwards, and the role hints the session's groups drive. The real IdP
// round trip against the backend is in roundtrip.roundtrip.ts.
import type { Page, Request } from "@playwright/test";
import type { ApiStub } from "./api";
import { expectNoViolations } from "./axe";
import * as body from "./fixtures";
import { tabTo } from "./keys";
// The server's CSP guard (page.ts) runs on every login state too.
import { expect, test } from "./page";

/**
 * Login mode with a stubbed server session. `/auth/login` (a top-level
 * navigation) "signs in": it marks the session live, sets an opaque HttpOnly
 * cookie as the real server would, and answers 303 to `/`.
 * `POST /auth/logout` ends it.
 */
async function loginMode(page: Page, api: ApiStub, signedIn: boolean, session = body.authSession) {
  const server = { live: signedIn };
  api.set("GET /auth/config", { json: body.authConfigLogin });
  api.set("GET /auth/session", () =>
    server.live ? { json: session } : { status: 401, json: body.noSession },
  );
  api.set("POST /auth/logout", () => {
    server.live = false;
    return { json: body.logoutLocal };
  });
  await page.route("**/auth/login", async (route) => {
    server.live = true;
    await route.fulfill({
      status: 303,
      headers: {
        location: "/",
        "set-cookie": "kavach_session_e2e=opaque-id; HttpOnly; Path=/; SameSite=Strict",
        "cache-control": "no-store",
      },
    });
  });
  return server;
}

/** Every request the console sends to its API, with the headers it carried. */
function recordApiRequests(page: Page): Request[] {
  const seen: Request[] = [];
  page.on("request", (request) => {
    const path = new URL(request.url()).pathname;
    if (["/health", "/v1/", "/auth/"].some((p) => path.startsWith(p))) seen.push(request);
  });
  return seen;
}

const signInHeading = (page: Page) => page.getByRole("heading", { level: 1, name: "Sign in to Kavach" });
const signInLink = (page: Page) => page.getByRole("link", { name: "Sign in" });
const signOutButton = (page: Page) => page.getByRole("button", { name: "Sign out" });

test.describe("login mode", () => {
  test("signed out: any page goes to /signin, which offers only a link", async ({ page, api }) => {
    await loginMode(page, api, false);
    await page.goto("/overview");
    await expect(page).toHaveURL(/\/signin$/);
    await expect(signInHeading(page)).toBeVisible();
    await expect(signInLink(page)).toHaveAttribute("href", "/auth/login");
    await expect(page.locator("form, input")).toHaveCount(0);
    await expect(page.getByText("Tokens stay on the Kavach server")).toBeVisible();
    expect(api.calls.map((c) => c.key).filter((k) => k.includes("/v1/"))).toEqual([]);
    await expectNoViolations(page);
  });

  test("signed in: the header shows the principal and a sign-out button", async ({ page, api }) => {
    await loginMode(page, api, true);
    const requests = recordApiRequests(page);
    await page.goto("/overview");
    await expect(page.getByRole("heading", { level: 1, name: "Overview" })).toBeVisible();
    await expect(page.getByRole("banner")).toContainText("oidc-operator-7");
    await expect(signOutButton(page)).toBeVisible();
    await expect(page.getByText("credit-risk").filter({ visible: true }).first()).toBeVisible();
    await expectNoViolations(page);

    expect(requests.length).toBeGreaterThan(2);
    for (const request of requests) {
      const headers = await request.allHeaders();
      expect(headers["x-kavach-console"], request.url()).toBe("1");
      expect(headers.authorization, request.url()).toBeUndefined();
      expect(headers["x-kavach-principal"], request.url()).toBeUndefined();
    }
  });

  test("the settings page describes the session, not a token field", async ({ page, api }) => {
    await loginMode(page, api, true);
    await page.goto("/settings");
    await expect(page.getByRole("heading", { level: 1, name: "Settings" })).toBeVisible();
    await expect(page.getByText("operators", { exact: true })).toBeVisible();
    await expect(page.locator("input")).toHaveCount(0);
    await expectNoViolations(page);
  });

  test("after sign-in, browser storage and document.cookie hold no token", async ({ page, api }) => {
    // Left over from the pasted-token days: removed on load in login mode.
    await page.addInitScript(() => {
      sessionStorage.setItem("kavach.accessToken", "eyJleftover.token.value");
      sessionStorage.setItem("kavach.principal", "operator-1");
    });
    await loginMode(page, api, false);
    await page.goto("/signin");
    await signInLink(page).click();
    await expect(page).toHaveURL(/\/overview$/);
    await expect(page.getByRole("banner")).toContainText("oidc-operator-7");

    const held = await page.evaluate(async () => ({
      local: Object.keys(localStorage),
      session: Object.keys(sessionStorage),
      databases: (await indexedDB.databases()).map((d) => d.name),
      cookie: document.cookie,
    }));
    expect(held).toEqual({ local: [], session: [], databases: [], cookie: "" });
    // The session cookie exists, but no script on the page can read it.
    const cookies = await page.context().cookies();
    expect(cookies.find((c) => c.name === "kavach_session_e2e")?.httpOnly).toBe(true);
    expect(api.unexpected).toEqual([]);
  });

  test("a 401 ends the session: /signin says so, and Back shows no signed-in data", async ({ page, api }) => {
    const server = await loginMode(page, api, true);
    await page.goto("/overview");
    await expect(page.getByText("credit-risk").filter({ visible: true }).first()).toBeVisible();

    server.live = false;
    api.set("GET /v1/agents", { status: 401, json: body.noSession });
    await page.getByRole("link", { name: "Agents" }).first().click();

    await expect(page).toHaveURL(/\/signin$/);
    await expect(page.getByRole("status")).toHaveText("Your session ended. Sign in again.");
    await expect(signInLink(page)).toBeVisible();
    await expectNoViolations(page);

    await page.goBack();
    await expect(signInHeading(page)).toBeVisible();
    await expect(page.getByRole("heading", { level: 1, name: "Overview" })).toHaveCount(0);
    await expect(page.getByText("credit-risk")).toHaveCount(0);
  });

  test("sign-in errors: a plain message, never the raw query value", async ({ page, api }) => {
    await loginMode(page, api, false);
    await page.goto("/signin?error=login_expired");
    await expect(page.getByRole("alert")).toContainText("expired or was already used");
    await expectNoViolations(page);

    await page.goto(`/signin?error=${encodeURIComponent("<i>call this number</i>")}`);
    await expect(page.getByRole("alert")).toHaveText("Sign-in did not complete. Try again.");
    await expect(page.getByText("call this number")).toHaveCount(0);
  });

  test("keyboard only: the sign-in link and the sign-out button", async ({ page, api }) => {
    await loginMode(page, api, false);
    await page.goto("/signin");
    await tabTo(page, signInLink(page));
    await page.keyboard.press("Enter");
    await expect(page).toHaveURL(/\/overview$/);
    await expect(signOutButton(page)).toBeVisible();

    await tabTo(page, signOutButton(page));
    await page.keyboard.press("Enter");
    await expect(page).toHaveURL(/\/signin$/);
    await expect(signInHeading(page)).toBeVisible();
    expect(api.calls.map((c) => c.key)).toContain("POST /auth/logout");
    // Signed out by choice: no session-ended message.
    await expect(page.getByRole("status")).toHaveText("");

    await page.goBack();
    await expect(signInHeading(page)).toBeVisible();
    await expect(page.getByText("credit-risk")).toHaveCount(0);
  });
});

test.describe("login mode: role hints from the session's groups", () => {
  const agent = body.quarantined;
  const approve = (page: Page) => page.getByRole("button", { name: "Approve and apply" });
  const reject = (page: Page) => page.getByRole("button", { name: "Reject" });

  test("viewers only: agent detail shows the hint lines, not the stop or reinstate controls", async ({
    page,
    api,
  }) => {
    await loginMode(page, api, true, body.viewerSession);
    api.set(`GET /v1/agents/${agent.agent_id}`, { json: agent });
    await page.goto(`/agents/${agent.agent_id}`);
    await expect(page.getByRole("status").filter({ hasText: `Agent ${agent.agent_id} is quarantined.` })).toBeVisible();
    await expect(
      page.getByText("Your groups (viewers) don't include one that may stop agents."),
    ).toBeVisible();
    await expect(
      page.getByText("Your groups (viewers) don't include one that may propose reinstating an agent."),
    ).toBeVisible();
    await expect(page.getByRole("button", { name: "Revoke", exact: true })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Request reinstatement" })).toHaveCount(0);
    await expectNoViolations(page);
  });

  test("viewers only: a pending change request shows the hint line, not approve or reject", async ({
    page,
    api,
  }) => {
    await loginMode(page, api, true, body.viewerSession);
    await page.goto("/changes");
    await expect(
      page.getByText("Your groups (viewers) don't include one that may approve or reject this change."),
    ).toBeVisible();
    await expect(approve(page)).toHaveCount(0);
    await expect(reject(page)).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Cancel (proposer)" })).toHaveCount(0);
    await expectNoViolations(page);
  });

  test("admins and change-approvers: the controls show, with no hint line", async ({ page, api }) => {
    await loginMode(page, api, true, body.approverSession);
    api.set(`GET /v1/agents/${agent.agent_id}`, { json: agent });
    await page.goto(`/agents/${agent.agent_id}`);
    await expect(page.getByRole("button", { name: "Revoke", exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Request reinstatement" })).toBeVisible();
    await expect(page.getByText(/Your groups \(/)).toHaveCount(0);

    await page.getByRole("link", { name: "Change requests" }).first().click();
    await expect(approve(page)).toBeVisible();
    await expect(reject(page)).toBeVisible();
    await expect(page.getByText(/Your groups \(/)).toHaveCount(0);
    await expectNoViolations(page);
  });
});

test.describe("other modes", () => {
  test("development fallback: the pasted-token field, labelled as such", async ({ page }) => {
    await page.goto("/signin");
    await expect(page.getByRole("heading", { level: 1, name: "Development sign-in" })).toBeVisible();
    await expect(page.getByText("Development fallback.")).toBeVisible();
    await expect(page.getByLabel("Access token (OIDC)")).toBeVisible();
    await expect(page.getByLabel("Principal ID")).toBeVisible();
    await expect(signInLink(page)).toHaveCount(0);
    await expectNoViolations(page);

    // The pages work as before, with no sign-out (there is no session).
    await page.goto("/overview");
    await expect(page.getByRole("heading", { level: 1, name: "Overview" })).toBeVisible();
    await expect(signOutButton(page)).toHaveCount(0);
  });

  test("login not configured: says so, with no token field and no link", async ({ page, api }) => {
    api.set("GET /auth/config", { json: body.authConfigNone });
    await page.goto("/overview");
    await expect(page).toHaveURL(/\/signin$/);
    await expect(
      page.getByRole("heading", { level: 1, name: "Console login is not configured on this server" }),
    ).toBeVisible();
    await expect(page.getByText("docs/INSTALL.md")).toBeVisible();
    await expect(page.locator("input")).toHaveCount(0);
    await expect(signInLink(page)).toHaveCount(0);
    expect(api.calls.map((c) => c.key)).toEqual(["GET /auth/config"]);
    await expectNoViolations(page);
  });
});

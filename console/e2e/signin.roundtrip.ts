// Console sign-in end to end (ADR-018 option C, its Playwright test plan):
// the console served by kavach-api, signing in at the OIDC test double. The
// guard in stack.ts runs on every test: no CSP violation under the server's
// real policy, no request to another origin, the CSP on every console page.
import type { BrowserContext, Page } from "@playwright/test";
import { expectNoViolations } from "./axe";
import { tabTo } from "./keys";
import { IDP_GROUPS, IDP_USER } from "./roundtripStack";
import { expect, test } from "./stack";

const SESSION_COOKIE = "__Host-kavach_session";

const signInHeading = (page: Page) => page.getByRole("heading", { level: 1, name: "Sign in to Kavach" });
const signInLink = (page: Page) => page.getByRole("link", { name: "Sign in" });
const signOutButton = (page: Page) => page.getByRole("button", { name: "Sign out" });
const overviewHeading = (page: Page) => page.getByRole("heading", { level: 1, name: "Overview" });

/** Signed in: the header names the double's user. */
async function expectSignedIn(page: Page) {
  await expect(page).toHaveURL(/\/overview$/);
  await expect(overviewHeading(page)).toBeVisible();
  await expect(page.getByRole("banner")).toContainText(IDP_USER);
  await expect(signOutButton(page)).toBeVisible();
}

/** A signed-out page goes to /signin; its link goes to the IdP and back. */
async function signIn(page: Page) {
  await page.goto("/overview");
  await expect(page).toHaveURL(/\/signin$/);
  await signInLink(page).click();
  await expectSignedIn(page);
}

/** The context's cookies by name; values are never printed. */
async function cookieNames(context: BrowserContext): Promise<string[]> {
  return (await context.cookies()).map((cookie) => cookie.name).sort();
}

test("sign-in round trip through the IdP, and a reload keeps the session", async ({ page, guard }) => {
  await signIn(page);
  expect(guard.idpNavigations, "the sign-in went through the identity provider").toBeGreaterThan(0);

  await page.reload();
  await expectSignedIn(page);
  // The session is the server's: /auth/session answers for it.
  await page.goto("/settings");
  await expect(page.getByText(IDP_GROUPS.join(", "), { exact: true })).toBeVisible();
});

test("sign out, then Back does not restore a signed-in page", async ({ page, context }) => {
  await signIn(page);
  await page.goto("/settings");
  await expect(page.getByRole("heading", { level: 1, name: "Settings" })).toBeVisible();

  await signOutButton(page).click();
  await expect(page).toHaveURL(/\/signin$/);
  await expect(signInHeading(page)).toBeVisible();
  await expect(page.getByRole("status")).toHaveText("");
  expect(await cookieNames(context)).toEqual([]);

  await page.goBack();
  await expect(signInHeading(page)).toBeVisible();
  await expect(page.getByRole("heading", { level: 1, name: "Settings" })).toHaveCount(0);
  await expect(page.getByText(IDP_USER)).toHaveCount(0);

  // A fresh load of a signed-in page asks the server, which has no session.
  await page.goto("/settings");
  await expect(page).toHaveURL(/\/signin$/);
  await expect(signInHeading(page)).toBeVisible();
});

test("after sign-in, no token in browser storage; the session cookie is __Host-, Secure, HttpOnly, SameSite=Strict, Path=/", async ({
  page,
  context,
}) => {
  await signIn(page);

  const held = await page.evaluate(async () => ({
    local: Object.keys(localStorage),
    session: Object.keys(sessionStorage),
    databases: (await indexedDB.databases()).map((d) => d.name),
    cookie: document.cookie,
  }));
  expect(held).toEqual({ local: [], session: [], databases: [], cookie: "" });

  // The login cookie is gone; the session cookie is the only one.
  expect(await cookieNames(context)).toEqual([SESSION_COOKIE]);
  const cookie = (await context.cookies()).find((c) => c.name === SESSION_COOKIE);
  expect(cookie, "the session cookie").toBeDefined();
  if (!cookie) return;
  expect({
    secure: cookie.secure,
    httpOnly: cookie.httpOnly,
    sameSite: cookie.sameSite,
    path: cookie.path,
    // Host-only (no Domain attribute), as the __Host- prefix requires.
    domain: cookie.domain,
    // A browser-session cookie: no Max-Age or Expires.
    expires: cookie.expires,
  }).toEqual({
    secure: true,
    httpOnly: true,
    sameSite: "Strict",
    path: "/",
    domain: "127.0.0.1",
    expires: -1,
  });
  expect(cookie.value.length > 0, "the cookie has a value (not printed)").toBe(true);
});

test("every page under the server's CSP: no violation, and no request to another origin", async ({
  page,
  guard,
}) => {
  await signIn(page);
  for (const path of [
    "/overview",
    "/evaluate",
    "/agents",
    "/agent-evidence",
    "/reconciliation",
    "/decision-events",
    "/policies",
    "/models",
    "/batch",
    "/changes",
    "/audit",
    "/incidents",
    "/retention",
    "/settings",
  ]) {
    await page.goto(path);
    await expect(page, path).toHaveURL(new RegExp(`${path}$`));
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    await page.waitForLoadState("networkidle");
  }
  await signOutButton(page).click();
  await expect(signInHeading(page)).toBeVisible();
  await page.waitForLoadState("networkidle");

  // Checked again by the guard after every test; stated here as well.
  expect.soft(guard.consoleDocuments).toBeGreaterThanOrEqual(15);
  expect.soft(guard.withoutCsp).toEqual([]);
  expect.soft(guard.violations).toEqual([]);
  expect.soft(guard.otherOrigins).toEqual([]);
  expect.soft(guard.idpNavigations).toBeGreaterThan(0);
});

// The stand-in for an expired session. The session clock is the server's
// wall clock (ConsoleLogin's clock; the --insecure-dev dev clock does not move
// it), and the shortest idle limit is 5 minutes. So the session is ended on
// the server by a sign-out in a second tab, and the session cookie is put
// back in the browser: the first tab then holds a cookie for a session the
// server no longer has, which is what an expired session looks like to it.
test("an ended session sends the operator to /signin with the session-ended message", async ({
  page,
  context,
}) => {
  await signIn(page);
  const held = (await context.cookies()).filter((c) => c.name === SESSION_COOKIE);
  expect(held).toHaveLength(1);

  const other = await context.newPage();
  await other.goto("/overview");
  await expectSignedIn(other);
  await signOutButton(other).click();
  await expect(signInHeading(other)).toBeVisible();
  await other.close();
  await context.addCookies(held);

  // The first tab's next call is refused (401): the session has ended.
  await page.getByRole("link", { name: "Change requests" }).first().click();
  await expect(page).toHaveURL(/\/signin$/);
  await expect(page.getByRole("status")).toHaveText("Your session ended. Sign in again.");
  await expect(signInLink(page)).toBeVisible();
  await expectNoViolations(page);

  // Signing in again works from there.
  await signInLink(page).click();
  await expectSignedIn(page);
});

test("keyboard only: sign in and sign out; axe on the signed-out and signed-in pages", async ({ page }) => {
  await page.goto("/signin");
  await expect(signInHeading(page)).toBeVisible();
  await expectNoViolations(page);

  await tabTo(page, signInLink(page));
  await page.keyboard.press("Enter");
  await expectSignedIn(page);
  await page.waitForLoadState("networkidle");
  await expectNoViolations(page);

  await tabTo(page, signOutButton(page));
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/\/signin$/);
  await expect(signInHeading(page)).toBeVisible();
  await expectNoViolations(page);
});

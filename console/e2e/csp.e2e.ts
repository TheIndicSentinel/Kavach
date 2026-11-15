// The guard in e2e/page.ts checked against itself: the console's files come
// with the server's policy, and a violation is caught (so a clean run means
// something). e2e/api.ts also refuses any request to another origin that
// got past the policy.
import { SERVER_CSP, expect, serverCsp, test } from "./page";

test.describe("the server's Content-Security-Policy in the browser tests", () => {
  test("is read from console.rs with its line continuations joined", () => {
    expect(serverCsp('pub const CONTENT_SECURITY_POLICY: &str = "a \\\n     b";')).toBe("a b");
    expect(SERVER_CSP).toContain("default-src 'self'");
    expect(SERVER_CSP).toContain("script-src 'self'");
    expect(SERVER_CSP).toContain("style-src 'self'");
    expect(SERVER_CSP).not.toContain("\\");
  });

  test("comes with every page of the console", async ({ page }) => {
    for (const path of ["/overview", "/agents/agent:collections-bot", "/no-such-page"]) {
      const response = await page.goto(path);
      expect(response?.headers()["content-security-policy"]).toBe(SERVER_CSP);
    }
  });

  test("a violation is caught", async ({ page, csp }) => {
    await page.goto("/overview");
    await expect(page.getByRole("heading", { level: 1, name: "Overview" })).toBeVisible();
    await page.evaluate(() => {
      const script = document.createElement("script");
      script.textContent = "void 0";
      document.body.append(script);
    });
    await expect.poll(() => csp.violations).toEqual(["script-src-elem: inline"]);
    // Seen: this test planted it, so it is not a finding.
    csp.violations.length = 0;
  });

  test("a request to another origin is stopped by the policy before it leaves", async ({ page, api, csp }) => {
    await page.goto("/overview");
    await expect(page.getByRole("heading", { level: 1, name: "Overview" })).toBeVisible();
    await page.evaluate(() => fetch("https://example.invalid/x").catch(() => undefined));
    await expect.poll(() => csp.violations).toEqual(["connect-src: https://example.invalid/x"]);
    expect(api.unexpected).toEqual([]); // it never reached the network
    // Seen: this test made it, so it is not a finding.
    csp.violations.length = 0;
  });
});

// The browser-test fixture every spec uses: e2e/api.ts's stubbed API, plus the
// headers the Kavach server sends with the console and a listener that fails
// the test on any Content-Security-Policy violation.
//
// vite preview sends no CSP at all, so without this a page that breaks the
// server's policy (an inline script or style) would pass here and fail when
// served by kavach-api. The policy is read from crates/kavach-api/src/console.rs
// at run time, so the two cannot drift; the headers are added to the console's
// own files only, as the server adds them.
import { readFileSync } from "node:fs";
import { API_PREFIXES, expect, test as apiTest } from "./api";

const CONSOLE_RS = new URL("../../crates/kavach-api/src/console.rs", import.meta.url);

/** The server's `CONTENT_SECURITY_POLICY`, with Rust's `\` line continuations joined. */
export function serverCsp(source = readFileSync(CONSOLE_RS, "utf8")): string {
  const match = source.match(/pub const CONTENT_SECURITY_POLICY: &str = "((?:[^"\\]|\\\n\s*)*)";/);
  if (!match) throw new Error("CONTENT_SECURITY_POLICY not found in crates/kavach-api/src/console.rs");
  return match[1].replace(/\\\n\s*/g, "");
}

export const SERVER_CSP = serverCsp();

/** The other headers console.rs sends that change what a browser does. */
const SERVER_HEADERS = {
  "content-security-policy": SERVER_CSP,
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
};

export type CspGuard = {
  /** Every violation reported in this test, in any document, as `directive: blocked`. */
  violations: string[];
};

export const test = apiTest.extend<{ csp: CspGuard }>({
  csp: [
    // Depends on `api` so this route is registered after the stub's and runs first.
    async ({ page, api, baseURL }, provide) => {
      void api;
      const origin = new URL(baseURL ?? "").origin;
      const guard: CspGuard = { violations: [] };

      await page.exposeFunction("__kavachCspViolation", (found: string) => {
        guard.violations.push(found);
      });
      await page.addInitScript(() => {
        document.addEventListener("securitypolicyviolation", (event) => {
          const report = (window as unknown as { __kavachCspViolation: (v: string) => void })
            .__kavachCspViolation;
          void report(`${event.effectiveDirective}: ${event.blockedURI || "inline"}`);
        });
      });

      await page.route("**/*", async (route) => {
        const url = new URL(route.request().url());
        if (url.origin !== origin || API_PREFIXES.some((prefix) => url.pathname.startsWith(prefix))) {
          await route.fallback(); // the API stub answers, or refuses another origin
          return;
        }
        try {
          const response = await route.fetch();
          await route.fulfill({ response, headers: { ...response.headers(), ...SERVER_HEADERS } });
        } catch (error) {
          // A navigation that starts while a file of the previous document is
          // still loading disposes that fetch. The document it was for is gone,
          // so there is nothing left to guard: drop the request. Anything else
          // still fails the test.
          if (!/has been disposed/.test(String(error))) throw error;
          await route.abort().catch(() => undefined);
        }
      });

      await provide(guard);
      expect(guard.violations, "Content-Security-Policy violations under the server's policy").toEqual([]);
    },
    { auto: true },
  ],
});

export { expect };

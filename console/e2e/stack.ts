// The fixture every round-trip spec uses (playwright.roundtrip.config.ts).
// Nothing is stubbed and no header is injected: the pages, their CSP and the
// cookies are what kavach-api sends. For every page in the test's browser
// context (every tab), the guard fails the test on:
// - a `securitypolicyviolation` event, under the server's real CSP;
// - a console document served without the server's CSP;
// - any request to an origin other than the console's. The one exception is a
//   top-level navigation to the identity provider (the sign-in redirect).
import { expect, test as base } from "@playwright/test";
import { serverCsp } from "./page";
import { CONSOLE_ORIGIN, IDP_ORIGIN } from "./roundtripStack";

/** console.rs's CONTENT_SECURITY_POLICY: the header every console document must carry. */
const SERVER_CSP = serverCsp();

export type StackGuard = {
  /** CSP violations, as `directive: blocked`. */
  violations: string[];
  /** Requests to another origin, as `METHOD origin/path (resource type)`; the query is left out. */
  otherOrigins: string[];
  /** Top-level navigations to the identity provider. */
  idpNavigations: number;
  /** Console documents (200, HTML) served, and those without the server's CSP. */
  consoleDocuments: number;
  withoutCsp: string[];
};

export const test = base.extend<{ guard: StackGuard }>({
  guard: [
    async ({ context }, provide) => {
      const guard: StackGuard = {
        violations: [],
        otherOrigins: [],
        idpNavigations: 0,
        consoleDocuments: 0,
        withoutCsp: [],
      };

      await context.exposeBinding("__kavachCspViolation", (_source, found: string) => {
        guard.violations.push(found);
      });
      await context.addInitScript(() => {
        document.addEventListener("securitypolicyviolation", (event) => {
          const report = (window as unknown as { __kavachCspViolation: (v: string) => void })
            .__kavachCspViolation;
          void report(`${event.effectiveDirective}: ${event.blockedURI || "inline"}`);
        });
      });

      context.on("request", (request) => {
        const url = new URL(request.url());
        // A data: image (img-src allows it) is not a request to any origin.
        if (url.protocol === "data:") return;
        if (url.origin === CONSOLE_ORIGIN) return;
        if (url.origin === IDP_ORIGIN && request.isNavigationRequest() && !request.frame().parentFrame()) {
          guard.idpNavigations += 1;
          return;
        }
        guard.otherOrigins.push(`${request.method()} ${url.origin}${url.pathname} (${request.resourceType()})`);
      });

      context.on("response", (response) => {
        if (response.request().resourceType() !== "document" || response.status() !== 200) return;
        const url = new URL(response.url());
        if (url.origin !== CONSOLE_ORIGIN) return;
        guard.consoleDocuments += 1;
        if (response.headers()["content-security-policy"] !== SERVER_CSP) guard.withoutCsp.push(url.pathname);
      });

      await provide(guard);

      // Soft: each check reports, whichever fails first.
      expect.soft(guard.violations, "Content-Security-Policy violations under the server's policy").toEqual([]);
      expect.soft(guard.otherOrigins, "requests to an origin other than the console's").toEqual([]);
      expect.soft(guard.withoutCsp, "console documents without the server's CSP").toEqual([]);
    },
    { auto: true },
  ],
});

export { expect };

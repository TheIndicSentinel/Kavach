// The console on a stack that scripts/demo.sh started: every demo user signs
// in through the OIDC test double's "Sign in as" page and opens every page.
// It starts nothing; run `scripts/demo.sh` first, then in console/:
//   npm run test:demo
// CI runs it against demo.sh started from a fresh clone (ci.yml).
import { defineConfig, devices } from "@playwright/test";

declare const process: { env: Record<string, string | undefined> };

/** As in playwright.config.ts: `chrome` where Playwright has no Chromium build (macOS 12). */
const CHANNEL = process.env.KAVACH_E2E_CHANNEL || undefined;

/** demo.sh's addresses (scripts/demo.sh). */
const ORIGIN = "http://127.0.0.1:8080";
const IDP_ORIGIN = "http://127.0.0.1:9400";

// `idpOrigin` is the guard's option (e2e/stack.ts).
export default defineConfig<{ idpOrigin: string }>({
  testDir: "e2e",
  testMatch: "**/*.demo.ts",
  outputDir: "test-results/demo",
  fullyParallel: false,
  workers: 1,
  forbidOnly: true,
  retries: 0,
  reporter: [["list"]],
  use: {
    ...devices["Desktop Chrome"],
    channel: CHANNEL,
    baseURL: ORIGIN,
    idpOrigin: IDP_ORIGIN,
    trace: "off",
    screenshot: "off",
    video: "off",
  },
});

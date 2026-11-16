// Browser tests: accessibility (axe, WCAG 2.2 AA tags) and keyboard checks
// against the built console in `vite preview`. Every API call is stubbed in
// e2e/api.ts; no backend runs and nothing leaves the machine.
import { defineConfig, devices } from "@playwright/test";

// Node's `process`, declared here: the console installs no Node type package.
declare const process: { env: Record<string, string | undefined> };

const PORT = 4173;

/**
 * Set to `chrome` to run the installed Google Chrome instead of Playwright's
 * Chromium, where Playwright has no Chromium build for the OS (macOS 12).
 * Unset (CI), the bundled Chromium from `npx playwright install chromium` runs.
 */
const CHANNEL = process.env.KAVACH_E2E_CHANNEL || undefined;
const OUT_DIR = ".e2e-dist"; // not dist/: kavach-api embeds dist/ when it exists

export default defineConfig({
  testDir: "e2e",
  testMatch: "**/*.e2e.ts",
  outputDir: "test-results",
  fullyParallel: true,
  forbidOnly: true,
  retries: 0,
  reporter: [["list"]],
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    trace: "off",
    screenshot: "off",
    video: "off",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"], channel: CHANNEL } }],
  webServer: {
    command: `vite build --outDir ${OUT_DIR} --emptyOutDir --logLevel warn && vite preview --outDir ${OUT_DIR} --host 127.0.0.1 --port ${PORT} --strictPort`,
    url: `http://127.0.0.1:${PORT}`,
    reuseExistingServer: false,
    timeout: 120_000,
  },
});

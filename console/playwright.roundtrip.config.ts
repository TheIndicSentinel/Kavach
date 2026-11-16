// The real sign-in round trip (ADR-018 option C): the console as kavach-api
// serves it, signing in through the OIDC test double. Nothing is stubbed and
// no header is injected: the console, its CSP and its cookies come from the
// server. Specs match `*.roundtrip.ts`; the stubbed suite (playwright.config.ts)
// is separate and unchanged.
//
// Build first (from the repository root):
//   (cd console && npm run build)   # kavach-api embeds console/dist at build time
//   cargo build -p kavach-api --bin kavach-api --example oidc_double
// then, in console/: `npm run test:roundtrip`.
//
// Both processes listen on 127.0.0.1 only, keep everything in memory (the
// evidence store is `memory`) and stop with the run. Nothing leaves the machine.
import { defineConfig, devices } from "@playwright/test";
import {
  API_PORT,
  CONSOLE_ORIGIN,
  GRPC_PORT,
  IDP_GROUPS,
  IDP_ORIGIN,
  IDP_PORT,
  IDP_USER,
} from "./e2e/roundtripStack";

// Node's `process`, declared here: the console installs no Node type package.
declare const process: { env: Record<string, string | undefined> };

/** As in playwright.config.ts: `chrome` where Playwright has no Chromium build (macOS 12). */
const CHANNEL = process.env.KAVACH_E2E_CHANNEL || undefined;

/** Where cargo put the binaries (CARGO_TARGET_DIR when it is set). */
const BIN = `${process.env.CARGO_TARGET_DIR || "../target"}/debug`;

/**
 * The client secret and the JWKS the double writes, owner-only, new each run
 * (the double writes a random secret when the file does not exist).
 */
const STACK = ".roundtrip-stack";

const repo = (path: string) => `../${path}`;

const double = [
  `${BIN}/examples/oidc_double`,
  `--listen 127.0.0.1:${IDP_PORT}`,
  `--client-secret-file ${STACK}/console.secret`,
  `--jwks-out ${STACK}/jwks.json`,
  `--sub ${IDP_USER}`,
  `--groups ${IDP_GROUPS.join(",")}`,
].join(" ");

// The flags the double prints, plus the rest of a minimal server: the finance
// pack and model, Cedar with the example entities, memory evidence.
const api = [
  `${BIN}/kavach-api`,
  `--listen 127.0.0.1:${API_PORT}`,
  `--grpc-listen 127.0.0.1:${GRPC_PORT}`,
  `--pack ${repo("packs/finance/v0.yaml")}`,
  `--model ${repo("models/finance/credit-underwriting-v1.yaml")}`,
  "--evidence-store memory",
  "--access-control cedar",
  `--cedar-policy ${repo("crates/kavach-auth/policies/kavach.cedar")}`,
  `--cedar-entities ${repo("crates/kavach-auth/policies/entities.example.json")}`,
  "--insecure-dev",
  `--oidc-issuer ${IDP_ORIGIN}`,
  "--oidc-audience kavach-api",
  `--oidc-jwks-file ${STACK}/jwks.json`,
  "--console-client-id kavach-console",
  `--console-client-secret-file ${STACK}/console.secret`,
  `--console-redirect-uri ${CONSOLE_ORIGIN}/auth/callback`,
].join(" ");

export default defineConfig({
  testDir: "e2e",
  testMatch: "**/*.roundtrip.ts",
  outputDir: "test-results/roundtrip",
  // One server and one IdP user: run the specs one at a time, in order.
  fullyParallel: false,
  workers: 1,
  forbidOnly: true,
  retries: 0,
  reporter: [["list"]],
  use: {
    baseURL: CONSOLE_ORIGIN,
    trace: "off",
    screenshot: "off",
    video: "off",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"], channel: CHANNEL } }],
  // Started in order: kavach-api reads the double's JWKS and discovery at startup.
  webServer: [
    {
      command: `rm -rf ${STACK} && mkdir -m 700 ${STACK} && exec ${double}`,
      url: `${IDP_ORIGIN}/.well-known/openid-configuration`,
      reuseExistingServer: false,
      timeout: 30_000,
    },
    {
      command: `exec ${api}`,
      url: `${CONSOLE_ORIGIN}/auth/config`,
      reuseExistingServer: false,
      timeout: 60_000,
    },
  ],
});

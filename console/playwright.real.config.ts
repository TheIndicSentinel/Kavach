// The console against a real, seeded stack: every page and action, signed
// in through the OIDC test double, on a full kavach-api and on an
// `--agent-only` one. Nothing is stubbed and no header is injected.
//
// The stack, started in order:
// 1. `kavach-dev generate` writes a dev bundle whose tokens name the double
//    as issuer; then the OIDC double starts, publishing the bundle's IdP
//    key next to its own in the JWKS file kavach-api reads (--also-trust).
// 2. The mock provider, with the bundle's TLS and credential keys.
// 3. kavach-api with the bundle's kavach.env (mandates, the signed tool
//    registry, consents, providers), memory evidence, Cedar, console login,
//    and its SoR and agent listeners.
// 4. The same, with --agent-only.
// realSetup.ts then issues a mandate on each and makes agent calls on it.
//
// Build first (from the repository root):
//   (cd console && npm run build)   # kavach-api embeds console/dist at build time
//   cargo build -p kavach-api --bin kavach-api --example oidc_double \
//     -p kavach-devkit --bin kavach-dev -p kavach-mock-provider --bin kavach-mock-provider
// then, in console/: `npm run test:real`.
//
// Everything listens on 127.0.0.1, keeps evidence in memory, and stops with
// the run. Nothing leaves the machine.
import { defineConfig, devices } from "@playwright/test";
import {
  ADMIN,
  AGENT_ONLY,
  BUNDLE,
  FULL,
  IDP_ORIGIN,
  IDP_PORT,
  type Instance,
  PROVIDER_INSPECT_PORT,
  PROVIDER_PORT,
  STACK,
} from "./e2e/realStack";

// Node's `process`, declared here: the console installs no Node type package.
declare const process: { env: Record<string, string | undefined> };

/** As in playwright.config.ts: `chrome` where Playwright has no Chromium build (macOS 12). */
const CHANNEL = process.env.KAVACH_E2E_CHANNEL || undefined;

/** Where cargo put the binaries (CARGO_TARGET_DIR when it is set). */
const BIN = `${process.env.CARGO_TARGET_DIR || "../target"}/debug`;

const repo = (path: string) => `../${path}`;

const bundle = [
  `${BIN}/kavach-dev generate`,
  `--out ${BUNDLE}`,
  `--kavach-mount ${BUNDLE}/kavach`,
  `--provider-endpoint https://localhost:${PROVIDER_PORT}`,
  "--provider-host localhost",
  "--provider-host 127.0.0.1",
  "--database-host localhost",
  `--issuer ${IDP_ORIGIN}`,
  "--token-hours 2",
].join(" ");

const double = [
  `${BIN}/examples/oidc_double`,
  `--listen 127.0.0.1:${IDP_PORT}`,
  `--client-secret-file ${STACK}/console.secret`,
  `--jwks-out ${STACK}/jwks.json`,
  `--also-trust ${BUNDLE}/kavach/jwks.json`,
  `--sub ${ADMIN.sub}`,
  `--groups ${ADMIN.groups.join(",")}`,
  "--users e2e/real-users.json",
].join(" ");

const provider = [
  `${BIN}/kavach-mock-provider serve`,
  `--listen 127.0.0.1:${PROVIDER_PORT}`,
  `--inspect-listen 127.0.0.1:${PROVIDER_INSPECT_PORT}`,
  `--encryption-key ${BUNDLE}/provider/encryption.key`,
  "--encryption-kid dev-provider-enc-1",
  `--credential-keys ${BUNDLE}/provider/credential-keys.json`,
  `--tls-cert ${BUNDLE}/provider/tls.pem`,
  `--tls-key ${BUNDLE}/provider/tls-key.pem`,
].join(" ");

/**
 * kavach-api with the bundle's environment (issuer, audiences, keys,
 * registry, consents, providers), and the double's JWKS file, which also
 * holds the bundle's IdP key.
 */
function api(instance: Instance, extra: string[] = []): string {
  const flags = [
    `${BIN}/kavach-api`,
    `--listen 127.0.0.1:${instance.listen}`,
    `--grpc-listen 127.0.0.1:${instance.grpc}`,
    `--sor-listen 127.0.0.1:${instance.sor}`,
    `--agent-listen 127.0.0.1:${instance.agent}`,
    `--pack ${repo("packs/finance/v0.yaml")}`,
    `--model ${repo("models/finance/credit-underwriting-v1.yaml")}`,
    "--evidence-store memory",
    "--access-control cedar",
    `--cedar-policy ${repo("crates/kavach-auth/policies/kavach.cedar")}`,
    `--cedar-entities ${repo("crates/kavach-auth/policies/entities.example.json")}`,
    "--insecure-dev",
    `--oidc-jwks-file ${STACK}/jwks.json`,
    "--console-client-id kavach-console",
    `--console-client-secret-file ${STACK}/console.secret`,
    `--console-redirect-uri ${instance.origin}/auth/callback`,
    ...extra,
  ].join(" ");
  return `set -a && . ./${BUNDLE}/kavach/kavach.env && set +a && exec ${flags}`;
}

// `idpOrigin` is the guard's option (e2e/stack.ts).
export default defineConfig<{ idpOrigin: string }>({
  testDir: "e2e",
  outputDir: "test-results/real",
  globalSetup: "./e2e/realSetup.ts",
  // One stack, shared state (stops, change requests): one test at a time, in order.
  fullyParallel: false,
  workers: 1,
  forbidOnly: true,
  retries: 0,
  reporter: [["list"]],
  use: {
    trace: "off",
    screenshot: "off",
    video: "off",
    idpOrigin: IDP_ORIGIN,
  },
  projects: [
    {
      name: "full",
      testMatch: "**/full.real.ts",
      use: { ...devices["Desktop Chrome"], channel: CHANNEL, baseURL: FULL.origin },
    },
    {
      name: "agent-only",
      testMatch: "**/agent-only.real.ts",
      use: { ...devices["Desktop Chrome"], channel: CHANNEL, baseURL: AGENT_ONLY.origin },
    },
  ],
  webServer: [
    {
      command: `rm -rf ${STACK} && mkdir -m 700 ${STACK} && ${bundle} >/dev/null && exec ${double}`,
      url: `${IDP_ORIGIN}/.well-known/openid-configuration`,
      reuseExistingServer: false,
      timeout: 30_000,
    },
    {
      command: `exec ${provider}`,
      url: `http://127.0.0.1:${PROVIDER_INSPECT_PORT}/v1/inbox`,
      reuseExistingServer: false,
      timeout: 30_000,
    },
    {
      command: api(FULL),
      url: `${FULL.origin}/auth/config`,
      reuseExistingServer: false,
      timeout: 60_000,
    },
    {
      command: api(AGENT_ONLY, ["--agent-only"]),
      url: `${AGENT_ONLY.origin}/auth/config`,
      reuseExistingServer: false,
      timeout: 60_000,
    },
  ],
});

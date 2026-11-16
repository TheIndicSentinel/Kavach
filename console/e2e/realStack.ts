// The real stack's addresses and users, shared by playwright.real.config.ts
// (which starts it), realSetup.ts (which seeds it) and the *.real.ts specs.
// Loopback only. The ports differ from the round-trip stack's, so neither
// run can pick up the other's servers.

/** The OIDC test double, signing in the users of e2e/real-users.json. */
export const IDP_PORT = 4290;
export const IDP_ORIGIN = `http://127.0.0.1:${IDP_PORT}`;

/** A kavach-api instance: the operator listener (console, /auth/*, API) and its other listeners. */
export type Instance = {
  name: "full" | "agent-only";
  origin: string;
  listen: number;
  grpc: number;
  sor: number;
  agent: number;
};

/** The whole API: the credit track and the agent path. */
export const FULL: Instance = {
  name: "full",
  origin: "http://127.0.0.1:4280",
  listen: 4280,
  grpc: 4281,
  sor: 4282,
  agent: 4283,
};

/** `--agent-only`: the agent path alone, as a hosted build runs it. */
export const AGENT_ONLY: Instance = {
  name: "agent-only",
  origin: "http://127.0.0.1:4284",
  listen: 4284,
  grpc: 4285,
  sor: 4286,
  agent: 4287,
};

/** The mock provider the gateway delivers to (HTTPS, the bundle's dev CA) and its inbox listener. */
export const PROVIDER_PORT = 4288;
export const PROVIDER_INSPECT_PORT = 4289;

/** Owner-only, new each run: the bundle, the client secret, the JWKS. */
export const STACK = ".real-stack";
export const BUNDLE = `${STACK}/bundle`;

/**
 * Who signs in (e2e/real-users.json; the double's `--sub` is ADMIN). Cedar
 * (crates/kavach-auth/policies/kavach.cedar) gives admins every proposal,
 * stop and read; change-approvers approve; viewers read governance only.
 */
export const ADMIN = { sub: "real-admin", groups: ["admins"] } as const;
export const APPROVER = { sub: "real-approver", groups: ["change-approvers"] } as const;
export const VIEWER = { sub: "real-viewer", groups: ["viewers"] } as const;
export type RealUser = typeof ADMIN | typeof APPROVER | typeof VIEWER;

/** The double's cookie that names who signs in (tests/support/oidc_double.rs USER_COOKIE). */
export const USER_COOKIE = "oidc_double_user";

/** The dev bundle's agents and borrower (crates/kavach-devkit). */
export const AGENT = "collections-agent";
export const OTHER_AGENT = "translation-agent";
export const SUBJECT = "ref:borrower:B-9382";

// The round-trip stack's addresses and user, shared by
// playwright.roundtrip.config.ts (which starts it) and the specs. Loopback
// only: the OIDC double refuses any other address.

/** kavach-api's HTTP listener: the console, /auth/* and the API on one origin. */
export const API_PORT = 4180;
/** kavach-api's gRPC listener (unused here, but kept off its 0.0.0.0 default). */
export const GRPC_PORT = 4181;
/** The OIDC test double (crates/kavach-api/examples/oidc_double.rs). */
export const IDP_PORT = 4190;

/**
 * The console's origin. It must be exactly the origin of
 * `--console-redirect-uri`: the server refuses a cookie request whose
 * `Origin` is anything else, so `localhost` would not do.
 */
export const CONSOLE_ORIGIN = `http://127.0.0.1:${API_PORT}`;
export const IDP_ORIGIN = `http://127.0.0.1:${IDP_PORT}`;

/** The one user the double signs in, and the token's groups. */
export const IDP_USER = "roundtrip-admin";
export const IDP_GROUPS = ["admins"];

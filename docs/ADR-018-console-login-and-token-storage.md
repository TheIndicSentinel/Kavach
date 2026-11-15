# ADR-018: Console Login (OIDC Authorization Code with PKCE) and Where Operator Tokens Live

**Status:** Accepted (2026-11-14). Option C, with the owner's answers to the open questions (see "Decisions on the open questions"). **Backend implemented on this branch, pending merge** (`feat/console-login-backend`, on top of roadmap 1.3); the console's sign-in screen is separate work. It is a second-review area (a client credential and session tokens; see SECOND_REVIEW.md).  
**Date:** 2026-11-14  
**Deciders:** Kavach product/engineering (owner decision, 2026-11-14)  
**Related:** ADR-008 (API authentication; it deferred console login to this ADR), ADR-009 (change requests), ADR-013 (kill switch), ADR-014 (tenancy), [CONSOLE_PLAN.md](CONSOLE_PLAN.md) UI-4, [SECURITY_PROPERTIES.md](SECURITY_PROPERTIES.md), [THREAT_MODEL.md](THREAT_MODEL.md)

**Scope.** This ADR is the console's login design, and it is also **roadmap item 1.4, "the token ADR"**: it settles where operator tokens live, how long they live, how they are refreshed and how a session ends. The other half of 1.4, the console's Content-Security-Policy and security headers, landed in pull request #224 (merged as `d2627a2`; see Context, "Headers"); this ADR states only the constraints the login puts on that policy. Agent tokens, system-of-record keys and the CLI's bearer tokens are out of scope and do not change.

## Context

What the code does today (read at `d2627a2`):

- **The API reads one credential header.** `crates/kavach-api/src/auth.rs` resolves the principal from `Authorization: Bearer`, then the mTLS SAN, then `X-Kavach-Principal` with `--insecure-dev` only (`resolve_principal`, `resolve_credentials`). It reads no cookie. Every operator route is then authorised by Cedar on that principal (`authorize_principal`). Because no ambient credential is accepted, the API has no cross-site request forgery (CSRF) surface today.
- **Token verification is local.** `crates/kavach-api/src/oidc.rs` checks the signature against the configured JWKS (`kid` required, RS256, PS256, ES256 or EdDSA only), `iss`, `aud`, `exp` and `nbf` with a leeway, and reads the principal and groups claims. It does not check the JWT `typ` header and does not call an introspection or revocation endpoint. A token stays valid until `exp` plus the leeway (SECURITY_PROPERTIES.md, "Token revocation before expiry").
- **Approvals need a token identity.** An approval is accepted only from a principal authenticated by an OIDC token, compared by the source-qualified key `oidc:<issuer>#<subject>` (`AuthenticatedPrincipal::identity_key` in `auth.rs`; `crates/kavach-api/src/state_changes.rs`; ADR-009). Whatever the console does must keep producing that identity.
- **The console stores a pasted token.** `console/src/lib/api.ts` keeps the token in `sessionStorage` under `kavach.accessToken` (and a development principal under `kavach.principal`) and sends it as `Authorization: Bearer` on every call. `console/src/pages/SettingsPage.tsx` is the paste field. There is no login, refresh or logout. The owner's decision of 2026-11-14 keeps this, under a strict CSP, until this work.
- **Headers.** Since #224, the console page and its files carry four headers from `security_headers` in `crates/kavach-api/src/console.rs`: `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'` (`CONTENT_SECURITY_POLICY`), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, and a `Cache-Control` chosen per file by `cache_control_for`: `no-store` for `index.html`, every single-page route and the "not built" page; `public, max-age=31536000, immutable` for hashed files under `assets/`; `no-cache` for other files such as `favicon.svg`. They are set only there (`console_response`), not on API routes or on the problem responses the fallback returns for `/v1/...` paths and missing files. The API sets no CORS headers, so the browser refuses cross-origin calls to it.
- **Same origin.** The console is served by `kavach-api` on the operator listener as the router's fallback (`crates/kavach-api/src/http.rs`, `console::fallback`), in both the full and the agent-only mode, so the console and the API share one origin. The fallback answers only `GET` and `HEAD`; `/v1/...` paths and missing files stay problem responses, never the console page.
- **Deployment.** Kavach runs as a single instance for now; high availability is an open decision.

Why change: a pasted token is readable by any script on the origin (`sessionStorage` is open to JavaScript), it pushes operators to copy bearer tokens through the clipboard and chat, and the documented way to get one (`docs/INSTALL.md`, Keycloak `client_credentials`) yields a service account, not a person. Approvals need a person.

## Options considered

| | A. Pasted token (today) | B. Browser public client: code + PKCE, tokens in memory | C. Backend for frontend (BFF) in `kavach-api`: code + PKCE, HttpOnly session cookie |
|---|---|---|---|
| Where tokens live | `sessionStorage`, in the tab, until the tab closes | JavaScript memory; lost on reload | Server memory only; the browser holds an opaque session id in an HttpOnly cookie |
| A script injected into the page (XSS, or a compromised npm dependency bundled as `'self'`) can | read the token and send it anywhere a top-level navigation can reach | read the token from memory, and start a fresh authorization flow while the IdP session lasts | send requests through the session while the page is open ("session riding"); it cannot read a token, so it cannot keep using one after the page closes |
| CSRF | none (header credential) | none (header credential) | **new**: the API accepts an ambient cookie, so every state-changing route needs a defence |
| CSP needs | `connect-src 'self'` | `connect-src` must add the IdP's token endpoint (per deployment, so the header is built from configuration); silent renewal in an iframe needs `frame-src` for the IdP and the IdP's consent to be framed | unchanged: `connect-src 'self'`, `frame-ancestors 'none'`; login and logout must be top-level navigations, not form posts (see Decision 7) |
| Refresh | none | a refresh token in the browser (needs rotation at the IdP and is the most valuable thing to steal), or none, with silent renewal that third-party cookie blocking often breaks | held by the server, never sent to the browser |
| IdP requirements | none; the operator gets a token elsewhere | a public client, PKCE `S256`, CORS on the token endpoint; some organisations do not allow public clients for internal tools | a confidential client with PKCE, an exact redirect URI; end-session and revocation endpoints are optional |
| New server state | none | none | a bounded in-memory session table; sessions end on restart and are not shared between replicas |
| New secrets on the server | none | none | the client credential (a client secret in an owner-only file; see decision 4) |
| API change | none | a public configuration endpoint, a CSP built from configuration, startup checks | login, callback, logout and session routes; a cookie-to-token step before the existing verification; CSRF checks; startup checks |
| Agent-only mode | works (the console is served in both modes since #224) | same | same; the routes are on the operator listener only |
| Logout | clear the field | drop memory; optionally end the IdP session | delete the session server-side, revoke the refresh token if the IdP supports it, clear the cookie; optionally end the IdP session |

The cookie variant that puts the encrypted tokens *in* the cookie (no server table) was set aside: tokens with a groups claim can exceed cookie size limits, it needs a new encryption key, and a server cannot end such a session before it expires without keeping a deny list, which is server state again.

Both B and C use the authorization code flow with PKCE. They differ in who holds the tokens.

## Decision

**Option C: a backend for frontend inside `kavach-api`, as a confidential OIDC client using the authorization code flow with PKCE. Tokens stay on the server; the browser holds only an HttpOnly session cookie. Every API call still goes through the existing token verification and Cedar.**

Why C over B: the console is used by the people who can stop agents, approve reinstatements and read evidence. With B, a script that gets into the page can take a token away and use it after the page is closed; with C it can act only while the page is open, through the same Cedar checks, and leaves the same audit trail. C also keeps `connect-src 'self'`, keeps refresh tokens out of the browser and needs no CORS at the IdP. It matches the owner's earlier direction ("HttpOnly cookie later"). The cost is real and is accepted knowingly: a CSRF surface the API does not have today, server-side session state, and a client credential to protect. The owner chose C over B on 2026-11-14 (decision 1).

### 1. Login

1. `GET /auth/login` (operator listener) creates a short-lived login record server-side: `state`, `nonce` and the PKCE `code_verifier` (random, `S256`), keyed by a random id in a `__Host-kavach_login` cookie (HttpOnly, Secure, SameSite=Lax because the IdP redirects back cross-site, Path=/, at most 10 minutes, single use). It redirects to the IdP's authorization endpoint with `response_type=code`, `scope=openid` plus what the groups claim needs, `code_challenge`, `state`, `nonce` and the exact registered `redirect_uri`.
2. `GET /auth/callback` refuses anything without a matching, unused login record (wrong `state`, replay, expired). It exchanges the code with the `code_verifier` and the client credential at the token endpoint, server to server.
3. It verifies the ID token (signature from the same JWKS, `iss`, `aud` equal to the console client id, `nonce`) and then **verifies the access token with the existing `OidcVerifier`** (operator audience, groups claim). A token the API would refuse never creates a session.
4. It creates a new session with a fresh 256-bit random id (never reusing a pre-login id), sets `__Host-kavach_session` (HttpOnly, Secure, **SameSite=Strict**, Path=/, no `Domain`, no `Max-Age` beyond the absolute session limit) and answers `303` to `/`, so the code leaves the address bar and history. Some browsers treat that first page load as cross-site and do not send a Strict cookie with it; this does not matter, because `index.html` is static and the console reads the session with a same-origin `fetch`.

### 2. Each request

A step on the operator listener only, before `resolve_credentials`: a request with the session cookie and no `Authorization` header has the session's access token put in front of the existing code path. Nothing after it changes: `verify_token` runs on that token each time, Cedar decides, and the identity is `oidc:<issuer>#<subject>`, the same key the CLI gets with a token from the same IdP. So maker-checker still compares people correctly. The agent and system-of-record listeners never read the cookie.

Refused, before verification: a cookie together with an `Authorization` header or `X-Kavach-Principal` (400, as today for header plus token); a cookie-authenticated request without the console's custom request header (for example `X-Kavach-Console: 1`); and one whose `Origin` (or `Sec-Fetch-Site`) is not the console's own origin. A cross-site page cannot add a custom header without a CORS preflight, and the API grants no CORS. SameSite=Strict is the second layer, not the only one.

### 3. Token storage and lifetime

- **Access and ID tokens and any refresh token:** server memory only, in the session entry, in a type that never prints and is cleared on drop (as `TokenSecret` in `crates/kavach-ports/src/credential.rs`). Never written to Postgres, a file or a log; never sent to the browser in a body, header or URL. The log redactor already masks JOSE tokens and `Bearer` values (SECURITY_PROPERTIES.md, logs row); that is a backstop, not the control.
- **Browser:** the opaque session id in an HttpOnly cookie. The console keeps the display name and expiry from `GET /auth/session` in memory. `kavach.accessToken` and `kavach.principal` are removed from `sessionStorage` (and cleared once on first load after the upgrade). The one exception is the development fallback of decision 6: the pasted-token field, and its `sessionStorage` entry, remain only when console login is not configured and the server runs with `--insecure-dev`.
- **Access token lifetime:** set at the IdP; this ADR recommends 5 to 10 minutes, because the API cannot revoke one before `exp`. Nothing in Kavach enforces it; the deployment guide will say so.
- **Session lifetime (settings, decision 2):** an idle limit, default 15 minutes, allowed from 5 to 60 minutes; and an absolute limit, default 8 hours, at most 12 hours. Startup refuses a value outside those bounds (Decision 6.2). Refreshing never extends the absolute limit.
- **Refresh (decision 5):** if the IdP issued a refresh token, the server refreshes shortly before the access token expires, one refresh at a time per session, and takes a rotated refresh token when the IdP sends one. A refresh never extends the absolute limit. No `offline_access` scope is requested. If refresh fails, or there is no refresh token, the session ends and the console asks the operator to sign in again.
- **Bounds:** the session table has a fixed maximum (for example 1,000). When it is full a new login is refused with a clear error; existing sessions are never evicted (decision 7). Sessions end on restart, and with more than one replica each holds its own: a load balancer needs affinity, or the operator signs in again (decision 8). Kavach stays a single instance; HA is still undecided.

### 4. Logout

`POST /auth/logout` (custom header and same-origin checks as above): delete the session and clear its tokens from memory, revoke the refresh token at the IdP when it offers a revocation endpoint (RFC 7009), and expire both cookies. **By default that is all: logout ends the Kavach session only**, and the person stays signed in at the IdP and in its other applications (decision 3).

Ending the IdP session as well is an **opt-in setting, off by default**. Only when it is on does the response tell the console to navigate to the IdP's end-session endpoint (OpenID Connect RP-Initiated Logout), with `client_id` and `post_logout_redirect_uri` and **not** `id_token_hint`, so no token is put in a URL. With the setting off, the response carries no end-session URL.

An access token that was issued stays valid at the API until `exp`, as today. After logout nothing holds it: it was never in the browser.

### 5. What stays the gate

The API authorises every `/v1` call with Cedar on the verified principal, whatever carried the token. The console's role-aware views (UI-4) only hide or disable what the principal probably cannot do, using the groups from `GET /auth/session` as hints; they are not a control, and a hidden action sent by hand still gets the API's 403. The `/auth/*` routes grant nothing: they create, show or end a session for a token the existing verifier accepts.

### 6. What the API must change

1. **Configuration:** console client id; the client credential, a client secret read from an owner-only file (`--require-hardening` checks its mode, as for the TLS key; decision 4); the exact redirect URI (or the console origin it is built from); the IdP's authorization, token, end-session and revocation endpoints, configured or read once from `{issuer}/.well-known/openid-configuration` over HTTPS; the idle and absolute session limits (decision 2); and the IdP-logout setting, off by default (decision 3). Outbound calls go only to the configured IdP, as the JWKS URL already does (ADR-008 §2). `private_key_jwt` (RFC 7523) client authentication comes later and is noted on issue #218; it is not part of this work.
2. **Startup refusals:** console login without operator OIDC; a console client id equal to the operator audience or the agent audience (the verifier does not check `typ`, so an ID token whose `aud` equalled the operator audience would pass as an access token); a non-HTTPS redirect URI outside `--insecure-dev`; an issuer that differs from the operator issuer; an idle limit outside 5 to 60 minutes or an absolute limit above 12 hours; and, under `--require-hardening`, the development fallback of decision 6 (console login not configured together with `--insecure-dev`). `--require-hardening` already refuses `--insecure-dev` as a relaxation (`Relaxation::InsecureDev` in `crates/kavach-api/src/relaxations.rs`); the refusal names the pasted-token fallback as well, so the reason is plain.
3. **Routes:** `GET /auth/login`, `GET /auth/callback`, `POST /auth/logout`, `GET /auth/session` (display principal, groups, expiry; never a token) and a public `GET /auth/config` that says only whether console login is configured and, when it is not, whether the development pasted-token field is allowed (only under `--insecure-dev`). Rate limited, documented in `docs/openapi.yaml`, with login and logout events in the admin audit log.
4. **The cookie step and CSRF checks** of Decision 2, operator listener only.
5. **Docs in the same change:** SECURITY_PROPERTIES.md rows (session tokens never leave the server; cookie refused on agent routes; CSRF checks), THREAT_MODEL.md (session riding as the residual risk of XSS; login CSRF), BYPASS_INVENTORY.md for the relaxations under `--insecure-dev` (a plain-HTTP redirect URI, and the pasted-token fallback of decision 6), INSTALL.md (IdP client registration), and SECOND_REVIEW.md (it handles a client credential and session tokens).

Cedar policies, `oidc.rs` verification, the identity key, the CLI and gRPC do not change.

### 7. CSP and redirect URI constraints

- `connect-src 'self'` stays: the browser never calls the IdP with `fetch`.
- `form-action 'self'` applies to redirects after a form submission in some browsers, so **login is a link** (`<a href="/auth/login">`), not a form, and logout is a `fetch` POST, followed by a script navigation to the end-session URL only when the server returns one (the IdP-logout setting is on).
- `frame-ancestors 'none'` stays; nothing is framed and there is no silent iframe renewal.
- `Referrer-Policy: no-referrer` keeps the code and `state` out of the IdP and third parties' referrers; the `303` after the callback removes them from history. `console.rs` sets that header only on the console page and its files, so the `/auth/*` routes must set it (and `Cache-Control: no-store`) on their own responses.
- The redirect URI is registered at the IdP as one exact `https://<console host>/auth/callback`. No wildcards and no second path. `http://localhost` is for development only, under `--insecure-dev`; whether each target browser keeps `Secure` and `__Host-` cookies on `http://localhost` is checked in the Playwright run, not assumed.

## Consequences

- No operator token is ever readable by console JavaScript or stored in the browser.
- The API gains a CSRF surface on the operator listener and the checks that close it; they need their own tests (below) and a second review.
- `kavach-api` holds per-session state and a client credential (a client secret in an owner-only file). A restart signs everyone out; with more than one replica, an operator needs affinity or signs in again.
- Signing out of the console does not, by default, sign the person out of the IdP or its other applications. A deployment that wants that turns on the IdP-logout setting.
- Session limits are settings within fixed bounds (idle 5 to 60 minutes, absolute at most 12 hours); a deployment cannot configure a session longer than that, and startup says why.
- Development stacks without an IdP (`kavach dev up`) keep the pasted-token field, but only with `--insecure-dev` and without console login configured; a hardened start refuses that. End-to-end tests use a small OIDC test double in the repository, so CI gains no new container image.
- A deployment's IdP must register a confidential client with PKCE and the exact redirect URI.

## Test plan

Rust integration tests in `crates/kavach-api/tests/` (with a test IdP double), before any Playwright:

- Callback: wrong or missing `state`, a replayed code or login record, an expired login record, a wrong `code_verifier`, an ID token with the wrong `nonce`, `aud` or `iss`, and an access token the `OidcVerifier` refuses: each creates no session.
- Cookie attributes exactly as in Decision 1; a new session id after login.
- A cookie without the custom header, with a cross-site `Origin` or `Sec-Fetch-Site`, or together with `Authorization` or `X-Kavach-Principal`: refused. The cookie on the agent and system-of-record listeners: 401.
- Idle and absolute expiry; a refresh (including one that rotates the refresh token) never extends the absolute limit; a failed refresh ends the session; logout makes the old cookie useless.
- Logout with the IdP-logout setting off (the default) returns no end-session URL; with it on, it returns one without `id_token_hint`.
- A full session table refuses a new login with a clear error and leaves every existing session working.
- Cedar through a session: a viewer cannot stop an agent (403); the proposer cannot approve their own change request through a second session (the identity check holds); a session and a CLI token of the same person are the same identity.
- Logs and responses: a captured-log test (as `logs_carry_correlation_and_never_the_destination_or_credential`) and a scan of every `/auth/*` response for token material.
- Startup refusals of Decision 6.2 (including session limits just outside each bound and the pasted-token fallback under `--require-hardening`) and the `--require-hardening` file-mode check on the client secret file.

Playwright and axe at UI-4 (approved dev dependencies `@playwright/test` and `@axe-core/playwright`), against a dev stack with the small OIDC test double in the repository (not a Keycloak image):

- Sign in round trip; a reload keeps the session; sign out, and Back does not restore a signed-in page.
- After sign-in, `localStorage`, `sessionStorage`, IndexedDB and `document.cookie` hold no token (the session cookie is HttpOnly).
- The network log shows no `fetch` to any origin but the console's.
- No `securitypolicyviolation` event on any page.
- An expired session sends the operator to sign in with a plain message.
- Keyboard-only sign-in and sign-out; axe finds no WCAG 2.2 AA violation on the signed-out and signed-in pages.

## Decisions on the open questions (owner, 2026-11-14)

1. **C or B:** C, the backend for frontend in `kavach-api` with an HttpOnly session cookie.
2. **Session limits:** defaults of 15 minutes idle and 8 hours absolute. They are settings, bounded to 5 to 60 minutes idle and at most 12 hours absolute; startup refuses values outside those bounds (Decisions 3 and 6.2).
3. **IdP logout:** by default, logout ends only the Kavach session. Ending the IdP session too is an opt-in setting, off by default (Decision 4).
4. **Client credential:** a client secret in an owner-only file, checked by `--require-hardening`. `private_key_jwt` comes later (noted on issue #218).
5. **Refresh tokens:** used when the IdP issues them; rotated ones are taken; they never extend the absolute limit (Decision 3).
6. **Development without an IdP:** the pasted-token field stays only when console login is not configured **and** the server runs with `--insecure-dev`. Startup with `--require-hardening` refuses that combination (Decision 6.2). End-to-end tests use a small OIDC test double in the repository, not a Keycloak image.
7. **A full session table:** refuse new logins with a clear error; never evict existing sessions (Decision 3).
8. **Multiple replicas:** "affinity or sign in again" is accepted. The single-instance decision stands.
9. **Order:** confirmed. Roadmap 1.3 (API security headers) lands first. Then the ADR-018 implementation, which is on the second-review list and needs the owner's go.

## References

- RFC 6749 (OAuth 2.0), RFC 7636 (PKCE), RFC 7009 (token revocation), RFC 7523 (JWT client authentication), RFC 9068 (JWT access tokens), draft-ietf-httpbis-rfc6265bis (cookie prefixes and SameSite), OpenID Connect Core 1.0, OpenID Connect RP-Initiated Logout 1.0
- IETF draft "OAuth 2.0 for Browser-Based Applications" (draft-ietf-oauth-browser-based-apps): the backend-for-frontend, token-mediating and browser-only patterns and their threats
- `crates/kavach-api/src/{auth.rs,oidc.rs,console.rs,http.rs,state_changes.rs}`, `console/src/lib/api.ts`, `console/src/pages/SettingsPage.tsx`

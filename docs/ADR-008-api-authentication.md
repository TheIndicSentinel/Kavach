# ADR-008: API Authentication — OIDC Access Tokens and mTLS Principals

**Status:** Accepted  
**Date:** 2026-09-30  
**Deciders:** Kavach product/engineering  
**Related:** ADR-001, ADR-003, ADR-007, [SECURITY_PROPERTIES.md](SECURITY_PROPERTIES.md), [THREAT_MODEL.md](THREAT_MODEL.md)

## Context

Until this ADR every API principal was the self-asserted `X-Kavach-Principal` header (or gRPC metadata). mTLS only proved that *some* client certificate chained to the CA and was never bound to the principal; HMAC covered only `/v1/evaluate`, signed the body alone and could be replayed. Cedar RBAC and dual control were therefore advisory (independent review; H0).

Regulated financial institutions standardise on two mechanisms: **mTLS** with bank-issued certificates for *which workload is calling*, and **OAuth 2.0 / OpenID Connect access tokens** from the bank's identity provider (Entra ID, Okta, Ping, ForgeRock, Keycloak) for *which principal is acting*. ADR-007 already chose Keycloak client-credentials JWTs for agents.

## Decision

### 1. Principal sources and precedence

1. **`Authorization: Bearer <JWT>`** — an OIDC/OAuth 2.0 access token (RFC 7519, RFC 9068 profile) verified locally (§2). *Primary.*
2. **mTLS client-certificate SAN** — for machine callers without an IdP (loan-origination systems, batch). With `--mtls-principal-san uri|dns` (requires `--tls-client-ca`), the verified leaf certificate's **single** SAN of that type is the principal id (for example a SPIFFE id `spiffe://bank.example/los`); zero or several SANs of that type give no principal. Groups come from the entities file. HTTP reads the certificate through a TLS acceptor that attaches it to each request on the connection; gRPC reads `peer_certs()`.
3. **`X-Kavach-Principal` header** — accepted **only with `--insecure-dev`**. Never trusted otherwise.

A token wins over a certificate principal: the token names the acting principal, the certificate the calling workload (which TLS has already verified). `X-Kavach-Principal` together with a token or a certificate principal is rejected (`400`). With Cedar access control on, startup fails unless an authenticated source (OIDC or mTLS principals) is configured or `--insecure-dev` is set.

### 2. Token verification (RFC 8725 practices)

- Algorithms: **RS256, PS256, ES256, EdDSA only**; `none` and HMAC algorithms are rejected (prevents algorithm-confusion attacks).
- `kid` is required and must be present in the configured JWKS; a JWK's own `alg`, when present, must match the token.
- `iss`, `aud`, `exp`, `nbf` validated; `--oidc-leeway-seconds` (default 60).
- Principal = configurable claim (default `sub`, 1–256 characters). Groups = configurable claim (default `groups`, array of strings). Groups become Cedar `Kavach::Group` parents of the principal, merged with memberships from the entities file; ids are used literally.
- JWKS from `--oidc-jwks-file` (fully offline) or `--oidc-jwks-url` (HTTPS only; fetched at startup, refreshed every 10 minutes and — at most once a minute — on an unknown `kid`; old keys kept if a refresh fails). The URL is the only outbound network call, it goes only to the bank's own IdP, and only when configured.

### 3. HMAC v2 (integrity and anti-replay, not identity)

For `/v1/evaluate` when `--hmac-secret` is set: `X-Kavach-Timestamp` (±300 s), single-use `X-Kavach-Nonce` (16–128 chars), and `X-Kavach-Signature: sha256=<hex>` over `v2\n{ts}\n{nonce}\n{METHOD}\n{path?query}\n` + body. Nonces are recorded only after the signature verifies; the cache fails closed when full. Body-only (v1) signatures are rejected.

*Scope decision:* HMAC stays on `/v1/evaluate` (the service-to-service ingestion path). Other routes are used by the console, which cannot hold a shared secret; they are authenticated by tokens or mTLS. gRPC does not support HMAC; it requires a bearer token in `authorization` metadata or mTLS.

### 4. Dual control during the transition

The **actor** of lifecycle changes is the authenticated principal. The **approver** is still named in `X-Kavach-Approver` (self-asserted) until H3 introduces change requests approved by a different authenticated principal.

*Superseded by ADR-009 (H3a):* `X-Kavach-Approver` is removed; changes are proposed and approved as change requests, and approvals require an OIDC token.

### 5. Deployment defaults

TLS uses the ring crypto provider explicitly; `aws-lc-rs` is banned in `deny.toml`, because with two providers compiled in rustls cannot choose a process default.

The pilot compose file no longer publishes Postgres, requires a database password, requires OIDC settings, mounts site-specific `entities.json`/`jwks.json`, and ships no example principals in the default container command.

## Consequences

- Cedar RBAC decisions now rest on a verified identity whenever OIDC is configured.
- **Breaking changes:** callers relying on `X-Kavach-Principal` must present access tokens (or run `--insecure-dev` locally); HMAC callers must sign v2; the pilot compose file needs `POSTGRES_PASSWORD`, OIDC settings and a `deploy/pilot-config/` directory.
- New dependencies: `jsonwebtoken` 9 (ring backend), `reqwest` with rustls and OS trust roots (only used for the JWKS URL).

## Deferred

- **Certificate revocation** (CRL/OCSP) for client certificates; keep certificate lifetimes short.
- **Trusted-proxy header** (API gateway injects identity over an allowlisted mTLS connection) — only if a pilot bank requires it.
- **RFC 8705 certificate-bound access tokens** (FAPI-grade) — P1.
- **Console OIDC login** (authorization code + PKCE); the console currently accepts a pasted access token.

## References

- RFC 7519 (JWT), RFC 8725 (JWT Best Current Practices), RFC 9068 (JWT Profile for OAuth 2.0 Access Tokens), RFC 8705 (OAuth 2.0 mTLS), OpenID Connect Core 1.0
- `crates/kavach-api/src/{auth.rs,oidc.rs,hmac_auth.rs}`, `crates/kavach-auth/src/lib.rs`

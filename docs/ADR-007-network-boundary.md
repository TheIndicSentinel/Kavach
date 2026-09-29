# ADR-007: Security Boundary, Network Topology and Enforcement Surfaces

**Status:** Accepted  
**Date:** 2026-09-29  
**Deciders:** Kavach product/engineering  
**Related:** ADR-003, ADR-004, ADR-005, ADR-006, [PRD](PRD.md) D3, D8, D11, FR-3, FR-4, FR-13; acceptance scenarios 1, 2, 4, 5, 11, 12

## Context

Kavach's core promise — "if an agent is not authorised to act, it does not hold the credential to act" — is only true if the agent **cannot reach protected resources except through Kavach** and **holds no credential that would let it**. That is a property of deployment topology and credential handling, not of policy alone. PRD D8 fixes the boundary as gateway + broker + network isolation, and states that SDKs enforce nothing.

Today:

- `deploy/docker-compose.pilot.yml` runs `postgres`, `kavach-api` and `batch-shadow` on the **default network**, with Cedar, HMAC and TLS all **off**.
- `X-Kavach-Principal` is trusted as-is (an upstream IdP is assumed).
- When access control is not configured, `authorize_principal` in `crates/kavach-api/src/auth.rs` returns `Ok(())` — **every request is allowed**.

These defaults are acceptable for the batch-shadow pilot but not for agent enforcement.

## Decision

### 1. The boundary

The security boundary is the **Resource Gateway + Credential Broker + network isolation**. SDKs (Python, TypeScript) are ergonomic helpers only; no security property may depend on them. `SECURITY_PROPERTIES.md` states the guarantee only for **brokered resources**.

### 2. Reference topology (Docker Compose)

```
agent_net   (internal: true — no egress)
  collections-agent, translation-subagent ──► kavach-dataplane
backend_net (internal: true)
  kavach-dataplane ──► mock-LMS, mock-messaging, mock-voice,
                       OpenBao, Keycloak, PostgreSQL
ops_net
  kavach-console, Ollama, OTel collector (off by default)
```

- `kavach-dataplane` (gateway + authorization + broker, one process per ADR-002) is the **only** container attached to `agent_net`; it is also attached to `backend_net` and `ops_net` (to reach backends and model endpoints). No other container spans networks.
- Agent containers have no route to `backend_net` or `ops_net` and no internet egress.
- **Model endpoints are governed resources:** agents reach Ollama through the gateway, not directly (PRD D3 — one Resource Gateway for tools, APIs and models).
- `POST /v1/sor/events` (ADR-004 §4) is exposed on `backend_net` only.

### 3. Agent authentication

- Agents authenticate with OAuth 2.0 client-credentials JWTs issued by Keycloak, validated against JWKS (`iss`, `aud`, `exp`, `nbf`) through the `IdentityProvider` port.
- `X-Kavach-Principal` is **not accepted** on agent surfaces.
- mTLS between agents and the data plane is optional in the MVP and supported by the existing rustls configuration.

### 4. Secure defaults

- Agent surfaces (`/mcp/*`, `/proxy/*`, `/v1/authorize`) **refuse to start** unless access control, identity validation and a non-test-double `CredentialBroker` are configured. There is no "access control off = allow" path for agents.
- Existing `/v1/evaluate` behaviour is unchanged by this ADR. A follow-up requires an explicit `--insecure-dev` flag to run it without access control.

### 5. Resource Gateway

- Native Rust (axum/hyper), with the official Rust MCP SDK (`rmcp`) for MCP.
- Flow per request: authenticate → load tool registration (trust level, action map, parameter schema, reference-only fields, risk class, manifest hash) → extract typed parameters → reject raw values in reference-only fields (`BLOCK`) → call the authorization core **in-process** (ADR-003) → apply obligations (mask, rate-limit, route) → resolve capability references via `ReferenceResolver` (ADR-004 §7) → obtain or inject the backend credential via `CredentialBroker` → forward to the backend → tag the response with the tool's trust level for taint tracking.
- `/v1/authorize` is also exposed (HTTP and gRPC) for SDK pre-checks and a future Envoy `ext_authz` adapter; it is not a substitute for the gateway.
- An unregistered tool, or a tool whose manifest hash changed, moves the agent to `RESTRICTED` and raises `ALERT` (PRD FR-3).

### 6. Backend credential acceptance

- Reference backends (mock LMS, mock messaging, mock voice) accept **only** broker-issued credentials: short-lived, audience-bound, bound to `mandate_id`, with a `jti` replay cache — or secrets injected by the gateway that the agent never sees and that rotate automatically.
- No backend secret appears in agent containers, their environment, mounted files or images. CI scans images and environments for secrets.
- Credentials issued after human approval are single-use and bound to the approved `action_hash` (PRD D17).

### 7. Bypass test matrix (acceptance scenario 11)

| Bypass attempt | Control that stops it | Test |
|---|---|---|
| Call a backend directly | `agent_net` has no route to `backend_net` | Connection refused from agent container |
| Find a secret in env / files / image | No secrets present; CI secret scan | Scan passes; attack harness finds nothing |
| Forge a mandate | JWS signature + issuer `kid` (ADR-004 §2) | `Rejected` → `BLOCK` |
| Replay a system-of-record event | `event_id` uniqueness + nonce + freshness (ADR-004 §4) | `Rejected` |
| Replay or reuse an expired credential | Backend validates `exp`, audience, `jti` | Backend rejects |
| Use a second, unregistered MCP endpoint | No route; gateway registry | Connection refused / `RESTRICTED` |
| Supply its own timestamp | Trusted server time only (ADR-003 §7) | Field ignored; decision unchanged |
| Dependency unavailable mid-request | Typed `Unavailable` errors (ADR-006 §3) | Critical action `BLOCK` (scenario 12) |

### 8. Future deployment targets

- Kubernetes: `NetworkPolicy` objects mirror the three compose networks; the data plane can also run as a sidecar.
- Service mesh / Envoy: an `ext_authz` adapter calls `/v1/authorize`; credential brokering remains in Kavach.

## Consequences

- The central security claim becomes demonstrable and testable rather than asserted.
- The reference compose file replaces the default-network pilot layout for agent workflows; the existing pilot compose remains for Decision Governance batch shadow.
- Operating agents through Kavach requires Keycloak (or another IdP) and OpenBao in the reference stack; both are free and local (PRD D6).
- **Follow-ups found during exploration:** require `--insecure-dev` for `/v1/evaluate` without access control; document that the existing pilot compose is not an agent-enforcement topology.

## References

- [PRD](PRD.md) D3, D8, D11, D17, FR-3, FR-4, FR-13; acceptance scenarios 1, 2, 4, 5, 11, 12
- `deploy/docker-compose.pilot.yml`, `crates/kavach-api/src/auth.rs`, `crates/kavach-api/src/http.rs`
- RFC 6749 §4.4 (client credentials), RFC 7519 (JWT), RFC 8693 (token exchange)
- Model Context Protocol specification; official Rust SDK (`rmcp`)

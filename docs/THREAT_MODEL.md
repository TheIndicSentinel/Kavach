# Threat Model (v2)

**Scope:** Decision Governance (evaluate API, batch, console, evidence) and the Agent Authorization path (mandates, the authorization core, the gateway and credential broker, the kill switch, revocation by system-of-record event, unknown-outcome reconciliation: ADR-003 … ADR-017). Both are in the code.  
**Status:** the older words (**Implemented**, **This release**, **Mitigated**) say a control exists in the code. Where a row was *planned*, it now carries a tag from [SECURITY_PROPERTIES.md](SECURITY_PROPERTIES.md) (**Enforced**, **Conditional**, **Reference**, **Dev stack**), which is the authority on what holds and under what condition, or **Planned**/**Not built** when it still does not exist (see its *Planned* and *Not guaranteed* sections). Last checked against the code and the ADR index on 2026-10-24.  
**Companion:** [SECURITY_PROPERTIES.md](SECURITY_PROPERTIES.md) states which properties are guaranteed today.

## Assets

| Asset | Property | Where |
|---|---|---|
| Policy packs | Integrity, provenance | `packs/`, runtime pointers |
| Evidence chains and (future) signing keys | Integrity, non-repudiation | Postgres `decision_events`; ADR-005 |
| Model records | Integrity | `models/` |
| API principals / Cedar policies and entities | Integrity | `crates/kavach-auth/policies/` |
| Service credentials (mTLS, HMAC) | Confidentiality | Operator secrets |
| Task Mandates and system-of-record issuer keys | Integrity, authenticity | ADR-004, ADR-014: **Enforced** (agent authorization core; the issuer-key row is **Conditional** until its Postgres contract has an Actions log) |
| Per-request resource credentials minted by the broker | Confidentiality | ADR-006/007: **Enforced** for the broker, **Reference** for the mock provider that accepts them. A real provider's own API token held by the gateway: **Planned** (ADR-015 provider mode is accepted; its sandbox provider/channel and template mapping remain open) |
| Credential exfiltration by the provider path (H5b) | Gateway HTTP client follows no redirects and ignores proxy environment variables; credentials go only to configured endpoints; HTTPS expected outside an isolated backend network | **Mitigated** |
| Resource credentials (H5b) | Confidentiality and integrity: bearer secrets carrying the destination | Signed then encrypted to the provider (JWE ECDH-ES/X25519, A256GCM): opaque outside the provider; never logged or returned to agents; 15 s life; dedicated signing key, separation checked at startup |
| Reference vault (capability ref → real value) | Confidentiality | ADR-004 §7: **Reference** (the fixture resolver); a production resolver adapter must pass the same conformance suite |
| Per-subject keys (crypto-shredding) | Confidentiality, controlled destruction | ADR-005 §7: **Not built**. Subjects are keyed pseudonyms under one key; a single subject cannot be erased by key destruction (SECURITY_PROPERTIES *Not guaranteed*) |
| Trusted time | Integrity, availability | ADR-003 §7: **Conditional** on a kernel-synchronised clock (`kavach-clocksync`, Linux; issuing and delegating answer 503 without it; a hand-set clock runs only under `--insecure-dev`, **Dev stack**) |
| Approvals bound to the exact change | Integrity, non-repudiation | Change requests carry a digest the approver must echo (ADR-009): **Enforced**. The WebAuthn step-up and single-use credential of PRD D17: **Not built** |
| Console sign-in sessions and the IdP tokens behind them (ADR-018) | Confidentiality, integrity | `kavach-api` memory only: the browser holds a random session handle in an `HttpOnly` `__Host-` cookie; access, refresh and ID tokens and the client secret never reach it (**Conditional**: only when console sign-in is configured) |

## Trust boundaries

```
Callers / LOS / console users ──(OIDC token or mTLS certificate → Cedar principal)──► kavach-api ──► Postgres
                                                                        │
                            (ADR-007, compose)                           ▼
agent_net (no egress) ──► kavach-dataplane ──► backend_net (SoR, tools, OpenBao, Keycloak)
                                           └──► ops_net (models, console)
```

Everything an agent sends (tool parameters, model output, borrower content) is **untrusted**. Only system-of-record events signed by registered issuers can create authority (ADR-004).

## STRIDE summary

| Threat | Mitigation | Status |
|---|---|---|
| Spoofing (API caller) | OIDC access token (JWT) on every HTTP route and gRPC call: issuer, audience, JWKS `kid`, `exp`/`nbf`, asymmetric algorithms only (ADR-008). `X-Kavach-Principal` accepted only with `--insecure-dev`; Cedar without an authenticated source refuses to start. HMAC v2 (timestamp + nonce + method + path) on `/v1/evaluate`. mTLS principals: the verified client certificate's single URI/DNS SAN (`--mtls-principal-san`), HTTP and gRPC. Residual: tokens valid until expiry; no client-certificate revocation checks. | **Mitigated** (OIDC or mTLS principals) |
| Spoofing (console sign-in, ADR-018) | Authorization code with PKCE S256 for a confidential client; `state` and `nonce` bound to a single-use login record (at most 600 s, keyed by an `HttpOnly` login cookie); the ID token checked (signature, `iss`, `aud`, `nonce`) and the access token verified by the same `OidcVerifier` as a CLI token, so a session and a CLI token of one person are one Cedar principal; a new session id at every sign-in (no fixation); idle (5–60 min) and absolute (at most 12 h) limits that no refresh extends; logout revokes the refresh token. Residual: a stolen session handle works until the session ends (no binding to the client); sessions live in one process's memory, so a restart signs everyone out and replicas do not share them | **Mitigated** when configured |
| CSRF and login CSRF (console session) | The session cookie is `SameSite=Strict`; a cookie request also needs `X-Kavach-Console: 1` (a header no cross-site form or simple request can set), an `Origin` equal to the console's own origin when present, and a `Sec-Fetch-Site` of `same-origin` or `none` when present; the cookie beside `Authorization` or `X-Kavach-Principal` is refused (400). All of this is checked before the session is looked up. Login CSRF (an attacker making the victim sign in as the attacker): the callback is accepted only with the login cookie whose record holds the returned `state`, so a callback URL started in another browser finds no record. Residual: a non-browser client that sends neither `Origin` nor `Sec-Fetch-Site` passes the origin checks; it still needs the custom header and the victim's cookie, which it cannot read | **Mitigated** when configured |
| Session riding after XSS in the console (residual) | Tokens are out of the browser's reach (`HttpOnly`, kept by the server), and the console's strict CSP (no inline script, `default-src 'self'`) makes injecting script hard. But a script that does run in the console's origin can send same-origin requests with the cookie and the custom header, and so act as the signed-in operator until the session ends (idle or absolute limit, or logout). It cannot take a token away to use elsewhere or later. Governance changes still need a second person (maker-checker), and Cedar limits what the session's principal may do | **Accepted residual** (ADR-018) |
| Spoofing (authorization disabled) | `--access-control` defaults to `cedar`; disabling requires `--insecure-dev` and prints a warning | **This release** |
| Tampering / misconfiguration (API RBAC policies) | Policies strictly validated and entities/requests validated against the compiled-in Cedar schema at startup; principal header treated as a literal id | **This release** |
| Spoofing (agent) | Client-credentials access tokens for a dedicated agent audience, verified via JWKS; agent id from a configurable claim (`azp`); agents without a passport refused; `X-Kavach-Principal` never accepted on agent surfaces; operator and agent tokens do not cross (H5a-5). Residual: tokens are bearer (RFC 8705 binding is P1); agent risk states (RESTRICTED/QUARANTINED) arrive with taint tracking in H5b+ | **Mitigated** for `/v1/authorize` |
| Spoofing (system-of-record issuer of another tenant) | Each issuer key is registered for one tenant and one system; an event is accepted only from the key registered for its own tenant and system; unknown key, another tenant's key and bad signature get one uniform refusal (no key enumeration); the same key material cannot be registered twice; the listener also refuses a tenant the stack does not serve. Residual: a compromised issuer key still speaks for its own tenant (rotate; ADR-004) | **Mitigated** (pending Postgres CI confirmation of the store contract) |
| Tampering (pack file, reload) | Digest recorded on activation; rollback / model update refuse changed bytes (409, audited); unpinned reloads audited | **This release** |
| Tampering (pack file, restart) | `--pack-sha256` startup pin (optional, API and batch) | **This release** (optional) |
| Tampering (pack file, restart without pin) | Postgres mode: the governed pointer row is the startup source of truth; API and batch refuse a `--pack` path or bytes that disagree; first start records an audited baseline; `--bootstrap-pack` is an audited recovery override (API only) | **This release** (Postgres mode) |
| Tampering (runtime pointer row) | Governance events (activate/rollback) recorded on the evidence chain | **Planned** (ADR-005 §11; no governance event record exists in the code yet). Meanwhile pointer integrity is **Conditional** on a separate database role and the startup pin |
| Inconsistent governance state on failure | Validate → persist + audit → swap live evaluator | **This release** |
| Tampering (pack content, model mode, retention, erasure — insider) | Maker-checker change requests (ADR-009): distinct authenticated approver with an OIDC token, `approve_*` separated from `propose_*` in Cedar, digest echo, binding re-checked, one transaction, immutable decided requests. Model mode persisted and the model file pinned and optionally signed (ADR-010). Residual: two IdP identities for one person; DBA can disable the trigger. | **Mitigated** |
| Tampering (agent tool registry) | Registry signed by a `tool`-role signer and optionally pinned; startup refuses unsigned, tampered or off-pin registries without `--insecure-dev`; digest recorded per decision (H5b) | **Mitigated** |
| Tampering (pack authenticity) | Detached Ed25519 pack signatures from trusted signers (`--pack-signers`), checked on every load in API and batch | **This release** (when configured) |
| Tampering (policy semantics) | Formal Cedar analysis (cedar-policy-symcc + cvc5) of the shipped agent policies on every CI run: subject binding, waiver ceiling, contact window, no evaluation errors; weakened variants must be detected | **This release** (shipped policies, in CI, which has been unavailable since the billing block). Analysis at activation time for deployable policy packs: **Not built** (agent policies are compiled in) |
| Information disclosure / tampering (database link) | Every Postgres connection uses TLS with a verified certificate and host name (`verify-full`); a server without TLS is refused before anything is sent; weaker modes refuse startup outside `--insecure-dev` and cannot be set through `PGSSLMODE` | **This release.** Client certificates to Postgres: not supported |
| Tampering (evidence chain) | Hash chain + verify CLI detect in-place edits of individual rows; a database writer can rewrite/re-hash or truncate the chain undetected | Partial — the v1 chain is a gap (documented); the INSERT-only runtime role is **Conditional** (separate database roles); signed heads and the offline bundle for the agent chain are below |
| Tampering (evidence, stronger) | Per-record signatures and JCS canonical hashing for agent records; signed checkpoints of the agent chain, written on a schedule with a dedicated key | Partial — **this release** for the agent chain: exported as a signed bundle and verified offline against a checkpoint kept off-host (`kavach-evidence export`, `verify-bundle --expect-checkpoint`), truncation and rewrites by a holder of the database and keys are detected. Only as far as the last kept checkpoint; not for the v1 `decision_events` chain; no external anchoring (ADR-005 §13) |
| Tampering / forgery (mandate) | Strict JWS (EdDSA, JCS-canonical, verified before parsing); stored status + stored-token match + trusted-time validity; issuance only from SoR events signed by a key registered for that system; event replay, staleness and wildcard subjects rejected | **This release** (library; enforced on agent requests from M1.5/M1.6) |
| Repudiation | Evidence rows carry service identity; admin audit and change requests record the authenticated proposer and approver with the change digest; decided requests are immutable. The audit table itself is still mutable by a DB writer | Partial — insert-only role **Conditional** (separate database roles); signed governance events **Planned** |
| Repudiation (approvals) | WebAuthn step-up bound to `action_hash`; single-use credential | **Not built** (no WebAuthn in the code). Approvals are OIDC identities echoing the change digest (ADR-009, **Enforced**) |
| Information disclosure | No raw input in DB (digests); no telemetry by default | Implemented |
| Information disclosure (agents) | Capability references; destinations resolved only inside the gateway after an allow and sent only encrypted to the provider; allowlisted gateway replies | **Enforced** for the gateway; the decision checks the requested fields against the mandate's fields. A read tool that returns data: **Not built** (`read_fields` is decided and recorded, not served) |
| Information disclosure (evidence reads) | `GET /v1/agent-decisions/{id}` is admin-only (Cedar `read_evidence`), rate-limited and audited per read; sequential ids allow enumeration by an admin, which the audit log records; records hold pseudonyms only | **Implemented** |
| Information disclosure (logs) | Redacting types never print; every log line passes a redacting writer (numbers in any script, JOSE tokens, credential headers, PAN, email); logs built from allowlisted fields and registry tool names; caller correlation ids validated; logs stay local (no export) | **Implemented** |
| Information disclosure (evidence PII) | Records hold keyed pseudonyms, never a raw subject; crypto-shredding with per-subject keys | Pseudonyms **Enforced**; per-subject erasure **Not built** |
| Denial of service | Body size limits; CEL wall-clock timeout | Implemented |
| Denial of service (slow and many clients; hung HSM) — **draft, awaiting the owner's go (1.2)** | On every listener: TLS handshake timeout, a header read and idle deadline that trickled bytes do not extend, a request timeout answered with a `503` problem (never a partial decision), a per-listener in-flight cap that refuses at once with `Retry-After` instead of queueing; each HSM sign and health call has a deadline and fails closed. All bounded settings; none can be turned off. Not covered: per-client fairness (one client can take the whole cap), connection count (only requests are capped), a call stuck in the HSM keeps its thread and session, startup `open()` of the HSM has no deadline, an HTTP/2 client that keeps sending PINGs keeps its idle connection | **This release** (local evidence only) |
| Denial of service (CEL cost) | CEL interpreter has no allocation limit and the timeout is checked between rules, so load-time bounds apply: pack ≤ 256 KiB, ≤ 200 rules, expressions ≤ 2048 chars, `timeout_ms` 1–1000; `max_alloc_bytes` is advisory | **This release** |
| Elevation of privilege | No caller-set enforce mode (ADR-001); Cedar RBAC | Implemented |
| Elevation (operator roles, ADR-019) | A role comes only from a stored binding, read per request with no cache; a binding lookup that fails refuses the request (503), never falls back to groups. Role entities are a separate Cedar type, so a token group named like a role gets nothing. A person binding needs the token's `sub` under the configured issuer (or, in development, the `X-Kavach-Principal` source); a certificate principal is never bound. Only `superadmin` may grant or revoke `superadmin`; only `superadmin` and `user_admin` may change a binding (alias groups may not); the solver proves these, plus that `viewer` and `auditor` change nothing. A decision that only `superadmin` allows is flagged `acting_as_superadmin` on its audit row | **Enforced** for the policy and the lookup (step 2b), and for grants and revokes (step 2c): a binding changes only through an approved change request, written in the approval's transaction; the proposer and the approver may not grant themselves or a group in their token; a revoke never leaves a tenant without an active person `superadmin` or `user_admin`, checked under a per-tenant lock so concurrent revokes cannot race past it. Residual: two colluding role holders can still grant each other's choices; the audit log and the access review (`GET /v1/access-review`, step 2c part 2: who proposed and approved each grant, and who has not been seen) are the detective control. Each export of the review is itself audited |
| Elevation (agent) | Effective authority = mandate ∩ chain ∩ passport ∩ policy ∩ risk; credential broker; network isolation | **Enforced** (agent authorization core, credential broker, gateway, kill switch); network isolation **Dev stack** (compose, proven by the isolation job). Delegation is a library: there is no HTTP delegation API |
| Time manipulation (evaluate) | Pack-effective selection uses trusted server time; client `decision_time` only validated (±300 s) and recorded | **This release** |
| Time manipulation (rules) | CEL rules receive trusted server time as `now`; the evaluate path passes server time | **This release** |
| Time manipulation (agents) | Agent windows computed in IST from trusted time (`kavach-authz`); kernel clock-sync gating for critical agent actions | **Enforced** windows; clock-sync gating **Conditional** (Linux kernel clock probe; no probe on macOS) |

## OWASP Top 10 for Agentic Applications — mapping

Item names follow the OWASP GenAI Security Project list (Dec 2025); verify IDs against the published version when this document is revised.

| OWASP risk | Kavach control | Status |
|---|---|---|
| ASI01 Agent goal hijack (prompt injection) | Mandate parameter binding; `@escalate` review; model output never grants authority; task taint | Binding and registry **Enforced**; `@escalate` → `HUMAN_REVIEW` exists but the approval credential is **Not built**; task taint tracking **Not built** (`task_tainted` is only an input to the policy) |
| ASI02 Tool misuse | Tool registry, action maps, parameter schemas, ceilings | **Enforced** (tool registry, mandate ceilings) |
| ASI03 Identity and privilege abuse | Credential broker; no standing secrets; short-lived, mandate-bound credentials | **Enforced** (broker, 15 s credentials); **Reference** for the provider that accepts them |
| ASI04 Agentic supply chain | Tool manifest hashes; signed packs; SBOM and licence allowlist in CI | Registry digest and signature **Enforced**; signed packs **Conditional** (`--pack-signers`); dependency and licence checks (`cargo deny`) run in CI, which has been unavailable since the billing block (see SECOND_REVIEW) |
| ASI05 Unexpected code execution | Agents isolated on `agent_net` without egress; no code-exec tools in reference workflow | Isolation **Dev stack** (compose); reference agents **Planned** (M5) |
| ASI06 Memory and context poisoning | Per-task taint from untrusted tool/user content | **Not built** |
| ASI07 Insecure inter-agent communication | Server-side delegation with narrowing (A2A deferred) | Narrowing and chain validity **Enforced** in the library (`kavach-mandate`); no HTTP delegation API, so not exercised end to end |
| ASI08 Cascading failures | Typed port errors; fail-closed for critical actions | **Enforced** for the agent path (evidence store, clock, signing and provider outages fail closed); the fault-injection coverage is being extended |
| ASI09 Human-agent trust exploitation | Exact-action approval rendering; batching and decision-latency monitoring | Change requests show the exact change and its digest (**Enforced**); batching and decision-latency monitoring **Not built** |
| ASI10 Rogue agents | Agent states (`RESTRICTED` → `REVOKED`) enforced on every call and through the delegation chain (ADR-013); operator stop/reinstate API with maker-checker reinstatement; signed state records; mandate revocation via events | Implemented (K1-1 to K1-3b), including attacks and independent-oracle simulation; see `SECURITY_PROPERTIES.md` for limits |

**MCP-specific risks** (OWASP MCP Top 10 themes; IDs to be verified): tool poisoning (manifest hashes, trust levels), token exposure (broker injection, no secrets in agent containers), privilege escalation (effective authority intersection), context over-sharing (capability references, purpose-minimal fields), insufficient authorization (gateway + Cedar on every call), audit gaps (Agent Decision Records).

## CEL as untrusted code

- Wall-clock timeout — Implemented  
- Allocation cap — **not available** in the CEL interpreter; `max_alloc_bytes` is advisory. Bounded instead by load-time limits (below)  
- No I/O from expressions — Implemented (interpreter has no I/O functions)  
- Max pack size 256 KiB, ≤ 200 rules, expressions ≤ 2048 characters, `timeout_ms` 1–1000 — **This release**  
- Rules must not base time decisions on `request.decision_time` (client-supplied); a trusted `now` variable arrives in M1.5  
- Pinned CEL interpreter version — Implemented (`Cargo.lock`)  

## Shadow infra failure

- Do not write fake healthy evidence  
- Incident record with `correlation_id`  
- Alert on-call  

## Insider: pack edit

- Maker-checker change requests (ADR-009) for activate, rollback, model, retention and erasure; admin audit log — Implemented  
- Pack file edited on disk after activation → rollback / model update refuse it (409, audited) — **This release**. A restart without `--pack-sha256` re-measures the edited file — closed by pointer-row startup (Postgres mode) and signed packs (when signers are configured)  
- Any byte change, including comments, requires an approved re-activation; integrity is byte-level by design  
- Signed packs so an insider without a signing key cannot introduce a pack — **This release** (when `--pack-signers` is configured); keep signing keys off the API host  

## Restore

- Postgres restore → run `kavach-evidence verify` before accepting traffic  
- After restore, start with `--pack-sha256` (or compare `/v1/runtime` `pack_sha256` with the expected digest) before enabling enforce mode — a matching `/v1/runtime` digest without a pin only proves which bytes were loaded, not that they are the approved ones  

## Out of scope for the current release

- Python dependency and model-weight licence checks — added with the reference agents (M5)  
- HA, HSM / KMS — Stage 2  

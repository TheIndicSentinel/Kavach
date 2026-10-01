# Threat Model (v2)

**Scope:** Decision Governance (implemented: evaluate API, batch, console, evidence) and the MVP Agent Authorization path (planned: ADR-003 … ADR-007).  
**Status legend:** **Implemented** · **This release** · **Planned (Mn)** — milestone from the MVP plan ([PRD](PRD.md)).  
**Companion:** [SECURITY_PROPERTIES.md](SECURITY_PROPERTIES.md) states which properties are guaranteed today.

## Assets

| Asset | Property | Where |
|---|---|---|
| Policy packs | Integrity, provenance | `packs/`, runtime pointers |
| Evidence chains and (future) signing keys | Integrity, non-repudiation | Postgres `decision_events`; ADR-005 |
| Model records | Integrity | `models/` |
| API principals / Cedar policies and entities | Integrity | `crates/kavach-auth/policies/` |
| Service credentials (mTLS, HMAC) | Confidentiality | Operator secrets |
| Task Mandates and system-of-record issuer keys | Integrity, authenticity | ADR-004 (planned) |
| Backend credentials held by the broker | Confidentiality | ADR-006/007 (planned) |
| Credential exfiltration by the provider path (H5b) | Gateway HTTP client follows no redirects and ignores proxy environment variables; credentials go only to configured endpoints; HTTPS expected outside an isolated backend network | **Mitigated** |
| Resource credentials (H5b) | Confidentiality and integrity: bearer secrets carrying the destination | Signed then encrypted to the provider (JWE ECDH-ES/X25519, A256GCM): opaque outside the provider; never logged or returned to agents; 15 s life; dedicated signing key, separation checked at startup |
| Reference vault (capability ref → real value) | Confidentiality | ADR-004 §7 (planned) |
| Per-subject keys (crypto-shredding) | Confidentiality, controlled destruction | ADR-005 §7 (planned) |
| Trusted time | Integrity, availability | ADR-003 §7 (planned) |
| Approvals bound to `action_hash` | Integrity, non-repudiation | PRD D17 (planned) |

## Trust boundaries

```
Callers / LOS / console users ──(OIDC token or mTLS certificate → Cedar principal)──► kavach-api ──► Postgres
                                                                        │
                            (planned, ADR-007)                           ▼
agent_net (no egress) ──► kavach-dataplane ──► backend_net (SoR, tools, OpenBao, Keycloak)
                                           └──► ops_net (models, console)
```

Everything an agent sends (tool parameters, model output, borrower content) is **untrusted**. Only system-of-record events signed by registered issuers can create authority (ADR-004).

## STRIDE summary

| Threat | Mitigation | Status |
|---|---|---|
| Spoofing (API caller) | OIDC access token (JWT) on every HTTP route and gRPC call: issuer, audience, JWKS `kid`, `exp`/`nbf`, asymmetric algorithms only (ADR-008). `X-Kavach-Principal` accepted only with `--insecure-dev`; Cedar without an authenticated source refuses to start. HMAC v2 (timestamp + nonce + method + path) on `/v1/evaluate`. mTLS principals: the verified client certificate's single URI/DNS SAN (`--mtls-principal-san`), HTTP and gRPC. Residual: tokens valid until expiry; no client-certificate revocation checks. | **Mitigated** (OIDC or mTLS principals) |
| Spoofing (authorization disabled) | `--access-control` defaults to `cedar`; disabling requires `--insecure-dev` and prints a warning | **This release** |
| Tampering / misconfiguration (API RBAC policies) | Policies strictly validated and entities/requests validated against the compiled-in Cedar schema at startup; principal header treated as a literal id | **This release** |
| Spoofing (agent) | Client-credentials access tokens for a dedicated agent audience, verified via JWKS; agent id from a configurable claim (`azp`); agents without a passport refused; `X-Kavach-Principal` never accepted on agent surfaces; operator and agent tokens do not cross (H5a-5). Residual: tokens are bearer (RFC 8705 binding is P1); agent risk states (RESTRICTED/QUARANTINED) arrive with taint tracking in H5b+ | **Mitigated** for `/v1/authorize` |
| Tampering (pack file, reload) | Digest recorded on activation; rollback / model update refuse changed bytes (409, audited); unpinned reloads audited | **This release** |
| Tampering (pack file, restart) | `--pack-sha256` startup pin (optional, API and batch) | **This release** (optional) |
| Tampering (pack file, restart without pin) | Postgres mode: the governed pointer row is the startup source of truth; API and batch refuse a `--pack` path or bytes that disagree; first start records an audited baseline; `--bootstrap-pack` is an audited recovery override (API only) | **This release** (Postgres mode) |
| Tampering (runtime pointer row) | Governance events (activate/rollback) recorded on the evidence chain | Planned (M2, ADR-005) |
| Inconsistent governance state on failure | Validate → persist + audit → swap live evaluator | **This release** |
| Tampering (pack content, model mode, retention, erasure — insider) | Maker-checker change requests (ADR-009): distinct authenticated approver with an OIDC token, `approve_*` separated from `propose_*` in Cedar, digest echo, binding re-checked, one transaction, immutable decided requests. Model mode persisted and the model file pinned and optionally signed (ADR-010). Residual: two IdP identities for one person; DBA can disable the trigger. | **Mitigated** |
| Tampering (agent tool registry) | Registry signed by a `tool`-role signer and optionally pinned; startup refuses unsigned, tampered or off-pin registries without `--insecure-dev`; digest recorded per decision (H5b) | **Mitigated** |
| Tampering (pack authenticity) | Detached Ed25519 pack signatures from trusted signers (`--pack-signers`), checked on every load in API and batch | **This release** (when configured) |
| Tampering (policy semantics) | Formal Cedar analysis (cedar-policy-symcc + cvc5) of the shipped agent policies on every CI run: subject binding, waiver ceiling, contact window, no evaluation errors; weakened variants must be detected | **This release** (shipped policies); analysis at activation time for deployable policy packs: planned (M1.6+) |
| Tampering (evidence chain) | Hash chain + verify CLI detect in-place edits of individual rows; a database writer can rewrite/re-hash or truncate the chain undetected | Partial — signed heads, INSERT-only role, export planned (P1) |
| Tampering (evidence, stronger) | Per-record signatures, signed checkpoints, JCS canonical hashing | Planned (M2, ADR-005) |
| Tampering / forgery (mandate) | Strict JWS (EdDSA, JCS-canonical, verified before parsing); stored status + stored-token match + trusted-time validity; issuance only from SoR events signed by a key registered for that system; event replay, staleness and wildcard subjects rejected | **This release** (library; enforced on agent requests from M1.5/M1.6) |
| Repudiation | Evidence rows carry service identity; admin audit and change requests record the authenticated proposer and approver with the change digest; decided requests are immutable. The audit table itself is still mutable by a DB writer | Partial — P1 (insert-only role, signed governance events) |
| Repudiation (approvals) | WebAuthn step-up bound to `action_hash`; single-use credential | Planned (M4) |
| Information disclosure | No raw input in DB (digests); no telemetry by default | Implemented |
| Information disclosure (agents) | Capability references; values resolved only in gateway; purpose-minimal fields | Planned (M3) |
| Information disclosure (evidence PII) | Crypto-shredding with per-subject keys | Planned (M2) |
| Denial of service | Body size limits; CEL wall-clock timeout | Implemented |
| Denial of service (CEL cost) | CEL interpreter has no allocation limit and the timeout is checked between rules, so load-time bounds apply: pack ≤ 256 KiB, ≤ 200 rules, expressions ≤ 2048 chars, `timeout_ms` 1–1000; `max_alloc_bytes` is advisory | **This release** |
| Elevation of privilege | No caller-set enforce mode (ADR-001); Cedar RBAC | Implemented |
| Elevation (agent) | Effective authority = mandate ∩ chain ∩ passport ∩ policy ∩ risk; credential broker; network isolation | Planned (M1–M3) |
| Time manipulation (evaluate) | Pack-effective selection uses trusted server time; client `decision_time` only validated (±300 s) and recorded | **This release** |
| Time manipulation (rules) | CEL rules receive trusted server time as `now`; the evaluate path passes server time | **This release** |
| Time manipulation (agents) | Agent windows computed in IST from trusted time (`kavach-authz`); kernel clock-sync gating for critical agent actions (M3) | Library: **this release**; sync gating planned (M3) |

## OWASP Top 10 for Agentic Applications — mapping

Item names follow the OWASP GenAI Security Project list (Dec 2025); verify IDs against the published version when this document is revised.

| OWASP risk | Kavach control | Status |
|---|---|---|
| ASI01 Agent goal hijack (prompt injection) | Task taint; mandate parameter binding; `@escalate` review; model output never grants authority | Planned (M1, M4) |
| ASI02 Tool misuse | Tool registry, action maps, parameter schemas, ceilings | Planned (M3) |
| ASI03 Identity and privilege abuse | Credential broker; no standing secrets; short-lived, mandate-bound credentials | Planned (M3) |
| ASI04 Agentic supply chain | Tool manifest hashes; signed packs; SBOM and licence allowlist in CI | Planned (M3) / Implemented (deny) |
| ASI05 Unexpected code execution | Agents isolated on `agent_net` without egress; no code-exec tools in reference workflow | Planned (M5) |
| ASI06 Memory and context poisoning | Per-task taint from untrusted tool/user content | Planned (M4) |
| ASI07 Insecure inter-agent communication | Server-side delegation with narrowing (A2A deferred) | Planned (M1) |
| ASI08 Cascading failures | Typed port errors; fail-closed for critical actions | Planned (M1) |
| ASI09 Human-agent trust exploitation | Exact-action approval rendering; batching and decision-latency monitoring | Planned (M4) |
| ASI10 Rogue agents | Agent states (`RESTRICTED` → `REVOKED`); mandate revocation via events | Planned (M4) |

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

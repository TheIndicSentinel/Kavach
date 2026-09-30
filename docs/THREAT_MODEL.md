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
| Reference vault (capability ref → real value) | Confidentiality | ADR-004 §7 (planned) |
| Per-subject keys (crypto-shredding) | Confidentiality, controlled destruction | ADR-005 §7 (planned) |
| Trusted time | Integrity, availability | ADR-003 §7 (planned) |
| Approvals bound to `action_hash` | Integrity, non-repudiation | PRD D17 (planned) |

## Trust boundaries

```
Callers / LOS / console users ──(mTLS or HMAC + Cedar principal)──► kavach-api ──► Postgres
                                                                        │
                            (planned, ADR-007)                           ▼
agent_net (no egress) ──► kavach-dataplane ──► backend_net (SoR, tools, OpenBao, Keycloak)
                                           └──► ops_net (models, console)
```

Everything an agent sends (tool parameters, model output, borrower content) is **untrusted**. Only system-of-record events signed by registered issuers can create authority (ADR-004).

## STRIDE summary

| Threat | Mitigation | Status |
|---|---|---|
| Spoofing (API caller) | mTLS or HMAC — **available, off by default**; without them Cedar authorizes a client-supplied principal name | Implemented (optional); startup warning when neither is configured — **This release** |
| Spoofing (authorization disabled) | `--access-control` defaults to `cedar`; disabling requires `--insecure-dev` and prints a warning | **This release** |
| Tampering / misconfiguration (API RBAC policies) | Policies strictly validated and entities/requests validated against the compiled-in Cedar schema at startup; principal header treated as a literal id | **This release** |
| Spoofing (agent) | Keycloak client-credentials JWT via JWKS; `X-Kavach-Principal` not accepted on agent surfaces | Planned (M3) |
| Tampering (pack file, reload) | Digest recorded on activation; rollback / model update refuse changed bytes (409, audited); unpinned reloads audited | **This release** |
| Tampering (pack file, restart) | `--pack-sha256` startup pin (optional, API and batch) | **This release** (optional) |
| Tampering (pack file, restart without pin) | Postgres mode: the governed pointer row is the startup source of truth; API and batch refuse a `--pack` path or bytes that disagree; first start records an audited baseline; `--bootstrap-pack` is an audited recovery override (API only) | **This release** (Postgres mode) |
| Tampering (runtime pointer row) | Governance events (activate/rollback) recorded on the evidence chain | Planned (M2, ADR-005) |
| Inconsistent governance state on failure | Validate → persist + audit → swap live evaluator | **This release** |
| Tampering (pack content, insider) | Dual control on activate/rollback; admin audit log | Implemented |
| Tampering (pack authenticity) | Signed packs (Ed25519 via `KeyProvider`); Cedar analysis before activation | Planned (M1) |
| Tampering (evidence chain) | Hash chain + offline verify CLI | Implemented |
| Tampering (evidence, stronger) | Per-record signatures, signed checkpoints, JCS canonical hashing | Planned (M2, ADR-005) |
| Tampering (mandate) | JWS signature + store status check; issuance only from signed SoR events | Planned (M1, ADR-004) |
| Repudiation | Append-only evidence; service identity per row; admin audit with actor + approver | Implemented |
| Repudiation (approvals) | WebAuthn step-up bound to `action_hash`; single-use credential | Planned (M4) |
| Information disclosure | No raw input in DB (digests); no telemetry by default | Implemented |
| Information disclosure (agents) | Capability references; values resolved only in gateway; purpose-minimal fields | Planned (M3) |
| Information disclosure (evidence PII) | Crypto-shredding with per-subject keys | Planned (M2) |
| Denial of service | Body size limits; CEL wall-clock timeout | Implemented |
| Denial of service (CEL cost) | CEL interpreter has no allocation limit and the timeout is checked between rules, so load-time bounds apply: pack ≤ 256 KiB, ≤ 200 rules, expressions ≤ 2048 chars, `timeout_ms` 1–1000; `max_alloc_bytes` is advisory | **This release** |
| Elevation of privilege | No caller-set enforce mode (ADR-001); Cedar RBAC | Implemented |
| Elevation (agent) | Effective authority = mandate ∩ chain ∩ passport ∩ policy ∩ risk; credential broker; network isolation | Planned (M1–M3) |
| Time manipulation (evaluate) | Pack-effective selection uses trusted server time; client `decision_time` only validated (±300 s) and recorded | **This release** |
| Time manipulation (rules / agents) | Trusted `now` in the CEL context (M1.5); kernel clock-sync gating for critical agent actions (M3) | Planned |

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

- Dual control on activate and rollback; admin audit log — Implemented  
- Pack file edited on disk after activation → rollback / model update refuse it (409, audited) — **This release**. A restart without `--pack-sha256` re-measures the edited file — closed by pointer-row startup (next PR) and signed packs (M1)  
- Any byte change, including comments, requires dual-control re-activation; integrity is byte-level by design  
- Signed packs so an insider cannot introduce an unsigned pack — Planned (M1)  

## Restore

- Postgres restore → run `kavach-evidence verify` before accepting traffic  
- After restore, start with `--pack-sha256` (or compare `/v1/runtime` `pack_sha256` with the expected digest) before enabling enforce mode — a matching `/v1/runtime` digest without a pin only proves which bytes were loaded, not that they are the approved ones  

## Out of scope for the current release

- Python dependency and model-weight licence checks — added with the reference agents (M5)  
- HA, HSM / KMS — Stage 2  

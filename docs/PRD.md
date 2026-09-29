# Kavach — MVP PRD

*Internal name: Kavach (matches the repository and crates). Public name: TBD — a parallel clearance workstream that must complete before public launch or any package publication.*

## Problem

Regulated lenders are putting AI into consequential workflows faster than their controls can follow.

- **Authority is too broad.** AI agents and automated decision systems run on standing API keys and service accounts with far more access than any single task needs. A manipulated model (prompt injection via a borrower reply, a poisoned tool response) can use all of it.
- **Authority is not traceable to a business reason.** Logs show which key made a call — not which business transaction, customer, purpose or consent justified it. Cloud IAM/authorization products (AWS Bedrock AgentCore Policy, Microsoft Entra Agent ID, Okta) answer "which agent is this and may it call this tool?" — not "is this action within what *this loan's delinquency* authorised, for *this borrower*, for *this purpose*, *now*?"
- **Regulation now demands proof.**
  - RBI recovery-conduct rules (effective 1 Jan 2027): contact only 08:00–19:00, recovery agents limited to data needed for recovery, 6-month record retention — applying to automated contact too.
  - DPDP purpose limitation and security safeguards (main obligations 13 May 2027).
  - The direction of RBI's draft Model Risk Management guidance (24 Jun 2026): kill switches, autonomy tiering, third-party model accountability.
  - Lenders remain accountable regardless of vendor claims.
- **Evidence is assembled manually,** after the fact, from editable logs.

**Who feels it:** CROs / model-risk / compliance (proof), CISOs / CTOs / platform teams (an enforceable boundary), heads of collections and operations (AI voice/WhatsApp agents already live across multiple vendors).

## Idea

**Kavach is an authorization and runtime control plane for consequential automated decisions and AI agents. Authority comes from the business transaction, not the agent: a system-of-record event creates a signed, time-bound, subject-bound Task Mandate, and an AI agent cannot turn model output into more authority than that mandate granted — because Kavach controls the credentials, the network path and the evidence.**

The MVP is a **fully local, reproducible, free/open-source reference implementation** proving this end to end on an AI-assisted loan-collections workflow, with the existing Decision Governance credit flow running on the same core.

### Locked decisions this PRD depends on

| ID | Decision |
|---|---|
| D1 | Public name TBD; clearance blocks launch and package publishing. "Kavach" is the internal name; repository and crate names unchanged for now. |
| D2 | Mandate encoding: JWS v1 behind a `MandateCodec`; server-side delegation. |
| D3 | Native Rust MCP/HTTP gateway → `/v1/authorize`; core independent of MCP. |
| D4 | Postgres outbox + LISTEN/NOTIFY behind an `EventBus` port. |
| D5 | **Licence: target Apache-2.0 for the future open-core release. Before relicensing, confirm a single copyright holder or obtain consent from every contributor whose code is relicensed. Until that audit completes, the existing MIT licence remains authoritative.** Dependency allowlist unchanged; `deny.toml` will document that `BSL-1.0` is the Boost Software License, not BUSL. |
| D6 | 100% reproducible with free/open-source/local resources; no external free service is part of any security guarantee. |
| D7 | Consent: domain model + fixture shaped as a ReBIT consent-artefact subset + contact-preference store; live integrations in Stage 2. |
| D8 | Security boundary = gateway + broker + network isolation; SDKs are not security-critical. |
| D9 | Evidence: tenant-partitioned chains + checkpoints; MVP runs one tenant × one partition. |
| D10 | Validation = public MVP + commercial-pull signals; GitHub popularity is not a go signal. |
| D11 | Agent tool interfaces use capability references, not sensitive values; raw values in reference-only fields → `BLOCK`. |
| D12 | Second implementation / test double for security-critical ports only; fixtures elsewhere. |
| D13 | `SECURITY_PROPERTIES.md` ships with every release. |
| **D14 Time** | **One authoritative server-side clock.** The authorization context receives an absolute trusted timestamp; business windows are evaluated in `Asia/Kolkata`; client/agent timestamps are never trusted. Critical actions fail closed when the clock's sync status is lost or drift exceeds the configured threshold (default sources: NIC/NPL NTP per CERT-In Directions). |
| **D15 Cedar / CEL** | **Cedar decides "is this action authorised?"** using trusted time and context. **CEL applies pack/business rules and maps to `PASS / ALERT / BLOCK / HUMAN_REVIEW`.** Invariant: **CEL can never downgrade a Cedar outcome**; CEL only refines a Cedar Allow. A Cedar Deny whose determining policies are **all** annotated `@escalate("human_review")` → `HUMAN_REVIEW` (lifted only by an approval bound to the exact `action_hash`); any other Cedar Deny → `BLOCK`. Overall result = most restrictive. See ADR-003 §5. |
| **D16 Mock LMS** | Written in **Rust**, described as a **protocol fixture**, not a lending system. Python for the LangGraph agents, attack harness and model experimentation. |
| **D17 Approver step-up** | **Keycloak WebAuthn/passkey step-up.** Approval is bound to the exact `action_hash` and yields a single-use credential; no session-level "approved for collections" can authorise a specific critical action. CI uses a **test-double step-up provider** — the property under test is approval → exact action → single-use credential binding. |

### Functional requirements

| ID | Requirement |
|---|---|
| **FR-1 Mandates** | Issue mandates only from signed system-of-record events: issuer allowlist, signature, nonce/event-ID replay protection, freshness window. Fields derived from the record, never free text. Reject wildcard subjects and ceilings exceeding any eligible agent's passport. Sign via `KeyProvider`. Support delegation (child ⊆ parent ∩ sub-agent passport, depth limit), revocation and expiry. |
| **FR-2 Authorization** | `/v1/authorize` (HTTP + gRPC `authz.v1`) computes effective authority = Mandate ∩ Chain ∩ Passport ∩ Policy ∩ Risk with trusted time (D14); Cedar + CEL combined per D15; obligations attached. Preserves ADR-001 `policy_decision` / `returned_decision` and shadow/enforce semantics. |
| **FR-3 Resource Gateway** | Native Rust MCP proxy + HTTP proxy. Tool registration: trust level, action map, parameter schema (incl. reference-only fields), risk class, manifest hash. Parameter extraction, reference-only enforcement, obligations (mask, rate-limit, route). Unregistered tool or manifest change → agent `RESTRICTED` + `ALERT`. |
| **FR-4 Credential plane** | `CredentialBroker` port: proxy injection (default), OpenBao dynamic secrets, Keycloak token exchange, in-memory test double. Agents never receive backend secrets. Short TTL, bound to `mandate_id`; single-use and bound to `action_hash` after approval; revocation cancels OpenBao leases. |
| **FR-5 Risk** | Monotonic per-task taint on responses from tools with trust `external_untrusted` or `user_content`. Tainted task + critical action ⇒ parameters must exactly match the mandate **and** `HUMAN_REVIEW`. Agent states `ACTIVE / RESTRICTED / QUARANTINED / REVOKED`. Detectors: Aadhaar (checksum), PAN, UPI, IFSC, Indian phone numbers. |
| **FR-6 Approvals** | Rendered exact-action view → WebAuthn step-up (D17) → approval record {`approval_id, action_hash, rendered_action, approver, step_up_ref, decision, single_use_credential_id, expires`}. Batching of similar requests; decision latency recorded. |
| **FR-7 Evidence** | Agent Decision Record v1. Chains partitioned by `(tenant, partition)` with signed Merkle checkpoints. For critical actions, a minimal signed record is written **before** credential issuance; enrichment is asynchronous. Per-subject keys with crypto-shredding. Offline `verify` CLI. External anchoring off by default. **No raw personal data on the chain.** Existing chain migrates to partition 0. |
| **FR-8 Consent** | Consent domain model; `LocalConsentFixture` using a subset of ReBIT consent-artefact fields (purpose code, data types, date range, lifetime, status); contact-preference store (opt-outs, channel). |
| **FR-9 Events / revocation** | `EventBus` port (Postgres outbox + NOTIFY; in-process test double). Payment, dispute, consent withdrawal, quarantine or manual kill → mandate and credentials revoked. |
| **FR-10 Packs** | `rbi-recovery-conduct`, `dpdp-core`, `credit-decision`, each mapped to source clauses with effective dates and labelled as guidance. Activation requires existing dual control plus a Cedar analysis run. |
| **FR-11 Console** | Existing console extended with: mandates, delegation chains, attack-chain stories, approval queue, evidence explorer/export, agent states. |
| **FR-12 SDKs** | Python + TypeScript: `mandate.from_record()`, `@action(bind=[...])`, task propagation. **Ergonomics only; no enforcement.** |
| **FR-13 Reference workflow** | **Rust** mock LMS (protocol fixture) emitting signed delinquency events; **Rust** mock messaging/voice providers accepting only Kavach-issued credentials; **Python** LangGraph collections agent + read-only translation sub-agent on Ollama (two pinned Apache-2.0-licensed models); **Python** attack harness; Docker Compose with isolated `agent_net` (no egress), `backend_net`, `ops_net`. |
| **FR-14 Decision Governance continuity** | Existing credit-evaluate flow runs unchanged on the same evidence chain and console, maintaining partner-pilot schema compatibility (`DECISION_EVENT_COMPAT.md`). |

### Non-functional requirements

| ID | Requirement |
|---|---|
| NFR-1 | Reproducible for free — no cloud account, paid API, proprietary model or paid SaaS. Licence allowlist enforced in CI for Rust, Python and npm dependencies and model weights. |
| NFR-2 | Performance on reference hardware (4-core / 16 GB; exact spec in ADR-003): `authorize` p99 < 5 ms in-process; gateway overhead p99 < 15 ms including minimal critical evidence write; 1,000 requests/s single-node baseline. |
| NFR-3 | Fail-safe: critical actions `BLOCK` if any required dependency or trusted time is unavailable; low-risk reads follow per-risk policy; auth/validation errors never disguised as PASS. |
| NFR-4 | Future-ready: `tenant_id` and version on every key, table, chain and format; `/v1` APIs; ports per D12. |
| NFR-5 | Supply chain: SBOM, signed images, provenance, pinned toolchains and models, `cargo-deny`. |
| NFR-6 | `SECURITY_PROPERTIES.md` (guaranteed / not guaranteed) updated in the same PR as any guarantee change. |
| NFR-7 | Time correctness: boundary tests at 07:59:59 / 08:00:00 / 18:59:59 / 19:00:00 IST, daily-counter rollover at IST midnight, injected clock skew and sync loss. |

### Acceptance scenarios (automated end-to-end tests and the public demo)

1. Reminder to `borrower:B-9382` at 11:00 IST → `PASS`; credential injected; minimal fields only.
2. Injected borrower reply → agent passes a raw phone number → task tainted; reference-only violation → `BLOCK`.
3. Contact at 19:45 IST, or a 4th contact in a day → `BLOCK`; boundary behaviour per NFR-7.
4. Request for `salary` / `other_loans` / `contacts` → `BLOCK`; mixed request → `PASS` with masking obligation.
5. Contact to `borrower:B-5511` under B-9382's mandate → `BLOCK` with no human involved.
6. 35% waiver (ceiling 10%) → `HUMAN_REVIEW` → WebAuthn step-up (test double in CI) → approval bound to `action_hash` → single-use credential. Replay fails; an altered amount fails; a session-level approval without the action hash fails.
7. Translation sub-agent calls `update_status` → `BLOCK`.
8. Dispute event → mandate revoked → in-flight credential rejected by the backend → next call `BLOCK`.
9. Unregistered tool or manifest-hash change → `RESTRICTED` + `ALERT`.
10. Evidence export verifies offline; B-9382 crypto-shredded; references unreadable; chain still valid.
11. Bypass attempts all fail: direct backend call, env/file/image secret search, forged mandate, replayed system-of-record event, expired or replayed credential, alternate MCP endpoint, agent-supplied timestamp.
12. Data plane, Postgres, OpenBao, Keycloak or trusted time unavailable mid-request → critical actions `BLOCK`; auth/validation errors remain visible.
13. Decision Governance: a credit-model output evaluated in shadow, then enforce, on the same chain and console.

## Target user

**Primary (adoption):** platform and security engineers at Indian NBFCs, fintech lenders and lending-platform vendors building or buying AI agents for collections and customer service — they run a local demo before involving anyone else.

**Primary (commercial signal):** heads of collections / operations / risk at mid-sized NBFCs and fintech lenders facing the RBI recovery rules (1 Jan 2027) with multiple AI and human collections vendors; model-risk teams preparing for the direction of RBI's draft Model Risk Management guidance.

**Secondary:** CISOs and CTOs at private banks; AI-agent developers globally via the open-source MCP gateway (adoption channel).

**Not the target:** consumers; non-regulated SMEs; buyers wanting a GRC dashboard without runtime enforcement.

## Success criteria

**Build — definition of done**

- All 13 acceptance scenarios pass as automated tests on every PR, **20 consecutive runs without flakiness**.
- **Zero successful bypasses** of brokered resources across scenario 11 plus a garak/PyRIT run of **≥ 500 injection attempts** against the reference agent.
- Cedar analysis proves in CI: no waiver above the ceiling without `HUMAN_REVIEW`; no action on a subject other than the mandate's; no contact outside the window.
- D15 invariant test: no CEL rule can produce anything but `BLOCK` after a Cedar Deny.
- NFR-2 performance targets met on the reference hardware.
- **3 external people** each run the demo from the README in **≤ 15 minutes** without help.
- `SECURITY_PROPERTIES.md`, `THREAT_MODEL` v2 and ADR-003 to ADR-007 accepted; harness gates `privacy_guardrails_review`, `qa_review` and `compliance_review` pass on the release commit.

**Market — within 90 days of public launch**

- **Stage 2 go signal:** ≥ **1** regulated lender or lending-platform vendor requests a pilot.
- **Supporting:** ≥ **5** enterprise-type enquiries (on-prem, security questionnaire, connector requests); ≥ **3** substantive specification comments from BFSI or security organisations.
- GitHub stars and forks are tracked but are **not** a go signal.

## Privacy & guardrails considerations

**Data the MVP touches:** **synthetic only** — generated borrowers, loans, phone numbers and consent records. No real personal data in the repository, CI, images or demo.

**Data a production deployment would touch, and the minimum needed:**

- Borrower: pseudonymous subject reference; phone number resolved **inside the gateway only after authorization** and never exposed to the agent; overdue amount; EMI due date; loan reference; consent / contact-preference status.
- **Explicitly not needed for collections and blocked by the pack:** salary, other loans, contact lists, Aadhaar and PAN values.
- Agent and approver identities from the customer's own identity provider.
- Decision records: hashes and pseudonymous references only; per-subject keys with crypto-shredding; retention per pack (6 months for recovery); stored only in the customer's environment.

**Posture:** no telemetry by default (OpenTelemetry off unless the operator enables it); no phone-home; no external network calls during operation (anchoring optional and off; time sync uses operator-chosen NTP sources); self-hosted only in the MVP.

**Guardrails on every input path:**

| Input path | Guardrail |
|---|---|
| System-of-record webhook | Issuer allowlist, signature, nonce/replay protection, freshness window, schema validation, size limits |
| `/v1/authorize` and the gateway | Authenticated caller (Keycloak token), per-tool schema validation, reference-only fields, detectors, rate limits, fuzzed parsers, trusted server time only |
| Approvals console | WebAuthn step-up, action-hash binding, single-use credentials, dual control for critical packs, full admin audit |
| Pack / policy upload and activation | Signed packs, dual control (existing), Cedar analysis before activation, rollback |
| Reference agent LLM input (borrower replies, tool output) | Treated as untrusted and taints the task; **model output never gains authority** |

**Misuse surface:** the same machinery could make harassment more "efficient" if packs were misconfigured. Mitigations: recovery-pack limits cannot be loosened by a single admin (dual control); every override is recorded as evidence; public documentation states the product's purpose as constraining authority, not scaling contact.

## Out of scope

- HA/clustering, HSM/cloud KMS, air-gapped Helm (the design allows for them; Stage 2).
- Live Account Aggregator or DPDP consent-manager integration (Stage 2).
- Legacy core-banking / LOS / LMS connectors; OEM / embedded mode.
- A2A, Envoy `ext_authz` and service-mesh adapters (Stage 3).
- Indic-language detectors; organisation-wide AI discovery; red-team lab product; bias tooling beyond existing Decision Governance.
- Real telephony or WhatsApp providers — mocks only.
- Any hosted/cloud control plane; any claim of legal compliance — packs are mapped *guidance*.
- Workflows other than collections (customer service, KYC, underwriting are Stage 3).
- Public name selection, crate renaming and relicensing (separate workstreams under D1 and D5).

## Open questions

1. **Public name:** shortlist held privately. Needs formal IP India / WIPO / USPTO searches (Classes 9, 42, 45; also 35 and 36) on the final pick. When do crates get renamed from `kavach-*` — on clearance or at launch?
2. **Repository visibility:** should `TheIndicSentinel/Kavach` remain public before launch?
3. **Contributor audit for D5:** confirm authorship and copyright ownership of every commit, including those made by AI coding agents under the owner's account.
4. **Model pins:** which two Apache-2.0 models, pinned by version, after a licence check.
5. ~~**Tenant migration**~~ — resolved in ADR-005 §1–3 (tracked migrations, `tenant_id` default, existing chain becomes partition 0, hashes never recomputed).
6. ~~**Time-sync thresholds**~~ — resolved in ADR-003 §7 (kernel sync status; critical actions require `max_error ≤ 1000 ms`; explicit `allow_unverified` developer profile refused in enforce mode).

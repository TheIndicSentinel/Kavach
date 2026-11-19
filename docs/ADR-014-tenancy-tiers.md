# ADR-014: Tenancy Tiers (Managed Single-Tenant First, Pooled Later)

**Status:** Accepted (2026-10-13, with the owner's amendments: one tenant per issuer key, open question 3 answered). The model (managed single-tenant first, pooled only on demand) was approved by the owner on 2026-10-12.  
**Date:** 2026-10-12  
**Deciders:** Kavach product/engineering  
**Related:** ADR-002 (deployment), ADR-005 (evidence), ADR-007 (network boundary), ADR-008 (authentication), ADR-012 (revocation), [SECURITY_PROPERTIES.md](SECURITY_PROPERTIES.md), [SECOND_REVIEW.md](SECOND_REVIEW.md)

## Context

Kavach is meant to be sold as a service to regulated lenders. Several of them will share a deployment only if it can be shown that they cannot see or affect each other. What the code does today, checked against `main` (2026-10-12):

| Area | Today |
|---|---|
| Agent data model | Keyed by `tenant_id`: decisions, mandates, contact counters, outcomes, checkpoints. Chains are per `(tenant, partition)`, and the partition lock is per `(tenant, partition)`, so tenants never queue behind each other |
| Credit track and admin audit | `decision_events`, `admin_audit_log`, batch jobs, retention and runtime pointers have **no** `tenant_id` (migrations 001–005) |
| System-of-record issuer keys | Registered per `system` only (`SorIssuer { system, key }`). The tenant is inside the signed event but is not tied to the key that signed it |
| Consents, references | JSON files read once at startup (adapters behind the `ConsentSource` and reference-resolver ports) |
| Keys | One evidence, mandate, checkpoint and pseudonym key per stack |
| Authentication, authorization | One OIDC issuer; Cedar entities from one file; principals carry no tenant |
| Isolation backstop | `WHERE tenant_id = …` in the application. No row-level security anywhere |
| Fairness | Process-global rate limits (evidence reads, system-of-record events) |
| Metrics | No tenant label |
| Tenant check | One stack serves one tenant, and refuses a signed event for any other (400) |

So the agent path is tenant-keyed by design, and everything around it is single-tenant by construction.

## Decision

### 1. Two tiers
| | **Tier 1: managed single-tenant** | **Tier 2: pooled** |
|---|---|---|
| What | One stack per customer: its own process(es), database, keys, network and IdP configuration | One data plane for several tenants, in one process and database |
| Isolation the customer can point to | Separate database, separate keys (HSM roles), separate network, separate failure domain | Application-enforced, with row-level security as a backstop |
| Same binary | Yes | Yes, with the prerequisites in §3 |
| When | **Now.** It is what the code does | Only when the number of tenants makes Tier 1's per-stack cost the problem, **and** the prerequisites are done |

Regulated lenders will ask for Tier 1's isolation and key ownership regardless, so it is also what the first customers will want.

### 2. No-regret work, done now (each is correct in Tier 1 too)
1. **Bind each system-of-record issuer key to exactly one tenant (and one system).** A key is registered for `(tenant, system, kid)`, never for a set of tenants: a key valid for several tenants is the weakness this removes. An event whose `tenant_id` is not its key's tenant is refused. The same public key is never registered for two tenants (checked on the key material, not the `kid`), and an unknown `kid` and a wrong-tenant `kid` get the same external refusal, so the error cannot be used to find which keys exist. **Security-critical:** it has its own tests (one tenant's key signs for another and must be refused; on Postgres) and goes on the second-review list. This becomes the primary control, with the listener's served-tenant check kept as a second layer.
2. **Agent-only mode** (`--agent-only`): the agent surfaces and the evidence reads only. Default for any hosted build. The credit track is frozen.
3. **A tenant column on the admin audit log** (a constant default, so nothing is rewritten) and a **tenant label on metrics**.
4. **A tenant-isolation test suite** at the store level: two tenants in one database, every store trait, no read or count crosses. This is meaningful today and catches regressions.
5. **The migration policy** (`MIGRATIONS.md`): constraints `NOT VALID`, then `VALIDATE`.

**Progress (2026-11-19):** items 1–3 are implemented: system-of-record issuer keys bind to one tenant and system; metrics carry the configured `tenant_id`; and `admin_audit_log.tenant_id` is added with a constant `default` value, with new audit writes and tenant-scoped list/last-row reads. The two-tenant isolation suite is in progress: shared `AgentEvidenceStore` conformance verifies identical request and credential identifiers remain isolated for memory and Postgres; `CredentialBroker` conformance verifies same credential IDs and mandate revocations are tenant scoped; review snapshots, human-review approvals and agent state verify same-ID cross-tenant isolation in both adapters; checkpoint conformance verifies identical partition/chain/sequence coordinates remain independent; reference resolution verifies the same capability reference resolves to tenant-specific destinations in fixture and Postgres tests; contact preferences and consent reads verify tenant-specific projections for shared subject/channel or consent identifiers; step-up challenge reads and consumption require a tenant argument. Remaining store traits are pending. Migration policy item 5 is tracked in `MIGRATIONS.md`.

### 3. Tier 2 prerequisites (not built)
- A **per-tenant configuration store with an API**: templates, passports, issuers, consents, references, providers. Files are not a control plane.
- **Per-tenant keys**: key ids per tenant (HSM roles), so one compromise is one tenant, and destroying a tenant's pseudonym key makes its records unlinkable (tenant offboarding; whether that satisfies erasure is a legal question).
- **Tenant-scoped principals**: a tenant claim, per-tenant IdP, Cedar policies scoped by it.
- **Row-level security** keyed on a per-request session setting, so a missing `WHERE` is not a leak.
- **Fairness**: per-tenant rate limits, quotas and connection-pool budgets, and a noisy-neighbour test.
- **Per-tenant retention and archival** (the chain is append-only; archiving a segment is export, checkpoint and detach).
- **A control plane**: provisioning, upgrade and offboarding of tenants.

### 4. What is the same in both tiers
- Chains per `(tenant, partition)`; verification, bundles and checkpoints are per tenant.
- Evidence and revocation semantics (ADR-005, ADR-012).
- The guarantees in `SECURITY_PROPERTIES.md`. Tier 2 may add rows about tenant separation; it may not weaken one.

## Consequences
- **Cost and operations:** Tier 1 costs a stack and a database per customer, and N upgrades. A small control plane (Phase 3) is what keeps that manageable. This is the price of an isolation story that does not depend on a first-of-its-kind pooled implementation.
- **Nothing is rewritten for Tier 1.** The no-regret items are small, and they narrow the cross-tenant surface even there.
- **Tier 2 is a large security change set** (§3), in areas that always need a second reviewer. It is deferred until there is independent review and a reason.
- **Burden of proof:** until Tier 2 exists, the answer to "can tenant A see tenant B?" is "they do not share a process, a database or a key".

## Open questions
1. **Who operates Tier 1:** Kavach's cloud, or the customer's (bring your own cloud)? It changes the control plane, not the binary. **Left open until a design partner answers.**
2. **Residency:** an India region first. Are there per-lender residency rules beyond that?
3. **One lender's sandbox and production: two stacks (decided 2026-10-13).** Never two tenants in one stack: a shared database makes a test mistake a production incident. Sandbox and production share no process, database or key.
4. **HSM:** one per tenant, or one shared with per-tenant key labels (an HSM-vendor question).
5. **Metering and billing:** the evidence chain is a natural meter. Not designed here.

## Not addressed here
Pricing, packaging, per-subject erasure (M2), and the control plane's design.

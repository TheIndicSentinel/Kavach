# ADR-003: Agent Authorization Model, Cedar/CEL Split and Trusted Time

**Status:** Accepted  
**Date:** 2026-09-29  
**Deciders:** Kavach product/engineering  
**Related:** ADR-001 (evaluate semantics), ADR-004 (mandates), ADR-005 (evidence), ADR-006 (ports), ADR-007 (network boundary), [PRD](PRD.md) D14, D15, FR-2, NFR-2, NFR-3, NFR-7

## Context

The MVP (see [PRD](PRD.md)) extends Kavach from governing ML decision outputs (`/v1/evaluate`) to authorizing AI-agent actions. Authority for an agent action comes from a Task Mandate (ADR-004), and the decision must be deterministic, explainable and — for the most important properties — provable.

What exists today:

- **Cedar** (`cedar-policy` 4.12.0) is used only for API RBAC in `crates/kavach-auth`: one namespace `Kavach`, one hard-coded resource `Kavach::System::"api"`, `Context::empty()`, and a schema file (`policies/schema.cedarschema`) that is **never loaded or validated**.
- **CEL** (`cel-interpreter` 0.10.0) evaluates pack rules in `crates/kavach-policy/src/engine.rs`; every matching rule contributes its decision and results combine with `Decision::max` (most restrictive wins).
- **Time**: all timestamps are `DateTime<Utc>`; the client-supplied `decision_time` is trusted within ±300 s (`kavach-domain/src/request.rs:48-61`) and used for pack-effective selection. There is no time-zone handling and no clock-sync awareness. This conflicts with PRD D14 ("client/agent timestamps are never trusted").
- The frozen decision enum (`PASS / ALERT / BLOCK / HUMAN_REVIEW`) and shadow/enforce semantics are defined by ADR-001 and must not change.

The PRD requires Cedar analysis to **prove** three properties in CI (no waiver above the ceiling without `HUMAN_REVIEW`; no action on a subject other than the mandate's; no contact outside the permitted window). PRD D15 originally said Cedar answers only allow/deny and CEL maps outcomes; that wording cannot support a Cedar-provable review property. This ADR refines D15 (decision recorded with the product owner, 2026-09-29).

## Decision

### 1. A second request type on the same decision model

Introduce `AuthorizeRequest` for agent actions alongside the existing `EvaluateRequest`. Both return the ADR-001 `Decision` enum. `policy_decision` / `returned_decision` and the shadow/enforce matrix apply unchanged. Governance mode is authoritative from the agent's Passport / tool registration and can never be set by the caller.

`AuthorizeRequest` carries only what the caller can legitimately assert: authenticated agent token (ADR-007), `task_id`, tool/action identifier and raw tool parameters. Everything else — mandate, delegation chain, time, counters, taint, agent state, signals — is derived server-side.

### 2. Two Cedar policy sets

| Policy set | Namespace | Purpose |
|---|---|---|
| Existing | `Kavach` | API RBAC (unchanged in this ADR) |
| New | `Kavach::Agent` | Agent action authorization |

Agent entity types: `Agent`, `Task`, `Mandate`, `Subject`, `Tool`, `Resource`. Actions are derived from each tool registration's action map (e.g. `contact`, `read_fields`, `propose_plan`, `update_status`). The Cedar resource is the typed subject or resource reference the action targets (ADR-004 §7).

### 3. Context is computed server-side only

The Cedar context record contains:

| Field | Source |
|---|---|
| `mandate` projection (subject, purpose, channels, allowed data fields, ceilings, window) | Verified, active mandate (ADR-004) |
| `delegation.depth`, `delegation.chain` | Mandate store |
| `params` (typed, extracted) | Gateway extraction against the tool's parameter schema (ADR-007) |
| `ist_minute_of_day`, `ist_date` | Trusted time (§7–8) |
| `counters` (e.g. contacts today for this subject) | Server-side counters keyed by `ist_date` |
| `task_tainted`, `agent_state` | Risk state (PRD FR-5) |
| `signals` | Detectors (cheap, synchronous) |
| `approval_valid` | True only if an approval exists that is bound to this request's exact `action_hash` (PRD D17) |

No field is copied from the agent's request other than the extracted `params`.

### 4. Schema validation is mandatory

The agent policy set ships with a `.cedarschema`. Kavach runs Cedar's validator in **strict** mode at startup and on every policy activation; startup or activation fails on any validation error. (Retrofitting schema validation to the existing API RBAC set is a follow-up — see Consequences.)

### 5. Outcome mapping (refines PRD D15)

```
Cedar result
  ├── Allow ───────────────────────────────► CEL stage
  ├── Deny, and EVERY determining policy
  │   is annotated @escalate("human_review") ► HUMAN_REVIEW
  └── any other Deny ──────────────────────► BLOCK

CEL stage (only after Allow):
  pack rules may raise the outcome to ALERT / HUMAN_REVIEW / BLOCK
  combined with Decision::max (existing)

Final decision = most restrictive of the above.
Invariant: CEL can never downgrade a Cedar outcome.
```

Escalation rules are expressed as Cedar `forbid` policies that are lifted by a valid, action-bound approval. Illustrative:

```cedar
@id("waiver-ceiling")
@escalate("human_review")
forbid (principal, action == Kavach::Agent::Action::"propose_plan", resource)
when   { context.params.waiver_pct > context.mandate.ceilings.waiver_pct }
unless { context.approval_valid };

@id("subject-binding")
forbid (principal, action, resource)
when { resource != context.mandate.subject };
```

A request that trips both an `@escalate` forbid and an unannotated forbid is `BLOCK`.

### 6. Provable properties in CI

Cedar policy analysis runs in CI and must prove, for the shipped agent policy set:

1. `propose_plan` with `waiver_pct > ceiling` is never `Allow` unless `approval_valid`.
2. Any action whose resource ≠ `context.mandate.subject` is `Deny`.
3. `contact` with `ist_minute_of_day` outside the mandate window is `Deny`.

A separate test proves the §5 invariant: for every CEL rule set in the shipped packs, no input yields an outcome less restrictive than the Cedar outcome.

### 7. Trusted time

Introduce a `TimeSource` port (ADR-006) returning:

```
TrustedNow { utc: DateTime<Utc>, sync: Synced { max_error_ms } | Unsynced | Unknown }
```

- **Linux adapter** reads the kernel clock-sync status (`ntp_adjtime`/`adjtimex`: `STA_UNSYNC` flag and `maxerror`). A fake clock is the test double.
- **Default policy:** critical actions require `Synced` with `max_error_ms ≤ 1000` (configurable). Otherwise they fail closed (`BLOCK`, incident recorded).
- **NTP sources** are chosen by the operator; documentation recommends NIC/NPL servers as referenced in the CERT-In Directions (2022). Kavach itself makes no outbound time calls.
- **Developer profile:** where kernel status is unavailable (e.g. Docker Desktop on macOS), `time.allow_unverified = true` may be set. It is **refused at startup if any agent resource is in enforce mode**, and every evidence record written under it carries `time_sync = "unverified"`.

### 8. Business windows and the evaluate path

- Windows are computed with `chrono-tz` (`Asia/Kolkata`) and passed to Cedar as integers (`ist_minute_of_day`, `ist_date`). No dependency on Cedar's datetime extension.
- Agent-supplied timestamps are ignored entirely.
- **Existing `/v1/evaluate`:** `decision_time` remains accepted, validated (skew check) and recorded for compatibility, but pack-effective selection and any time-based rule evaluation move to trusted server time. This is a documented behaviour change with no schema change (see Consequences).

### 9. Hot path versus asynchronous work

| Synchronous (per request) | Asynchronous |
|---|---|
| Identity (cached JWKS) → Passport (cached) → mandate signature + status (cache invalidated by events) → parameter extraction → cheap detectors → Cedar → CEL → minimal evidence write (critical actions only, ADR-005) → credential issuance | Evidence enrichment, reporting, metrics, analytics, regulatory mapping |

### 10. Reference hardware and benchmarks

Reference hardware for PRD NFR-2: 4 CPU cores, 16 GB RAM, local PostgreSQL 16. `authorize` is benchmarked with `criterion` (in-process p99 < 5 ms); gateway overhead with `oha` (MIT) load tests (p99 < 15 ms including the minimal critical evidence write; 1,000 requests/s single-node baseline). Benchmarks run in CI on every release branch.

## Consequences

- Agent decisions are explainable (determining policy IDs + CEL rule hits) and the three core safety properties are machine-proven rather than only tested.
- D15 in the PRD is updated to the §5 wording.
- **Follow-ups found during exploration:**
  - Load and validate `schema.cedarschema` for the existing API RBAC policy set.
  - Enforce CEL `max_alloc_bytes` (declared in the pack schema but not enforced) or remove the field.
  - Add a note to `DECISION_EVENT_COMPAT.md` describing the §8 evaluate-path time change.
- Developer experience on macOS requires the explicit `allow_unverified` profile; production deployments must run on hosts with kernel clock-sync status.

## References

- [PRD](PRD.md) D14, D15, D17, FR-2, FR-5, NFR-2, NFR-3, NFR-7
- ADR-001 §1, §3, §5 (decision enum, sync semantics, shadow vs fail-closed)
- `crates/kavach-auth/src/lib.rs`, `crates/kavach-auth/policies/`
- `crates/kavach-policy/src/engine.rs`
- `crates/kavach-domain/src/request.rs` (`check_clock_skew`)
- Cedar policy language and validator documentation
- CERT-In Directions under section 70B(6) of the IT Act (28 April 2022) — clock synchronisation

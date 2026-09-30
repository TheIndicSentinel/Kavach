# ADR-011: Mandate and Agent-Authorization Hardening

**Status:** Accepted  
**Date:** 2026-10-01  
**Deciders:** Kavach product/engineering  
**Related:** ADR-003, ADR-004, ADR-006, [SECURITY_PROPERTIES.md](SECURITY_PROPERTIES.md)

## Context

A review of `kavach-mandate` and `kavach-authz` (H4, before agents are reachable over HTTP in H5) found that:

- one permit mapped unknown actions to `update_status`;
- missing or negative parameters were allowed: a plan with no waiver defaulted to 0, empty field lists passed, and a negative waiver passed;
- a mandate without a window could contact a borrower at any hour, with no daily cap;
- verification checked only the leaf mandate, not its ancestors;
- revoke and delegate could race, leaving an active child under a revoked parent;
- configuration was never validated.

## Decision

### 1. One permit per action, derived from the schema
- Each of the five actions has its own permit, naming it with `action == ...`.
- `AgentAuthorizer::new` reads the actions from the schema and refuses policies unless every action has exactly one such permit. Unconstrained or `in` permits are refused, so a new action cannot inherit another's rights.
- CI proves, per action, that an allow implies the mandate lists that action, and that only the holder is ever allowed.

### 2. Missing or invalid parameters are unrepresentable or forbidden
- The context carries `has_waiver`, `has_channel` and `has_requested_fields`. A plan without a waiver, a contact without a channel, and a field read without fields are each **BLOCK**. A plan with no waiver must send `waiver_bps: 0`; the H5 tool schema makes it required.
- Waivers outside `0..=10000` bps are BLOCK.
- `contacts_today` is `u32` in Rust. Cedar also forbids a negative count, as defence in depth.

### 3. Contact floor
- `send_reminder` and `place_call` are forbidden outside **08:00–19:00 IST** and forbidden when the mandate has no window. The floor does not apply to non-contact actions.
- The values are `CONTACT_FLOOR_*` in `kavach-domain`. A test evaluates the shipped policy at 07:59, 08:00, 18:59 and 19:00 against those constants.
- Templates and delegation windows may only narrow the floor. Configuration and issuance refuse contact actions without a window.
- *Source:* RBI directions on recovery agents' contact hours. **Pending compliance sign-off**; treat as guidance. Widening the floor needs a policy change and a proof update.

### 4. Whole-chain verification
`verify_active` loads the chain in one `MandateStore::ancestors` call, bounded by the depth cap (4). For the mandate and every ancestor it checks:
- the signature, and that the stored value equals the signed token;
- stored status `Active`;
- trusted time within `[nbf, exp)`;
- for each link: `parent_id`, `depth == parent.depth + 1` and `is_within`.

The chain must end at a root; a missing parent is a rejection.

### 5. Store invariant and atomic operations
*A mandate is `Active` only if every ancestor is `Active`.* The port provides:
- `insert_child`, which inserts only while the parent is active, atomically with that check;
- `revoke_tree`, which revokes the whole subtree in one operation.

`revoke` returns `{revoked, publish_errors}`: the revocation is committed even when an event fails to publish. Until an outbox exists, short credential TTLs are the backstop.

A shared conformance suite in `kavach-ports-testkit` includes delegation racing revocation. It is written to the contract, and the H5 Postgres store must pass it in CI.

### 6. Delegation
- A child can re-delegate only to agents named in the delegation request **and** allowed by the parent. By default it cannot re-delegate.
- `is_within` also checks: the holder is allowed by the parent, the child's `max_depth` and `allowed_agents` narrow the parent's, `nbf` does not precede the parent's, and `parent_id` is correct.

### 7. Configuration validation (`MandateService::new`)
`MandateService::new` refuses:
- duplicate templates or passports;
- a TTL outside 1 second to 30 days;
- channels outside `sms`, `voice`, `whatsapp`;
- windows outside the floor, or with `max_per_day = 0`;
- contact actions without a window or channel;
- negative ceilings, or basis-point ceilings above 10000;
- `max_depth` above 4;
- agents without passports;
- template scope beyond eligible agents' passports.

## Consequences
- Agents cannot contact borrowers outside 08:00–19:00 IST or without a window, whatever a template says.
- Operators cannot ship an invalid template; it fails at startup rather than at request time.
- The store contract is fixed before the Postgres store is written.

## Not addressed here
- `by_agent` (the delegating agent) and `contacts_today` are caller-supplied until H5 derives them from authenticated agent identity and stored counters. **Until then they are unsafe inputs.**
- For asynchronous channels, authorisation at 18:59 may not mean delivery by 19:00. H5 should attach a send-by deadline to the credential or obligation. This is a hypothesis to validate against provider behaviour.
- Event delivery has no outbox yet (P1).

# ADR-013: Agent Kill Switch (Restrict, Quarantine, Revoke)

**Status:** Accepted (with the owner's amendments, 2026-10-06)  
**Date:** 2026-10-06  
**Deciders:** Kavach product/engineering  
**Related:** ADR-008 (authentication), ADR-009 (change requests), ADR-012 (revocation), PRD FR-5 and FR-9, OWASP Agentic ASI10 (rogue agents)

## Context

PRD FR-5 defines agent states `ACTIVE / RESTRICTED / QUARANTINED / REVOKED`, and FR-9 includes "quarantine or manual kill" among the triggers that revoke mandates. The Cedar agent policy already has `agent-restricted`, which forbids every action when the agent's state is not `Active`, and `RevocationReason` has `AgentQuarantined`. But:

- the API hard-codes every agent's state to `Active` (`dataplane.rs`, two places);
- no store, route or command can change it;
- so a rogue or compromised agent can only be stopped by editing configuration and restarting.

## Decision

### 1. A store for agent states
- **Postgres:** `agent_states (tenant_id, agent_id, state, reason, changed_by, approved_by, changed_at)`. The memory store mirrors it for development.
- **Default:** an agent with no row is `active`.
- **Reads:** at every authorization, so there is no cache and nothing to propagate to other replicas.

### 2. What each state means
| State | Effect |
|---|---|
| `active` | As today |
| `restricted` | No `external_effect` tool: no contact, no call, no proposal (a recorded BLOCK, `agent-restricted`). Reads stay limited to what the mandate grants |
| `quarantined` | Every action is a recorded BLOCK and **no credential is minted**. The agent's mandates are **suspended, not revoked**: they and every mandate delegated from them stop authorising anything while any holder in the chain is quarantined, and work again when it is reinstated. Revocation cascades and cannot be undone; lifting a quarantine must not need the system of record to re-issue everything |
| `revoked` | As quarantined, and final: the agent's mandates are **revoked** (reason `Manual`, through `revoke_tree`, cascading to delegations). It cannot be reinstated: a new passport, with a new agent id, is the way back |

The Cedar policy changes from "not active → forbid all" to the table above. That's a policy change, proved by the existing Cedar analysis job (cvc5).

**Suspension through the chain.** Authorization already verifies a mandate's whole chain (ADR-011). It now also reads the state of every holder in the chain: a mandate whose own holder, or any ancestor's holder, is quarantined or revoked authorises nothing. Nothing is written to the mandates, so reinstating restores them exactly.

### 3. Asymmetric controls
- **Stopping:**
  - `restrict`, `quarantine` and `revoke` take **one admin**, take effect immediately, and need a reason;
  - they go through the operator API (Cedar action `stop_agent`) and are audited;
  - they make things safer, and in an incident speed matters.
- **Reinstating:**
  - `restricted → active` and `quarantined → active` re-grant authority, so they go through **maker-checker**: an ADR-009 change request of kind `reinstate_agent`, approved by a different principal;
  - `revoked` can't be reinstated.

### 4. Surfaces
- **Operator API:**
  - `POST /v1/agents/{agent_id}/restrict | quarantine | revoke`, with `{ "reason": … }`;
  - `GET /v1/agents/{agent_id}`;
  - reinstatement through `/v1/change-requests`.
- **CLI:**
  - `kavach agent status | restrict | quarantine | revoke <agent>`;
  - `kavach agent reinstate <agent>`, which proposes the change.
- **Evidence:**
  - every decision for a non-active agent carries the signal `agent_state:<state>`, in the existing `signals` field;
  - **every state change is a signed record in the agent evidence chain**, of a new kind `agent_state`: the agent, the old and new state, the reason, who changed it, and for a reinstatement who approved it. It is hash-chained and checkpointed like decisions, and exported and verified with them. This adds a record kind to the bundle format, documented in `EVIDENCE_BUNDLE.md`, and verifiers that do not know the kind refuse the bundle rather than skip it.
  - Each change is also an admin audit entry, as for every operator action.

### 5. Simulation and attacks
- **`kavach simulate`:** a scenario in which a rogue agent is quarantined mid-run. Its later calls are BLOCKs (and a sub-agent's under its delegated mandates too), other agents are unaffected, and after reinstatement its mandates work again. The oracle models agent states.
- **Attack catalog:**
  - `quarantined-agent-acts`: refused;
  - `restricted-agent-contacts`: refused;
  - `reinstate-without-approval`: refused, because one principal can't approve its own reinstatement.

### 6. How fast a stop takes effect
- **Every replica, from the next call.** The state is read from the database at every authorization: no cache, nothing to propagate.
- **A call already past authorization** is caught by the gateway's re-check just before it forwards (ADR-012 §5): the agent's state is read again there.
- **The outer bound:** a resource credential already minted lives at most 15 seconds and is single-use. No credential outlives a stop by more than that. This bound is documented in SECURITY_PROPERTIES.

## Consequences

- An incident responder can stop an agent in one call, with no restart. It stays stopped across replicas and restarts, because the state lives in the store. Quarantine is reversible without the system of record; revocation is not.
- One more store read per authorization: a primary-key lookup.
- A wrongly stopped agent needs two people to bring back. That's deliberate, and the reason is recorded.
- SECURITY_PROPERTIES gains a row: "a quarantined agent can do nothing, from the next call, on every replica; bringing it back takes two principals".

## Not addressed here

- **Automatic quarantine** on attack signals (anomaly thresholds, repeated refusals): this ADR provides the switch, and a later one decides what may throw it automatically.
- **Taint (FR-5's per-task taint and `HUMAN_REVIEW`):** separate work.
- **The console's controls:** after the API and CLI.

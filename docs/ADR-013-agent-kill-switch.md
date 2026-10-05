# ADR-013: Agent Kill Switch (Restrict, Quarantine, Revoke)

**Status:** Proposed  
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
| `restricted` | Only `read_only` tools (`read_fields`); every external effect (contact, call, proposal) is a recorded BLOCK (`agent-restricted`) |
| `quarantined` | Every action is a recorded BLOCK, and **the agent's live mandates are revoked** (`AgentQuarantined`, through ADR-012's `revoke_tree`). Reinstating does not bring them back: the SoR issues new ones |
| `revoked` | As quarantined, and final: it cannot be reinstated. A new passport, with a new agent id, is the way back |

The Cedar policy changes from "not active → forbid all" to the table above. That's a policy change, proved by the existing Cedar analysis job (cvc5).

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
- **Evidence:** every decision for a non-active agent carries the signal `agent_state:<state>`. `signals` is an existing field, so the evidence format doesn't change. State changes are audit entries.

### 5. Simulation and attacks
- **`kavach simulate`:** a scenario in which a rogue agent is quarantined mid-run. Its later calls are BLOCKs, its mandates are revoked, and other agents are unaffected. The oracle models agent states.
- **Attack catalog:**
  - `quarantined-agent-acts`: refused;
  - `restricted-agent-contacts`: refused;
  - `reinstate-without-approval`: refused, because one principal can't approve its own reinstatement.

## Consequences

- An incident responder can stop an agent in one call, with no restart. It stays stopped across replicas and restarts, because the state lives in the store.
- One more store read per authorization: a primary-key lookup.
- A wrongly stopped agent needs two people to bring back. That's deliberate, and the reason is recorded.
- SECURITY_PROPERTIES gains a row: "a quarantined agent can do nothing, from the next call, on every replica; bringing it back takes two principals".

## Not addressed here

- **Automatic quarantine** on attack signals (anomaly thresholds, repeated refusals): this ADR provides the switch, and a later one decides what may throw it automatically.
- **Taint (FR-5's per-task taint and `HUMAN_REVIEW`):** separate work.
- **The console's controls:** after the API and CLI.

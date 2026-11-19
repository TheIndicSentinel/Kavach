# High-availability reference plan

**Status:** Approved direction; implementation in progress (2026-11-19). The owner approved an active/passive API topology with one Postgres writer. This plan records the state boundaries and gates that must be complete before a multi-instance deployment is enabled.

## Scope and limits

- Keep Kavach a modular monolith. Run one active `kavach-api` process and one warm standby against the same Postgres primary. The standby receives no application traffic until promoted.
- This reference covers API process failure only. Postgres, the load balancer, the IdP and host failure are not made highly available by adding an API standby. Do not describe the result as production HA until those dependencies and recovery objectives are separately addressed.
- Do not enable two active API instances until replay protection, console failover behavior, runtime-pointer convergence, single-active fencing, readiness and failover tests are complete.
- A database-backed process uses the same configured tenant and signing/encryption keys. Postgres remains the single serialization point for governed writes and evidence.

## Process state and failover behavior

| State | Current storage | HA behavior required |
|---|---|---|
| HMAC `/v1/evaluate` nonce | Process-local cache | Database-backed instances reserve tenant-scoped nonces in the shared Postgres replay guard. An unavailable guard refuses the request. Memory development mode remains process-local. |
| OIDC login transaction and console session tokens | Process memory (`ADR-018`) | Keep tokens out of Postgres and files. A promoted process cannot resume a session from the failed process; the operator signs in again. Never extend token/session lifetime during failover. |
| In-progress D17 OIDC step-up flow and session-bound proof | Process memory, bound to the console session | Failover invalidates an incomplete ceremony and any unconsumed session-bound proof. The reviewer signs in and completes a new exact-action step-up. |
| Durable D17 challenge, review snapshot, approval and release | Postgres in database-backed mode | Preserve existing one-use and exact-action checks across processes. A release remains bound to its original request, action hash and execution ID. |
| Runtime pack/model pointers and loaded evaluators | Postgres pointer plus each process's in-memory evaluator | Before enabling replicas, every process must detect and apply committed pointer changes, validate the loaded assets, and stop serving governed requests while stale or unable to converge. |

The API standby must not accept traffic until it is promoted. Once promoted, an old session cookie is unauthorized on the new process and the console directs the operator to sign in again. This follows ADR-018's rule that OIDC tokens remain process memory only; this plan does not relax that rule to persist secrets for failover.

## Implementation order

1. **Shared HMAC replay guard — implemented in this slice.** Use the existing tenant-scoped Postgres `ReplayGuard` for database-backed `/v1/evaluate`; namespace HMAC keys; retain the bounded in-memory cache only without Postgres. Fail closed if the database reservation fails. Purge expired reservations opportunistically on a bounded interval.
2. **Session and step-up failover semantics — verified in this slice.** A promoted process returns 401 for a session cookie it did not issue; operators sign in again. In-progress callback secrets and verified step-up proofs stay bound to the original process session and cannot be used after promotion. The durable challenge may remain until its short expiry, but cannot authorize without those secrets and that session. Completed approvals/releases remain shared and single use in Postgres. Do not persist OIDC tokens.
3. **Runtime-pointer convergence — in progress.** A one-second background watcher and runtime-dependent pack/model catalog, change-request, retention, batch-job, decision-event, and evaluation routes compare the shared pointer version. A newer pointer triggers validation of the pinned pack/model bytes, configured signatures, and governed model state before swapping the evaluator. Backward movement, read errors, or invalid assets refuse the request. Postgres-backed replica coverage verifies lagging processes reload after an approved pack activation. Agent evidence/revocation reads remain on their independent data plane. Gating incident, audit, and other governed routes is pending. Keep maker-checker pointer-version checks authoritative.
4. **Active/passive fencing and readiness.** Ensure only the promoted process serves application traffic and that a former active cannot continue writing after promotion. Provide a readiness signal that includes the dependencies needed for safe serving; liveness remains separate.
5. **Reference deployment and fault tests.** Supply an on-prem, free/open-source active/passive example and exercise active failure, promotion, stale process fencing, database loss, pointer change, and recovery. Record observed failover and data-loss behavior; make no unmeasured SLO claims.

## First slice verification

`crates/kavach-api/tests/hmac_postgres.rs` races two independently selected HMAC stores against one Postgres database using the same signed nonce. Exactly one request succeeds and the other receives 401. API unit coverage verifies signature binding, timestamp bounds, and replay refusal in memory mode. Postgres failure maps to 503 rather than accepting the request without replay protection.

The console-login tests also send a valid active-process cookie to a fresh API state and assert 401, and prove that a new process cannot read the old session, pending step-up callback secrets, or verified proof. Existing Postgres human-review tests verify that completed releases remain durable under concurrent retries and retain one exact execution record.

The runtime-pointer unit test supplies an invalid newer pointer and confirms `/v1/evaluate` returns 503 without evaluating. A watcher test confirms a process converges without waiting for an evaluation request and exits on the shared shutdown signal. The Postgres replica test confirms retention settings/tombstone reads, batch-job listing, decision-event reads, change-request listing, pack/model list/detail routes, and evaluation converge to an approved pack activation; `/v1/runtime` then reports `pointer_drift: false`. HTTP and gRPC evaluations use the same asynchronous convergence path; incident, audit, and remaining governed routes are pending.

## References

- [ADR-002](ADR-002-deployment-architecture.md): modular monolith and one shared Postgres.
- [ADR-008](ADR-008-api-authentication.md): HMAC v2 scope and request signature.
- [ADR-009](ADR-009-change-requests.md): runtime-pointer versioning and current replica drift behavior.
- [ADR-018](ADR-018-console-login-and-token-storage.md): process-memory-only OIDC tokens and session lifetime.
- [Security properties](SECURITY_PROPERTIES.md): current guarantees and known replica-convergence limitation.

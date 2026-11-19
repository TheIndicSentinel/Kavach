# HA active/passive fencing plan

**Status:** Approved; implementation in progress (2026-11-19). The owner approved the Postgres epoch lease, token-hash write guards, self-fencing after renewal failure, and 3-second renewal/10-second expiry defaults. The first storage slice adds lease claim and renewal primitives; API activation and write guards remain gated on later slices.

## Goal

For the approved one-active/one-standby API topology, promotion must make the former active unable to commit any later Postgres write, including a transaction already in flight when promotion begins. `/ready` must be false for a process that does not hold the current fence.

## Recommended mechanism: Postgres epoch lease with write guards

Use Postgres as the serialization point. Do not rely on a process-local flag or a session advisory lock alone: a process can lose its lock connection while other pooled connections remain able to write.

1. Add one owner-controlled lease row per tenant with `holder_id`, a monotonically increasing `epoch`, a SHA-256 hash of a random 256-bit process token, and `lease_expires_at`.
2. A process claims an absent or expired lease in one transaction using Postgres `clock_timestamp()`. A successful claim increments `epoch`; the process keeps the raw random token only in memory. The runtime database role cannot read or update the lease row directly.
3. The active renews every 3 seconds with a 10-second lease. A renewal must match both holder ID and token hash. After a renewal failure, the process permanently self-fences for that run and does not reclaim automatically; restart is required. A standby may claim only after expiry.
4. Each runtime database connection sets the current holder ID and token hash from process memory. `BEFORE INSERT/UPDATE/DELETE` triggers on every table writable by the API call a `SECURITY DEFINER` check that matches those values to the live lease row and locks that row `FOR SHARE` for the transaction. The app role cannot read the row or mint a new token.
5. Promotion updates the lease row and therefore waits for older write transactions holding the share lock to finish. Once promotion commits, a former active's next write fails its trigger check. This gives the promotion commit a clear fence boundary.
6. Readiness requires a successful renewal and a current epoch. On loss, the local process stops accepting application requests; `/health` remains liveness only. Standby readiness becomes true only after a successful claim and validated runtime convergence.

The migration must enumerate every table the runtime role can mutate, including evidence, incidents, batch jobs, change requests, role state, replay nonces, human-review state, consent/reference state, and agent records. Add a migration test that compares the trigger inventory with runtime-role write grants so a later writable table cannot silently skip fencing. Owner/superuser access remains outside this guarantee, consistent with the existing database-owner threat boundary.

## Failure behavior

- Postgres loss or an unrenewable lease: the active reports not-ready and refuses new application requests.
- Active process exit or loss of its DB session: its lease expires; a standby can claim a higher epoch.
- A former active that reconnects after promotion: it retains only the old token and epoch, so trigger-guarded writes fail. It must restart to compete for a future lease.
- Promotion while a write is in flight: promotion waits for that transaction to commit/abort; no former-owner transaction can commit after the new epoch is installed.
- No HA mode configured: existing single-instance behavior remains unchanged.

## Verification before enabling replicas

- Two processes cannot own the same tenant lease concurrently.
- A healthy standby is not ready and cannot serve application routes.
- Lease loss makes the active not-ready; it cannot silently reacquire in the same run.
- After expiry, standby promotion increments the epoch and is ready only after pointer convergence.
- The former active cannot write to every guarded store after promotion.
- Promotion waits for a deliberately held old write transaction; after promotion commits, new old-owner writes fail.
- Postgres loss, process kill, restart, and recovery preserve the expected fence and evidence behavior.
- Single-instance mode and current Postgres runtime grants continue to pass their existing tests.

## Proposed defaults

Use a 3-second renewal interval and a 10-second expiry, both measured by Postgres time. These bound normal failover detection to at most 10 seconds plus promotion and pointer convergence, without making an SLO claim. If the deployment needs different values, make them explicit configuration and test the selected values.

## Slice record

1. **Lease storage primitives — implemented.** Migration 039 creates owner-controlled lease rows and `SECURITY DEFINER` claim/renew functions. The runtime role can execute only those functions, cannot read or edit the table, and receives monotonically increasing epochs on expired-lease takeover. `crates/kavach-storage/tests/postgres_active_lease.rs` covers concurrent claims, token-bound renewal, expiry takeover, old-holder rejection, and table privilege isolation. This slice does not yet activate API leases or fence application writes.

2. **API lease lifecycle — pending.** Generate an ephemeral process token, hash it, claim once at startup, renew on the approved interval, and permanently self-fence on failure.
3. **Write fencing — pending.** Bind lease identity to runtime connections and guard all runtime-writable tables transactionally; verify trigger inventory against grants.
4. **Readiness and lifecycle integration — pending.** Gate application routes/readiness on lease ownership while preserving liveness and non-HA single-instance mode.
5. **HA reference deployment and fault tests — pending.** Complete the scenarios and deployment example in `HA_REFERENCE_PLAN.md` before enabling replicas.

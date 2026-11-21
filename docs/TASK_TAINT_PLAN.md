# FR-5 task taint implementation plan

**Status:** proposed; owner approval needed for the task boundary and persistence contract before implementation. This plan is limited to the existing PRD FR-5 and acceptance scenario 2. It does not change the approved requirement.

## Current gap

The authorization core always supplies `task_tainted: false` to Cedar. The registry has no `external_untrusted` or `user_content` trust labels, the agent request has no task correlation field, and the gateway has no persisted taint state. The existing raw-identifier detector independently blocks a raw phone number in a reference-only field, but it does not taint other actions in the same task.

## Recommended contract

1. Treat a verified mandate ID as the task key. Mandates are the server-issued, tenant-bound authority for the task; the client must not be able to clear or select a different taint key independently of its mandate. Child mandates inherit taint from their parent task.
2. Mark the task tainted after Kavach returns content from a governed model invocation. Model output is untrusted even when the prompt's provenance is unknown. A future tool registry may additionally classify returned tool content as `external_untrusted` or `user_content`; only such explicitly classified content taints a task. Do not infer taint from caller-supplied flags.
3. Persist taint monotonically in Postgres for database-backed deployments and in the memory store for development/tests. A taint write must complete before untrusted content is returned to the agent; on write failure, return no content and fail closed. A later clean response cannot clear taint.
4. On every subsequent action under that task, derive `task_tainted` from the server-side store. The existing Cedar policy escalates critical `propose_plan` and `update_status` actions to `HUMAN_REVIEW`; non-critical actions retain existing policy behavior. Existing mandate and parameter checks remain authoritative, so taint never expands authority.
5. Do not store prompt/completion text or raw tool content. Persist only tenant, task/mandate identifier, first-tainted timestamp, and a bounded source category; expose the taint through signed evidence without the content.

## Implementation sequence

1. Add a typed task-taint port and memory/Postgres stores with monotonic/idempotent `mark_tainted` and read operations; add a tracked migration and least-privilege grants.
2. Wire governed model invocations to mark taint before returning the completion; fail closed if the taint write fails.
3. Feed stored task taint into every authorization path, including precheck and exact-action approval/release, and record the derived risk state in evidence.
4. Add a test-only user-content tool fixture and complete acceptance scenario 2: taint survives subsequent calls, clean content cannot clear it, critical action escalates, wrong mandate cannot read another task's taint, and taint-store failure never releases content or an external effect.
5. Update PRD status, acceptance matrix, ADR-003 context, and `SECURITY_PROPERTIES.md` in the implementation change. Run memory and real-Postgres tests.

## Implementation record

- **Slice 1 complete (2026-11-21):** added the typed `TaskTaintStore` port, a memory adapter, and a Postgres adapter. Migration 051 stores only tenant, mandate/task key, first-tainted timestamp and bounded source; `kavach_runtime` receives `SELECT, INSERT` only. The table is included in the active/passive HA write fence. Memory and least-privilege Postgres integration tests passed against a disposable local PostgreSQL cluster. The Postgres test also confirms runtime cannot update or delete taint. No request path reads or writes this store yet; FR-5 enforcement is not complete.
- **Next:** wire governed model completions to persist taint before returning response content, with fail-closed behavior on storage errors.

## Decision needed

Please approve or change the recommended task boundary (mandate ID, inherited by child mandates) and the conservative rule that every governed model completion taints its task. These choices determine cross-request behavior and the persistence schema. Until decided, the code continues to fail closed on existing raw-identifier violations but does not claim FR-5 task-taint enforcement.

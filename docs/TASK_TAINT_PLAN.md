# FR-5 task taint implementation plan

**Status:** implementation in progress; task boundary and conservative model-output taint rule approved by the owner on 2026-11-21. This plan is limited to the existing PRD FR-5 and acceptance scenario 2. It does not change the approved requirement.

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
- **Slice 2 complete (2026-11-21):** successful `/v1/models/{role}/invoke` responses now mark the signed invocation's mandate task as `governed_model_output` tainted before response content is returned. Missing trusted time or a failed store write returns 503 without returning content. A focused route test verifies a completed model output taints only its mandate task, while an invalid mandate creates no taint. The legacy `/proxy/*` path is unchanged and remains ungoverned. Taint is not yet read by authorization or Cedar, so this does not complete FR-5 critical-action escalation.
- **Slice 3 complete (2026-11-21):** API authorization paths now derive taint only after verifying the presented mandate chain and confirming the authenticated agent is its leaf holder. A taint on any mandate in the verified parent chain applies to the current task. Precheck, commit, exact-action release, and governed model authorization receive this server-derived value; callers cannot set it. Cedar escalates critical tainted actions to `HUMAN_REVIEW`, and the derived risk appears as a bounded `task_tainted` signal/reason in signed decision evidence. Focused dataplane and API route tests passed for precheck, signed commit evidence, and escalation.
- **Slice 4a complete (2026-11-21):** added a synthetic test-only `user_content` store fixture and verified it drives critical-action review; a later clean/model source cannot replace or clear the first taint. API coverage now uses a second, separately issued valid mandate and verifies it cannot read the tainted task, while the original task's taint persists through a later precheck and commit. Focused dataplane and API tests passed. This does not add production tool-content classification.
- **Slice 4b complete (2026-11-22):** centralized the fail-closed gates used by the model response and authorization/effect paths. An unavailable taint write maps to 503 before model content is returned; an unavailable taint lookup maps to 503 before authorization or gateway execution. Injected-error unit tests passed, along with the successful governed-model route regression test. Route-level store fault injection and an assertion against the external-effect fixture remain unverified.
- **Slice 4c complete (2026-11-22):** added a `test-support`-only failure injector to the in-memory taint store. Route tests now inject a write failure and verify `/v1/models/.../invoke` returns 503 without completion content, and inject a read failure and verify `/v1/tools/...` returns 503 with an empty mock-provider inbox. Both route tests passed. This verifies the memory-backed API path; a live Postgres fault drill is not included.
- **Slice 5a complete (2026-11-22):** added a regression assertion that a tainted task with a subject outside its mandate remains `BLOCK`; taint does not widen the subject binding. Existing Cedar checks also retain field-scope and waiver constraints.
- **Slice 5b complete (2026-11-22):** the owner approved clarifying FR-5 as preserving the existing verified mandate and parameter checks, with taint adding `HUMAN_REVIEW` only to eligible critical actions. PRD and acceptance wording now match this contract; no policy behavior changed.
- **Slice 6 complete (2026-11-22):** added a Postgres-backed API route test using an isolated schema and least-privilege runtime credentials. The test issues a mandate after a signed consent grant, invokes the governed model, verifies persisted task taint, then confirms a subsequent critical-action precheck returns `HUMAN_REVIEW`. The focused test passed against a disposable local PostgreSQL cluster; cleanup completed. This verifies the healthy Postgres API path, not a database-outage fault drill.
- **Slice 7 complete (2026-11-22):** the Postgres API test now revokes only the runtime role's `INSERT` privilege on the isolated taint table, then invokes the governed model. The route returns 503 without model content; the test restores the grant before completion. The focused test passed against a disposable local PostgreSQL cluster, which was cleaned up.
- **Slice 8 complete (2026-11-22):** a Postgres API test revokes only the runtime role's `SELECT` privilege on the isolated taint table. A valid model request returns 503 before the fake upstream is called; the test restores the grant. The focused test passed against a disposable local PostgreSQL cluster, which was cleaned up.

## Approved decisions

- **2026-11-21:** use mandate ID as the task key; child mandates inherit taint from their verified parent chain.
- **2026-11-21:** every governed model completion taints its task, regardless of prompt provenance.
- **2026-11-22:** preserve existing verified mandate subject/action/parameter checks; taint adds review and never overrides a `BLOCK`.

## Remaining work

- Add production classification of inbound borrower/user tool content under the approved trust labels when an inbound tool-output path is introduced. The current registry has no such response path; the test-only `user_content` fixture covers the store and authorization behavior. Postgres read/write denial is covered at the model route; a full database-outage drill remains optional follow-up coverage.

# Service-Level Objectives (single instance)

**Status: Draft.** Proposed objectives for the owner to review. **Nothing here is measured.** Every target is labelled "proposed, not measured", and every number in angle brackets (`<…>`) is a placeholder for the owner to set; none of them is a figure Kavach has achieved. No latency or throughput figure is quoted here: those belong to [PERFORMANCE.md](PERFORMANCE.md), which has no published numbers yet.

**Scope.** One `kavach-api` process with one Postgres, which is the deployment decided for now (high availability is an open decision). The objectives cover four things: the authorization path being available, failing closed, the durability of evidence, and how fast a kill-switch change takes effect. They do not restate the security properties ([SECURITY_PROPERTIES.md](SECURITY_PROPERTIES.md)); they say how an operator would see whether those properties are being exercised and whether the service is up.

Every service-level indicator (SLI) below is built from a signal the code already exposes, named with the file it comes from. Where a useful indicator needs a signal that does not exist, the doc says **not built**.

## 1. The signals that exist

| Signal | Where | What it says | What it does not say |
|---|---|---|---|
| `GET /health`, operator listener | `crates/kavach-api/src/http.rs` (`health`) | The process answers HTTP and the caller is authorised for `read_health` (Cedar). Returns `{"status":"ok"}` | Touches no dependency: Postgres, the HSM and the clock can all be down while it answers `ok` |
| `GET /health`, agent listener | `crates/kavach-api/src/dataplane.rs` (`agent_router`) | The agent listener accepts connections. Unauthenticated, static `{"status":"ok"}` | Same: no dependency is checked |
| `GET /metrics`, operator listener | `http.rs` (`metrics`), `crates/kavach-api/src/metrics.rs` | The Prometheus registry below; needs an operator token allowed `read_metrics` ([deploy/monitoring/README.md](../deploy/monitoring/README.md)) | A failed scrape looks the same whether the process is down or the scrape token expired |
| `GET /v1/runtime` | `crates/kavach-api/src/governance.rs` (`runtime`) | Reads the stored runtime pointer from Postgres; checkpoint health; whether the HSM answers now (`hsm`); `relaxations`, `insecure_dev`, `require_hardening` | Not designed as a probe: it needs `read_governance` and returns a body to parse |
| Readiness route | none | **Not built.** There is no route that answers "ready" only when Postgres, the signing keys and trusted time are usable | |

The metrics used below (all in `metrics.rs`, labels are fixed vocabularies):

- `kavach_gateway_calls_total{tool, decision, outcome}`: one per gateway call that reached a decision (`POST /v1/tools/{tool}`). `decision` is `PASS`, `ALERT`, `BLOCK` or `HUMAN_REVIEW`; `outcome` is `delivered`, `failed`, `refused`, `not_executed`, `unknown`, or `none` when nothing was sent.
- `kavach_gateway_malformed_total`: calls refused as malformed (400, nothing recorded).
- `kavach_gateway_stage_seconds{stage}`: time per stage (`decide`, `commit`, `resolve`, `credential`, `forward`, `outcome`).
- `kavach_gateway_outcome_write_failures_total`, `kavach_gateway_jti_conflicts_total`.
- `kavach_evaluate_requests_total{transport, outcome, status_class}` (credit track, full mode only).
- `kavach_sor_events_unavailable_total{kind}`: system-of-record events answered 503 (`issuing`, `revoking`).
- `kavach_checkpoint_*`: `last_seq`, `uncovered_records`, `last_covered_timestamp_seconds`, `stalled`, `written_total`, `skipped_total{reason}`.
- `kavach_revocation_records_missing`, `kavach_agent_state_records_missing`, `kavach_revocation_audit_entries_missing`, and the `*_last_pass_timestamp_seconds` gauge of each reconciler.
- `kavach_outcomes_{unresolved,ambiguous,conflicted,resolved}`, `kavach_outcome_oldest_unconfirmed_age_seconds`, `kavach_allows_without_outcome_beyond_lookback`.
- `kavach_agent_state_changes_total{to, result}`.
- `kavach_insecure_dev`, `kavach_relaxation_active{relaxation}`.

`POST /v1/authorize` (the pre-check) is not counted by any metric; nor is a gateway call refused as `conflict` (409), `in_flight` (409) or `not_forwardable` (501), or one whose task failed (500). Only the 400s are counted. A per-route request counter with the HTTP status is **not built**.

## 2. Availability of the authorization path

**What "available" means.** An agent's tool call gets a decision: an answer that is `PASS`, `ALERT`, `BLOCK` or `HUMAN_REVIEW`. A `BLOCK` is an available answer, even one caused by a dependency failure (section 3), because the agent was told no. Unavailable means no decision: the process is down, the listener does not answer, or the call fails with a 5xx.

| SLI | Built from | Status |
|---|---|---|
| The process is up | Prometheus `up{job="kavach-api"}` on the `/metrics` scrape (rule `KavachDown`) | Exists; it measures the operator listener, not the agent listener |
| The agent listener answers | A black-box probe of the agent listener's `GET /health` | The route exists; the probe is the deployment's own, not shipped |
| Gateway calls that got a decision, out of all gateway calls | Numerator: `sum(rate(kavach_gateway_calls_total[…]))`. Denominator needs every call, including 5xx | **Not built:** no counter of gateway calls by HTTP status; 500s (a failed call task) are logged, not counted |
| Evaluate calls without a server error (credit track) | `kavach_evaluate_requests_total{status_class!="5xx"}` over all | Exists (rule `KavachEvaluateErrors`) |

**Proposed objectives (proposed, not measured):**

- **A-1.** The agent listener answers `GET /health` in `<owner: N>`% of probes over a rolling `<owner: 30>` days.
- **A-2.** Of gateway calls, `<owner: N>`% get a decision rather than a 5xx, over a rolling `<owner: 30>` days. Needs the status counter above before it can be measured.
- **A-3 (credit track, full mode only).** Of evaluate requests, `<owner: N>`% end without a 5xx over a rolling `<owner: 30>` days.

**What the budget does not cover.** A single instance has no failover: a restart, an upgrade or a host failure is downtime, and every second of it spends budget. An orderly stop drains in-flight calls up to `--shutdown-grace-seconds` (default 30; `crates/kavach-api/src/shutdown.rs`) and writes a final checkpoint; the time between stop and the next start is not served. The owner sets the target knowing that; it cannot be higher than the deployment's restart pattern allows.

## 3. Fail-closed behaviour

Failing closed is a property, not a rate: when the evidence store, the mandate store, the contact counter or an agent's state cannot be read, the call is `BLOCK` with the reason `dependency_unavailable`, and when trusted time is not synchronised it is `BLOCK` with `trusted_time_unavailable` (`AuthorizeCore::authorize` in `crates/kavach-dataplane/src/authorize.rs`; reason texts in `crates/kavach-domain/src/reasons.rs`), never an allow; a mandate is not issued while the clock is unsynchronised (503). The objective is that this never fails, and separately that it is not triggered so often that the service is in effect down.

| SLI | Built from | Status |
|---|---|---|
| Allows recorded while a dependency was unavailable | None; enforced by construction and covered by tests (SECURITY_PROPERTIES.md rows on fail-closed and the kill switch) | A test-time guarantee, not a runtime measurement |
| Calls blocked because a dependency was unavailable | `kavach_gateway_calls_total{decision="BLOCK"}` counts every BLOCK, policy and fail-closed together. The reason is in the reply (and in the evidence record when one could be written), not in a metric label | **Not built:** a counter of fail-closed blocks by reason (fixed vocabulary: `dependency_unavailable`, `trusted_time_unavailable`) |
| Mandate issuing refused | `kavach_sor_events_unavailable_total{kind="issuing"}` (rule `KavachSorEventsUnavailable`) | Exists; does not say whether the clock or the store was the cause |
| Relaxations active | `kavach_relaxation_active`, `kavach_insecure_dev` (rules `KavachRelaxationActive`, `KavachInsecureDevActive`) | Exists. A relaxation can turn a fail-closed path off; it should read 0 in production |

**Proposed objectives (proposed, not measured):**

- **F-1.** Zero allows while a dependency the decision needs is unavailable. This is not an error budget: one occurrence is a security incident. It is checked by the tests named in SECURITY_PROPERTIES.md, not by a metric.
- **F-2.** Zero minutes with any `kavach_relaxation_active` above 0 on a production instance.
- **F-3.** Fail-closed blocks are below `<owner: N>`% of gateway calls over `<owner: 1>` hour, so that a degraded dependency is noticed as an outage rather than as a run of refusals. Needs the reason counter above.
- **F-4.** `kavach_sor_events_unavailable_total` does not rise for more than `<owner: N>` minutes in a row (the existing alert fires after 10 minutes of increase plus 5 minutes `for`; that is an alert threshold, not a measured objective).

## 4. Evidence durability

What protects a decision once it is made: the decision record is committed in Postgres before anything is forwarded (the `commit` stage); outcomes are written after the send; records are covered by signed checkpoints (`--checkpoint-interval-seconds`, default 60, or every 1,000 records); a checkpoint protects nothing against someone who holds the database and the keys until a copy is kept off-host (`kavach-evidence checkpoints --latest`, [EVIDENCE_BUNDLE.md](EVIDENCE_BUNDLE.md)). Reconcilers write the records a request could not (revocations, agent state). Postgres backups are the deployment's own; Kavach does not take them.

| SLI | Built from | Status |
|---|---|---|
| Age of the newest checkpoint coverage | `time() - kavach_checkpoint_last_covered_timestamp_seconds` (rules `KavachCheckpointLagging`, `KavachCheckpointStalled`) | Exists |
| Records not yet covered | `kavach_checkpoint_uncovered_records` | Exists |
| Outcomes that happened but were not recorded | `kavach_gateway_outcome_write_failures_total` (rule `KavachOutcomeWriteFailures`) | Exists |
| Allows with no outcome, too old to reconcile | `kavach_allows_without_outcome_beyond_lookback` (rule `KavachAllowWithoutOutcome`) | Exists |
| Revocation and agent-state changes without their evidence record | `kavach_revocation_records_missing`, `kavach_agent_state_records_missing` and their reconcilers' last-pass gauges | Exists |
| Age of the newest checkpoint kept off-host | The operator's scheduled `kavach-evidence checkpoints --latest` job | **Not built** as a signal: the job's success and time are the deployment's to record |
| A scheduled export verifies | `kavach-evidence export` then `verify-bundle --expect-checkpoint`; exit 0, 1 or 2 | The tools exist; a scheduled job and a metric of its result are **not built** |
| A restore from backup verifies | The restore drill runbook, `docs/runbooks/RESTORE_DRILL.md` (drafted in a separate change) | Not yet rehearsed |

**Proposed objectives (proposed, not measured):**

- **E-1.** Zero recorded decisions lost: every decision a client received has its record in the chain. This follows from the commit-before-forward order and is not an error budget.
- **E-2.** `kavach_gateway_outcome_write_failures_total` does not increase in `<owner: N>`% of `<owner: 30>`-day windows; every increase is investigated.
- **E-3.** Records are covered by a checkpoint within `<owner: N>` minutes, `<owner: N>`% of the time (`--checkpoint-stall-seconds` defaults to 600; that is an alert threshold, not a target).
- **E-4.** The newest off-host checkpoint is never older than `<owner: N>` minutes. This is the recovery point for detecting a rewritten chain.
- **E-5.** A full export verifies with exit 0 against the kept checkpoint at least every `<owner: N>` days.
- **E-6.** A restore drill completes and verifies at least every `<owner: N>` days; the recovery point and recovery time it shows are recorded, not assumed.
- **E-7.** `kavach_revocation_records_missing` and `kavach_agent_state_records_missing` are 0 at the end of every reconcile pass, except for at most `<owner: N>` minutes.

## 5. How kill-switch changes become visible

An agent's state is read from the store at every authorization, with no cache, so a stop applies from the agent's next call; a call already decided is re-checked just before its credential is minted and ends `not_executed`; a credential already minted lives at most 15 seconds (ADR-013; SECURITY_PROPERTIES.md, kill-switch row). On one instance there is nothing to propagate. A state that cannot be read blocks the call (section 3).

| SLI | Built from | Status |
|---|---|---|
| Stop requests applied | `kavach_agent_state_changes_total{result="applied"}` against all results (`unchanged`, `refused`, `rate_limited`, `unavailable`, `forbidden`, `unknown_agent`) | Exists (rules `KavachAgentStopped`, `KavachAgentStopBurst`, `KavachAgentStopForbidden`) |
| Stops that could not be applied because the store did not answer | `kavach_agent_state_changes_total{result="unavailable"}` | Exists |
| A stop's evidence record written | `kavach_agent_state_records_missing`, `kavach_agent_state_reconcile_last_pass_timestamp_seconds` | Exists |
| Time from a stop being applied to the agent's first refused call | None at runtime | **Not built.** Covered by tests and by `kavach simulate` against a development stack; a production probe would need a canary agent, which does not exist |
| Allows for an agent after its stop record | Could be read from the evidence chain (state records and decisions share one chain) | **Not built:** the verifier does not check it |

**Proposed objectives (proposed, not measured):**

- **K-1.** A stop request that reaches the API is applied or answered with a clear refusal: `unavailable` results are below `<owner: N>`% of stop attempts over `<owner: 30>` days.
- **K-2.** Zero allowed calls for an agent after its stop is applied, other than a call already past its credential mint, whose credential lives at most 15 seconds. Like F-1, one occurrence is an incident. Today this is checked by tests; a check in the verifier is not built.
- **K-3.** A stop's evidence record is in the chain within `<owner: N>` minutes of the stop, `<owner: N>`% of the time.

## 6. What would make this measurable

In the order the objectives need them; each is a separate change, none is started:

1. A counter of gateway and pre-check requests by HTTP status class (A-2).
2. A counter of fail-closed blocks by fixed reason, `dependency_unavailable` and `trusted_time_unavailable` (F-3).
3. A readiness route that checks Postgres, the signing keys and trusted time, separate from `/health` (A-1 would then probe readiness, not liveness).
4. A metric, written by the operator's job, for the last off-host checkpoint and the last verified export (E-4, E-5).
5. A verifier check for allows after a stop record (K-2).

Each adds a metric or route only; none collects personal data, and labels stay fixed vocabularies, as in `metrics.rs` today.

## 7. Open for the owner

1. Every `<…>` placeholder above.
2. Whether F-1, E-1 and K-2 stay as zero-tolerance properties outside any error budget (proposed).
3. Which of section 6 to build, and in what order.
4. Whether the credit-track objective (A-3) is kept while that track is frozen in hosted builds.

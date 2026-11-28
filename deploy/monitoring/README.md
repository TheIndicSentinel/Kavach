# Monitoring

Alert rules and a dashboard for `kavach-api`. Starting points: set the thresholds from your own traffic.

| File | What |
|---|---|
| [kavach-alerts.rules.yml](kavach-alerts.rules.yml) | Prometheus alert rules (evidence, gateway, service) |
| [kavach-dashboard.json](kavach-dashboard.json) | A Grafana dashboard (import it, and pick your Prometheus data source) |

## Scraping
`/metrics` is on the **operator** listener and needs an operator token that your Cedar policy allows to `read_metrics`.

```yaml
scrape_configs:
  - job_name: kavach-api
    metrics_path: /metrics
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/kavach-operator.token   # a short-lived operator token
    static_configs:
      - targets: ["kavach-api.internal:8080"]
```

The `KavachDown` rule assumes `job="kavach-api"`: change it if yours differs.

## Loading the rules
```yaml
rule_files:
  - /etc/prometheus/rules/kavach-alerts.rules.yml
```
Check them with `promtool check rules kavach-alerts.rules.yml`.

## What each alert means first
- **Critical** (page): a checkpoint stall, a revocation with no evidence record, an outcome that could not be recorded, a credential id conflict, the service down.
- **Warning** (look today): checkpoint lag or skipped checkpoints, a stopped reconciler (revocation evidence, revocation audit, agent state), a revocation whose audit entry could not be written, events answered 503 (an unsynchronised clock or an unreachable store: no new mandates are being made), many unknown outcomes, a slow commit stage, a malformed spike, incident write failures, a model/pack mismatch.

Every rule carries a `description` that says what it means and where to look. The metric names are in [INSTALL.md](../../docs/INSTALL.md).

## Which failures are silent by design (and which alert covers them)
Several things fail *closed*, which is correct but looks like an outage without a signal:

| Behaviour | Signal |
|---|---|
| New mandates refused (an unsynchronised clock or an unreachable store) | `KavachSorEventsUnavailable` (`kavach_sor_events_unavailable_total`) |
| The HA lease task ended and the API exits for a restart (REL-04) | `KavachBackgroundTaskExited` (`kavach_background_task_exits_total{task}`); also the container restart count, since the counter resets on restart |
| A revocation has no evidence record | `KavachRevocationRecordMissing` |
| A revocation has no audit entry | `KavachRevocationAuditEntryMissing` |
| A reconciler has stopped | `KavachRevocationReconcilerStopped`, `KavachRevocationAuditReconcilerStopped`, `KavachAgentStateReconcilerStopped`, `KavachOutcomeReconcilerStopped` |
| An allowed call has no outcome and is too old for the reconciler to record (F7) | `KavachAllowWithoutOutcome` (warning; `kavach_allows_without_outcome_beyond_lookback`) |
| A send's result is unknown or in dispute (ADR-017) | `KavachOutcomeConflicted` (critical), `KavachOutcomeAmbiguous`, `KavachOutcomeUnconfirmedOld` (warning; the three days is a default to set) |
| Checkpoints are late or skipped | `KavachCheckpointLagging`, `KavachCheckpointStalled`, `KavachCheckpointsSkipped` |
| A closed loan still has authority (a lost payment event) | `KavachClosedLoanWithLiveAuthority`; `KavachSnapshotNotRunRecently` (warning, silent until a first run) says how old that answer is |
| Many unknown provider outcomes | `KavachUnknownOutcomesHigh` (how many unknown outcomes happened). How many are still unconfirmed and for how long is `kavach_outcomes_unresolved` / `_ambiguous` / `_conflicted` and `kavach_outcome_oldest_unconfirmed_age_seconds`, refreshed every pass of the reconciler; `kavach_outcome_resolution_rows{source}` says how outcomes were learned |

## Not here yet
Tracing (OpenTelemetry), a SIEM export, per-tenant labels and SLO burn-rate alerts. A rule for a shutdown that was not clean is the `ALERT shutdown was not clean` log line, not a metric.

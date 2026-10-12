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
- **Warning** (look today): checkpoint lag or skipped checkpoints, a stopped reconciler, many unknown outcomes, a slow commit stage, a malformed spike, incident write failures, a model/pack mismatch.

Every rule carries a `description` that says what it means and where to look. The metric names are in [INSTALL.md](../../docs/INSTALL.md).

## Not here yet
Tracing (OpenTelemetry), a SIEM export, per-tenant labels and SLO burn-rate alerts. A rule for a shutdown that was not clean is the `ALERT shutdown was not clean` log line, not a metric.

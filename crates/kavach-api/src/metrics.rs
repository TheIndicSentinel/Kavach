use kavach_domain::Decision;
use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounterVec, Opts, Registry, TextEncoder,
};
use std::collections::HashMap;
use std::sync::Arc;

const METRIC_EVALUATE_TOTAL: &str = "kavach_evaluate_requests_total";
const METRIC_EVALUATE_LATENCY: &str = "kavach_evaluate_latency_ms";

#[derive(Clone)]
pub struct Metrics {
    registry: Arc<Registry>,
    evaluate_total: IntCounterVec,
    evaluate_latency_ms: HistogramVec,
    incident_write_failures: prometheus::IntCounter,
    model_pack_mismatch: prometheus::IntGauge,
    gateway_calls: IntCounterVec,
    gateway_malformed: prometheus::IntCounter,
    sor_unavailable: IntCounterVec,
    snapshot: SnapshotMetrics,
    revocation_audit: RevocationAuditMetrics,
    gateway_jti_conflicts: prometheus::IntCounter,
    gateway_outcome_write_failures: prometheus::IntCounter,
    agent_state_changes: IntCounterVec,
    gateway_stage_seconds: HistogramVec,
    checkpoints: CheckpointMetrics,
    credit_checkpoints: CreditCheckpointMetrics,
    revocation_evidence: RevocationEvidenceMetrics,
    agent_state_evidence: AgentStateEvidenceMetrics,
    outcomes: OutcomeMetrics,
    relaxations: RelaxationMetrics,
}

/// How long each stage of a gateway call takes (`stage` is the fixed list
/// in `kavach_dataplane::Stage`), so a slow call can be located.
fn gateway_stage_histogram(registry: &Registry) -> Result<HistogramVec, prometheus::Error> {
    let histogram = HistogramVec::new(
        HistogramOpts::new(
            "kavach_gateway_stage_seconds",
            "Duration of each stage of a gateway call: decide, commit, resolve, credential, \
             forward, outcome",
        )
        .buckets(vec![
            0.000_25, 0.000_5, 0.001, 0.002_5, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5,
            5.0,
        ]),
        &["stage"],
    )?;
    registry.register(Box::new(histogram.clone()))?;
    Ok(histogram)
}

/// Evidence checkpoints (ADR-005 §13). `reason` is a fixed vocabulary.
#[derive(Clone)]
struct CheckpointMetrics {
    written: prometheus::IntCounter,
    skipped: IntCounterVec,
    last_seq: prometheus::IntGauge,
    uncovered_records: prometheus::IntGauge,
    last_covered: prometheus::IntGauge,
    stalled: prometheus::IntGauge,
}

#[derive(Clone)]
struct CreditCheckpointMetrics {
    written: prometheus::IntCounter,
    skipped: IntCounterVec,
    last_seq: prometheus::IntGauge,
    uncovered_records: prometheus::IntGauge,
    last_covered: prometheus::IntGauge,
    stalled: prometheus::IntGauge,
}

impl CreditCheckpointMetrics {
    fn register(registry: &Registry) -> Result<Self, prometheus::Error> {
        let metrics = Self {
            written: prometheus::IntCounter::new(
                "kavach_credit_checkpoints_written_total",
                "Credit decision-event checkpoints written by this process",
            )?,
            skipped: IntCounterVec::new(
                Opts::new(
                    "kavach_credit_checkpoints_skipped_total",
                    "Due credit decision-event checkpoints not written, by reason",
                ),
                &["reason"],
            )?,
            last_seq: prometheus::IntGauge::new(
                "kavach_credit_checkpoint_last_seq",
                "seq of the newest credit decision-event checkpoint (0: none)",
            )?,
            uncovered_records: prometheus::IntGauge::new(
                "kavach_credit_checkpoint_uncovered_records",
                "Credit decision events newer than the newest checkpoint",
            )?,
            last_covered: prometheus::IntGauge::new(
                "kavach_credit_checkpoint_last_covered_timestamp_seconds",
                "Unix time when every credit decision event was last covered by a checkpoint",
            )?,
            stalled: prometheus::IntGauge::new(
                "kavach_credit_checkpoint_stalled",
                "1 when credit decision events have been uncovered longer than the stall threshold",
            )?,
        };
        registry.register(Box::new(metrics.written.clone()))?;
        registry.register(Box::new(metrics.skipped.clone()))?;
        registry.register(Box::new(metrics.last_seq.clone()))?;
        registry.register(Box::new(metrics.uncovered_records.clone()))?;
        registry.register(Box::new(metrics.last_covered.clone()))?;
        registry.register(Box::new(metrics.stalled.clone()))?;
        Ok(metrics)
    }
}

impl CheckpointMetrics {
    fn register(registry: &Registry) -> Result<Self, prometheus::Error> {
        let gauge = |name: &str, help: &str| prometheus::IntGauge::new(name, help);
        let metrics = Self {
            written: prometheus::IntCounter::new(
                "kavach_checkpoints_written_total",
                "Evidence checkpoints written by this process",
            )?,
            skipped: IntCounterVec::new(
                Opts::new(
                    "kavach_checkpoints_skipped_total",
                    "Due evidence checkpoints that were not written, by reason",
                ),
                &["reason"],
            )?,
            last_seq: gauge(
                "kavach_checkpoint_last_seq",
                "seq of the newest evidence checkpoint (0: none)",
            )?,
            uncovered_records: gauge(
                "kavach_checkpoint_uncovered_records",
                "Agent records newer than the newest evidence checkpoint",
            )?,
            last_covered: gauge(
                "kavach_checkpoint_last_covered_timestamp_seconds",
                "Unix time when every agent record was last covered by a checkpoint; alert when it is old",
            )?,
            stalled: gauge(
                "kavach_checkpoint_stalled",
                "1 when agent records have had no checkpoint for longer than the stall threshold",
            )?,
        };
        registry.register(Box::new(metrics.written.clone()))?;
        registry.register(Box::new(metrics.skipped.clone()))?;
        registry.register(Box::new(metrics.last_seq.clone()))?;
        registry.register(Box::new(metrics.uncovered_records.clone()))?;
        registry.register(Box::new(metrics.last_covered.clone()))?;
        registry.register(Box::new(metrics.stalled.clone()))?;
        Ok(metrics)
    }
}

/// The audit entries of revocations (S3): what the reconciler could not write
/// and what it had to repair.
#[derive(Clone)]
struct RevocationAuditMetrics {
    missing: prometheus::IntGauge,
    written: prometheus::IntCounter,
    last_pass: prometheus::IntGauge,
}

impl RevocationAuditMetrics {
    fn register(registry: &Registry) -> Result<Self, prometheus::Error> {
        let metrics = Self {
            missing: prometheus::IntGauge::new(
                "kavach_revocation_audit_entries_missing",
                "Revocations whose audit entry could not be written in the last reconcile \
                 pass; alert when above 0 (the revocation stands, the audit trail has a gap)",
            )?,
            written: prometheus::IntCounter::new(
                "kavach_revocation_audit_entries_written_total",
                "Audit entries written by the reconciler because the request that revoked \
                 could not write them",
            )?,
            last_pass: prometheus::IntGauge::new(
                "kavach_revocation_audit_last_pass_timestamp_seconds",
                "Unix time of the last reconcile pass that could read every revocation; \
                 alert when it is old",
            )?,
        };
        registry.register(Box::new(metrics.missing.clone()))?;
        registry.register(Box::new(metrics.written.clone()))?;
        registry.register(Box::new(metrics.last_pass.clone()))?;
        Ok(metrics)
    }
}

/// Snapshot reconciliation (ADR-012 addendum): the last run's result.
#[derive(Clone)]
struct SnapshotMetrics {
    mismatches: prometheus::IntGauge,
    last_run: prometheus::IntGauge,
}

impl SnapshotMetrics {
    fn register(registry: &Registry) -> Result<Self, prometheus::Error> {
        let metrics = Self {
            mismatches: prometheus::IntGauge::new(
                "kavach_snapshot_mismatches",
                "Live mandates for loans the lender reported closed, from the last snapshot \
                 reconciliation; alert when above 0 (a payment or dispute event was likely lost)",
            )?,
            last_run: prometheus::IntGauge::new(
                "kavach_snapshot_last_run_timestamp_seconds",
                "Unix time of the last snapshot reconciliation; 0 until one has run",
            )?,
        };
        registry.register(Box::new(metrics.mismatches.clone()))?;
        registry.register(Box::new(metrics.last_run.clone()))?;
        Ok(metrics)
    }
}

/// Revocation evidence records (ADR-012 §7): the reconciler's view.
#[derive(Clone)]
struct RevocationEvidenceMetrics {
    missing: prometheus::IntGauge,
    reconciled: prometheus::IntCounter,
    last_pass: prometheus::IntGauge,
}

impl RevocationEvidenceMetrics {
    fn register(registry: &Registry) -> Result<Self, prometheus::Error> {
        let metrics = Self {
            missing: prometheus::IntGauge::new(
                "kavach_revocation_records_missing",
                "Revocations by system-of-record event still without their evidence-chain \
                 record after the last reconcile pass; alert when above 0",
            )?,
            reconciled: prometheus::IntCounter::new(
                "kavach_revocation_records_reconciled_total",
                "Revocation evidence records written by the reconciler because the request \
                 that revoked could not write them",
            )?,
            last_pass: prometheus::IntGauge::new(
                "kavach_revocation_reconcile_last_pass_timestamp_seconds",
                "Unix time of the last complete reconcile pass; alert when it is old",
            )?,
        };
        registry.register(Box::new(metrics.missing.clone()))?;
        registry.register(Box::new(metrics.reconciled.clone()))?;
        registry.register(Box::new(metrics.last_pass.clone()))?;
        Ok(metrics)
    }
}

/// Agent-state evidence records (ADR-013 §4): the reconciler's view.
#[derive(Clone)]
struct AgentStateEvidenceMetrics {
    missing: prometheus::IntGauge,
    reconciled: prometheus::IntCounter,
    last_pass: prometheus::IntGauge,
}

impl AgentStateEvidenceMetrics {
    fn register(registry: &Registry) -> Result<Self, prometheus::Error> {
        let metrics = Self {
            missing: prometheus::IntGauge::new(
                "kavach_agent_state_records_missing",
                "Changes of an agent's state still without their evidence-chain record \
                 after the last reconcile pass; alert when above 0",
            )?,
            reconciled: prometheus::IntCounter::new(
                "kavach_agent_state_records_reconciled_total",
                "Agent-state evidence records written by the reconciler because the \
                 request that changed the state could not write them",
            )?,
            last_pass: prometheus::IntGauge::new(
                "kavach_agent_state_reconcile_last_pass_timestamp_seconds",
                "Unix time of the last complete agent-state reconcile pass; alert when it is old",
            )?,
        };
        registry.register(Box::new(metrics.missing.clone()))?;
        registry.register(Box::new(metrics.reconciled.clone()))?;
        registry.register(Box::new(metrics.last_pass.clone()))?;
        Ok(metrics)
    }
}

/// Which relaxations the process runs with (BYPASS_INVENTORY.md section 1).
#[derive(Clone)]
struct RelaxationMetrics {
    insecure_dev: prometheus::IntGauge,
    active: prometheus::IntGaugeVec,
}

impl RelaxationMetrics {
    fn register(registry: &Registry) -> Result<Self, prometheus::Error> {
        let metrics = Self {
            insecure_dev: prometheus::IntGauge::new(
                "kavach_insecure_dev",
                "1 when the process runs with --insecure-dev, which turns several \
                 guarantees off (never in production); alert when above 0",
            )?,
            active: prometheus::IntGaugeVec::new(
                Opts::new(
                    "kavach_relaxation_active",
                    "1 for each way this process runs with a guarantee relaxed (a fixed set of \
                     names, all always present, see BYPASS_INVENTORY.md); alert when above 0",
                ),
                &["relaxation"],
            )?,
        };
        registry.register(Box::new(metrics.insecure_dev.clone()))?;
        registry.register(Box::new(metrics.active.clone()))?;
        // Every name is present from the start, at 0.
        for name in crate::relaxations::Relaxation::ALL {
            metrics.active.with_label_values(&[name.as_str()]).set(0);
        }
        Ok(metrics)
    }
}

/// Unknown outcomes and their resolutions (ADR-017 R3a): what is still
/// unconfirmed, how long, and how it is known. Counts and ages only; nothing
/// that names a loan, a borrower or a destination.
#[derive(Clone)]
struct OutcomeMetrics {
    unresolved: prometheus::IntGauge,
    ambiguous: prometheus::IntGauge,
    conflicted: prometheus::IntGauge,
    resolved: prometheus::IntGauge,
    oldest_unconfirmed_age: prometheus::IntGauge,
    rows_by_source: prometheus::IntGaugeVec,
    last_pass: prometheus::IntGauge,
    beyond_lookback: prometheus::IntGauge,
}

impl OutcomeMetrics {
    fn register(registry: &Registry) -> Result<Self, prometheus::Error> {
        let gauge = |name: &str, help: &str| prometheus::IntGauge::new(name, help);
        let metrics = Self {
            unresolved: gauge(
                "kavach_outcomes_unresolved",
                "Unknown outcomes (a send whose result is not known) that no resolution \
                 has said anything about yet",
            )?,
            ambiguous: gauge(
                "kavach_outcomes_ambiguous",
                "Unknown outcomes nobody could resolve (only ambiguous): they wait for a \
                 person; alert when above 0",
            )?,
            conflicted: gauge(
                "kavach_outcomes_conflicted",
                "Unknown outcomes with two different confirmed states and no two-person \
                 closure: an incident; alert when above 0",
            )?,
            resolved: gauge(
                "kavach_outcomes_resolved",
                "Unknown outcomes that one confirmed state governs",
            )?,
            oldest_unconfirmed_age: gauge(
                "kavach_outcome_oldest_unconfirmed_age_seconds",
                "Age of the oldest unknown outcome that is not resolved (unresolved, \
                 ambiguous or conflicted); 0 when there is none",
            )?,
            rows_by_source: prometheus::IntGaugeVec::new(
                Opts::new(
                    "kavach_outcome_resolution_rows",
                    "Resolution rows kept for unknown outcomes, by source",
                ),
                &["source"],
            )?,
            beyond_lookback: gauge(
                "kavach_allows_without_outcome_beyond_lookback",
                "Allowed calls with no outcome that are older than the 7 days the \
                 reconciler looks back over, so it leaves them as they are (the verifier \
                 reports each as outcome_missing); at most 1000 are counted. Alert when \
                 above 0",
            )?,
            last_pass: gauge(
                "kavach_outcome_reconcile_last_pass_timestamp_seconds",
                "Unix time of the last outcome reconcile pass that read the summary; \
                 alert when it is old",
            )?,
        };
        registry.register(Box::new(metrics.unresolved.clone()))?;
        registry.register(Box::new(metrics.ambiguous.clone()))?;
        registry.register(Box::new(metrics.conflicted.clone()))?;
        registry.register(Box::new(metrics.resolved.clone()))?;
        registry.register(Box::new(metrics.oldest_unconfirmed_age.clone()))?;
        registry.register(Box::new(metrics.rows_by_source.clone()))?;
        registry.register(Box::new(metrics.last_pass.clone()))?;
        registry.register(Box::new(metrics.beyond_lookback.clone()))?;
        Ok(metrics)
    }
}

/// The counters of the operator and system-of-record surfaces: agent state
/// changes, and events answered 503.
fn operator_counters() -> Result<(IntCounterVec, IntCounterVec), prometheus::Error> {
    let agent_state_changes = IntCounterVec::new(
        Opts::new(
            "kavach_agent_state_changes_total",
            "Attempts to change an agent's state through the operator API, by the state \
                 asked for and the result (applied, unchanged, refused, rate_limited, \
                 unavailable, forbidden, unknown_agent). A stop is an incident; a burst of \
                 them is a stolen credential until shown otherwise",
        ),
        &["to", "result"],
    )?;
    let sor_unavailable = IntCounterVec::new(
        Opts::new(
            "kavach_sor_events_unavailable_total",
            "System-of-record events answered 503 because Kavach could not act on them \
                 now (clock not synchronised, store unreachable), by kind (issuing, \
                 revoking). The sender retries; alert when it keeps rising: no new mandates \
                 are being made",
        ),
        &["kind"],
    )?;
    Ok((agent_state_changes, sor_unavailable))
}

impl Metrics {
    /// Creates all process metrics with the tenant label from startup
    /// configuration. Request data must never select or change this value.
    pub fn new(tenant_id: &str) -> Result<Self, prometheus::Error> {
        let registry = Registry::new_custom(
            None,
            Some(HashMap::from([(
                "tenant_id".to_string(),
                tenant_id.to_string(),
            )])),
        )?;
        let evaluate_total = IntCounterVec::new(
            Opts::new(
                METRIC_EVALUATE_TOTAL,
                "Evaluate requests by transport, outcome, and HTTP-style status class",
            ),
            &["transport", "outcome", "status_class"],
        )?;
        let evaluate_latency_ms = HistogramVec::new(
            HistogramOpts::new(
                METRIC_EVALUATE_LATENCY,
                "Evaluate handler latency in milliseconds",
            )
            .buckets(vec![
                1.0, 2.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0,
            ]),
            &["transport"],
        )?;
        let incident_write_failures = prometheus::IntCounter::new(
            "kavach_incident_write_failures_total",
            "Incidents that could not be persisted (evidence or policy failure made invisible otherwise)",
        )?;
        registry.register(Box::new(evaluate_total.clone()))?;
        registry.register(Box::new(evaluate_latency_ms.clone()))?;
        let model_pack_mismatch = prometheus::IntGauge::new(
            "kavach_model_pack_mismatch",
            "1 when the active model record names a different pack than the one running",
        )?;
        registry.register(Box::new(incident_write_failures.clone()))?;
        registry.register(Box::new(model_pack_mismatch.clone()))?;
        // Gateway: labels are fixed vocabularies only (registry tool names,
        // decisions, outcomes), never agent-supplied strings.
        let gateway_calls = IntCounterVec::new(
            Opts::new(
                "kavach_gateway_calls_total",
                "Gateway tool calls by tool, decision and outcome",
            ),
            &["tool", "decision", "outcome"],
        )?;
        let gateway_malformed = prometheus::IntCounter::new(
            "kavach_gateway_malformed_total",
            "Gateway requests refused as malformed (400; nothing recorded)",
        )?;
        let gateway_jti_conflicts = prometheus::IntCounter::new(
            "kavach_gateway_jti_conflicts_total",
            "ALERT: a provider reported a credential id used for other claims (outcome unknown)",
        )?;
        let gateway_outcome_write_failures = prometheus::IntCounter::new(
            "kavach_gateway_outcome_write_failures_total",
            "ALERT: an outcome happened but could not be recorded",
        )?;
        let (agent_state_changes, sor_unavailable) = operator_counters()?;
        let snapshot = SnapshotMetrics::register(&registry)?;
        let revocation_audit = RevocationAuditMetrics::register(&registry)?;
        registry.register(Box::new(sor_unavailable.clone()))?;
        registry.register(Box::new(agent_state_changes.clone()))?;
        registry.register(Box::new(gateway_calls.clone()))?;
        registry.register(Box::new(gateway_malformed.clone()))?;
        registry.register(Box::new(gateway_jti_conflicts.clone()))?;
        registry.register(Box::new(gateway_outcome_write_failures.clone()))?;
        let checkpoints = CheckpointMetrics::register(&registry)?;
        let credit_checkpoints = CreditCheckpointMetrics::register(&registry)?;
        let revocation_evidence = RevocationEvidenceMetrics::register(&registry)?;
        let gateway_stage_seconds = gateway_stage_histogram(&registry)?;
        let (outcomes, relaxations) = (
            OutcomeMetrics::register(&registry)?,
            RelaxationMetrics::register(&registry)?,
        );
        Ok(Self {
            evaluate_total,
            evaluate_latency_ms,
            incident_write_failures,
            model_pack_mismatch,
            gateway_calls,
            gateway_malformed,
            sor_unavailable,
            snapshot,
            revocation_audit,
            gateway_jti_conflicts,
            gateway_outcome_write_failures,
            agent_state_changes,
            gateway_stage_seconds,
            checkpoints,
            credit_checkpoints,
            revocation_evidence,
            outcomes,
            relaxations,
            agent_state_evidence: AgentStateEvidenceMetrics::register(&registry)?,
            registry: Arc::new(registry),
        })
    }

    pub fn observe_success(&self, transport: &str, decision: Decision, latency_ms: u64) {
        self.evaluate_total
            .with_label_values(&[transport, decision_label(decision), "2xx"])
            .inc();
        self.evaluate_latency_ms
            .with_label_values(&[transport])
            .observe(f64::from(u32::try_from(latency_ms).unwrap_or(u32::MAX)));
    }

    pub fn set_model_pack_mismatch(&self, mismatch: bool) {
        self.model_pack_mismatch.set(i64::from(mismatch));
    }

    pub fn observe_incident_write_failure(&self) {
        self.incident_write_failures.inc();
    }

    pub fn observe_client_error(&self, transport: &str) {
        self.evaluate_total
            .with_label_values(&[transport, "none", "4xx"])
            .inc();
    }

    pub fn observe_server_error(&self, transport: &str) {
        self.evaluate_total
            .with_label_values(&[transport, "none", "5xx"])
            .inc();
    }

    /// One pass of the revocation audit reconciler: entries it wrote, entries
    /// it could not write, and whether it could read every revocation.
    pub fn observe_revocation_audit_pass(&self, written: usize, failed: usize, complete: bool) {
        let metrics = &self.revocation_audit;
        metrics
            .written
            .inc_by(u64::try_from(written).unwrap_or(u64::MAX));
        if complete {
            metrics
                .missing
                .set(i64::try_from(failed).unwrap_or(i64::MAX));
            metrics.last_pass.set(chrono::Utc::now().timestamp());
        }
    }

    /// One snapshot reconciliation: how many live mandates it found for
    /// loans reported closed.
    pub fn observe_snapshot_reconciliation(&self, mismatches: i64) {
        self.snapshot.mismatches.set(mismatches);
        self.snapshot.last_run.set(chrono::Utc::now().timestamp());
    }

    /// An event answered 503 (`kind`: `issuing` or `revoking`).
    pub fn observe_sor_unavailable(&self, kind: &str) {
        self.sor_unavailable.with_label_values(&[kind]).inc();
    }

    pub fn observe_gateway_malformed(&self) {
        self.gateway_malformed.inc();
    }

    pub fn observe_checkpoint_written(&self) {
        self.checkpoints.written.inc();
    }

    pub fn observe_checkpoint_skipped(&self, reason: &str) {
        self.checkpoints.skipped.with_label_values(&[reason]).inc();
    }

    pub fn set_checkpoint_status(&self, status: &kavach_dataplane::CheckpointStatus) {
        let checkpoints = &self.checkpoints;
        checkpoints.last_seq.set(status.last_seq.unwrap_or(0));
        checkpoints.uncovered_records.set(status.uncovered_records);
        checkpoints
            .last_covered
            .set(status.last_covered_at.timestamp());
        checkpoints.stalled.set(i64::from(status.stalled));
    }

    pub fn observe_credit_checkpoint_written(&self) {
        self.credit_checkpoints.written.inc();
    }

    pub fn observe_credit_checkpoint_skipped(&self, reason: &str) {
        self.credit_checkpoints
            .skipped
            .with_label_values(&[reason])
            .inc();
    }

    pub fn set_credit_checkpoint_status(&self, status: &kavach_dataplane::CheckpointStatus) {
        let checkpoints = &self.credit_checkpoints;
        checkpoints.last_seq.set(status.last_seq.unwrap_or(0));
        checkpoints.uncovered_records.set(status.uncovered_records);
        checkpoints
            .last_covered
            .set(status.last_covered_at.timestamp());
        checkpoints.stalled.set(i64::from(status.stalled));
    }

    /// One reconcile pass of the revocation evidence: what is still missing,
    /// what it wrote, and (when it read everything) that it completed.
    pub fn observe_revocation_reconcile(&self, report: &kavach_dataplane::ReconcileReport) {
        let metrics = &self.revocation_evidence;
        metrics
            .missing
            .set(i64::try_from(report.missing.len()).unwrap_or(i64::MAX));
        metrics
            .reconciled
            .inc_by(u64::try_from(report.reconciled.len()).unwrap_or(u64::MAX));
        if report.error.is_none() {
            metrics.last_pass.set(chrono::Utc::now().timestamp());
        }
    }

    /// The relaxations the process runs with, set once at startup.
    pub fn set_relaxations(&self, on: &std::collections::BTreeSet<crate::relaxations::Relaxation>) {
        use crate::relaxations::Relaxation;
        let metrics = &self.relaxations;
        metrics
            .insecure_dev
            .set(i64::from(on.contains(&Relaxation::InsecureDev)));
        for name in Relaxation::ALL {
            metrics
                .active
                .with_label_values(&[name.as_str()])
                .set(i64::from(on.contains(&name)));
        }
    }

    /// One outcome reconcile pass (ADR-017 R3a): the summary it read. A pass
    /// that could not read it leaves the gauges as they were and does not
    /// move `last_pass`, so a stuck reconciler shows as an old pass.
    pub fn observe_outcome_reconcile(&self, report: &kavach_dataplane::OutcomeReconcileReport) {
        // Whether any allow is older than the lookback does not depend on the
        // summary, so it is published whenever the pass ran.
        if report.at.is_some() {
            self.outcomes
                .beyond_lookback
                .set(i64::try_from(report.beyond_lookback).unwrap_or(i64::MAX));
        }
        let Some(summary) = &report.summary else {
            return;
        };
        let metrics = &self.outcomes;
        let count = |n: u64| i64::try_from(n).unwrap_or(i64::MAX);
        metrics.unresolved.set(count(summary.unresolved));
        metrics.ambiguous.set(count(summary.ambiguous));
        metrics.conflicted.set(count(summary.conflicted));
        metrics.resolved.set(count(summary.resolved));
        // Ages are measured on the clock the outcomes were stamped with.
        let now = report.at.unwrap_or_else(chrono::Utc::now);
        metrics.oldest_unconfirmed_age.set(
            summary
                .oldest_unconfirmed
                .map_or(0, |oldest| (now - oldest).num_seconds().max(0)),
        );
        // Every source, so a source with no rows reads 0 rather than absent.
        for source in [
            "provider_status",
            "operator_attested",
            "conflict_resolution",
            "reconciler",
        ] {
            metrics
                .rows_by_source
                .with_label_values(&[source])
                .set(count(
                    summary.rows_by_source.get(source).copied().unwrap_or(0),
                ));
        }
        metrics.last_pass.set(chrono::Utc::now().timestamp());
    }

    /// One reconcile pass of the agent-state evidence.
    pub fn observe_agent_state_reconcile(&self, report: &kavach_dataplane::StateReconcileReport) {
        let metrics = &self.agent_state_evidence;
        metrics
            .missing
            .set(i64::try_from(report.missing.len()).unwrap_or(i64::MAX));
        metrics
            .reconciled
            .inc_by(u64::try_from(report.reconciled.len()).unwrap_or(u64::MAX));
        if report.error.is_none() {
            metrics.last_pass.set(chrono::Utc::now().timestamp());
        }
    }

    /// One attempt to change an agent's state (`to` and `result` are fixed
    /// vocabularies).
    pub fn observe_agent_state_change(&self, to: &str, result: &str) {
        self.agent_state_changes
            .with_label_values(&[to, result])
            .inc();
    }

    pub fn gather_text(&self) -> Result<String, prometheus::Error> {
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        TextEncoder::new().encode(&metric_families, &mut buffer)?;
        Ok(String::from_utf8(buffer).unwrap_or_default())
    }
}

fn decision_label(decision: Decision) -> &'static str {
    match decision {
        Decision::Pass => "PASS",
        Decision::Alert => "ALERT",
        Decision::Block => "BLOCK",
        Decision::HumanReview => "HUMAN_REVIEW",
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new("default").expect("metrics init")
    }
}

impl kavach_dataplane::GatewayObserver for Metrics {
    fn call(
        &self,
        tool: &str,
        decision: Decision,
        outcome: Option<kavach_ports::agent_evidence::Outcome>,
    ) {
        self.gateway_calls
            .with_label_values(&[
                tool,
                decision_label(decision),
                outcome.map_or("none", kavach_ports::agent_evidence::Outcome::as_str),
            ])
            .inc();
    }

    fn jti_conflict(&self) {
        self.gateway_jti_conflicts.inc();
    }

    fn outcome_write_failed(&self) {
        self.gateway_outcome_write_failures.inc();
    }

    fn stage(&self, stage: kavach_dataplane::Stage, elapsed: std::time::Duration) {
        self.gateway_stage_seconds
            .with_label_values(&[stage.as_str()])
            .observe(elapsed.as_secs_f64());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gather_contains_evaluate_metrics() {
        let metrics = Metrics::new("tenant-a").expect("metrics");
        let other_tenant_metrics = Metrics::new("tenant-b").expect("other tenant metrics");
        metrics.observe_success("http", Decision::Pass, 3);
        other_tenant_metrics.observe_success("http", Decision::Pass, 3);
        let text = metrics.gather_text().expect("gather");
        let other_tenant_text = other_tenant_metrics.gather_text().expect("gather");
        assert!(text.contains(METRIC_EVALUATE_TOTAL));
        assert!(text.contains(METRIC_EVALUATE_LATENCY));
        assert!(text.contains("tenant_id=\"tenant-a\""));
        assert!(!text.contains("tenant_id=\"tenant-b\""));
        assert!(other_tenant_text.contains("tenant_id=\"tenant-b\""));
        assert!(!other_tenant_text.contains("tenant_id=\"tenant-a\""));
    }

    #[test]
    fn gateway_stages_are_a_histogram_labelled_by_stage_only() {
        use kavach_dataplane::GatewayObserver;
        let metrics = Metrics::new("default").expect("metrics");
        for stage in kavach_dataplane::Stage::ALL {
            metrics.stage(stage, std::time::Duration::from_millis(3));
        }
        let text = metrics.gather_text().expect("gather");
        for stage in kavach_dataplane::Stage::ALL {
            let count = format!(
                "kavach_gateway_stage_seconds_count{{stage=\"{}\",tenant_id=\"default\"}} 1",
                stage.as_str()
            );
            assert!(text.contains(&count), "{text}");
        }
        assert!(
            text.contains("kavach_gateway_stage_seconds_bucket{stage=\"commit\",tenant_id=\"default\",le=\"0.005\"} 1"),
            "{text}"
        );
    }
}

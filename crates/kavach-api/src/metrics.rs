use kavach_domain::Decision;
use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounterVec, Opts, Registry, TextEncoder,
};
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
    gateway_jti_conflicts: prometheus::IntCounter,
    gateway_outcome_write_failures: prometheus::IntCounter,
    gateway_stage_seconds: HistogramVec,
    checkpoints: CheckpointMetrics,
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

impl Metrics {
    pub fn new() -> Result<Self, prometheus::Error> {
        let registry = Registry::new();
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
        registry.register(Box::new(gateway_calls.clone()))?;
        registry.register(Box::new(gateway_malformed.clone()))?;
        registry.register(Box::new(gateway_jti_conflicts.clone()))?;
        registry.register(Box::new(gateway_outcome_write_failures.clone()))?;
        let checkpoints = CheckpointMetrics::register(&registry)?;
        let gateway_stage_seconds = gateway_stage_histogram(&registry)?;
        Ok(Self {
            registry: Arc::new(registry),
            evaluate_total,
            evaluate_latency_ms,
            incident_write_failures,
            model_pack_mismatch,
            gateway_calls,
            gateway_malformed,
            gateway_jti_conflicts,
            gateway_outcome_write_failures,
            gateway_stage_seconds,
            checkpoints,
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
        Self::new().expect("metrics init")
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
        let metrics = Metrics::new().expect("metrics");
        metrics.observe_success("http", Decision::Pass, 3);
        let text = metrics.gather_text().expect("gather");
        assert!(text.contains(METRIC_EVALUATE_TOTAL));
        assert!(text.contains(METRIC_EVALUATE_LATENCY));
    }

    #[test]
    fn gateway_stages_are_a_histogram_labelled_by_stage_only() {
        use kavach_dataplane::GatewayObserver;
        let metrics = Metrics::new().expect("metrics");
        for stage in kavach_dataplane::Stage::ALL {
            metrics.stage(stage, std::time::Duration::from_millis(3));
        }
        let text = metrics.gather_text().expect("gather");
        for stage in kavach_dataplane::Stage::ALL {
            let count = format!(
                "kavach_gateway_stage_seconds_count{{stage=\"{}\"}} 1",
                stage.as_str()
            );
            assert!(text.contains(&count), "{text}");
        }
        assert!(
            text.contains("kavach_gateway_stage_seconds_bucket{stage=\"commit\",le=\"0.005\"} 1"),
            "{text}"
        );
    }
}

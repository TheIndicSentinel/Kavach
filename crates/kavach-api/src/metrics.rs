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
        registry.register(Box::new(evaluate_total.clone()))?;
        registry.register(Box::new(evaluate_latency_ms.clone()))?;
        Ok(Self {
            registry: Arc::new(registry),
            evaluate_total,
            evaluate_latency_ms,
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
}

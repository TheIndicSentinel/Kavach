//! The shipped alert rules and dashboard (`deploy/monitoring`) stay true to
//! the code: they parse, every rule is complete, and every metric they name
//! is one the API registers, so a renamed or removed metric fails here and
//! not silently in production.

use std::collections::BTreeSet;
use std::path::Path;

use serde_json::Value;

fn root() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
}

/// Every `kavach_…` metric name the code registers, read from the source:
/// a labelled metric has no sample (and so no line in a scrape) until used.
fn registered() -> BTreeSet<String> {
    let sources = std::fs::read_to_string(root().join("crates/kavach-api/src/metrics.rs")).unwrap();
    let mut names = BTreeSet::new();
    for part in sources.split('"') {
        if part.starts_with("kavach_")
            && part
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            names.insert(part.to_string());
        }
    }
    names
}

/// The metric names an expression uses (`_bucket`, `_sum`, `_count` map
/// back to their histogram).
fn used(expression: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let bytes = expression.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let starts = expression[i..].starts_with("kavach_")
            && (i == 0 || !(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_'));
        if starts {
            let end = expression[i..]
                .find(|c: char| !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'))
                .map_or(expression.len(), |n| i + n);
            let name = &expression[i..end];
            let base = ["_bucket", "_sum", "_count"]
                .iter()
                .find_map(|s| name.strip_suffix(s))
                .unwrap_or(name);
            out.insert(base.to_string());
            i = end;
        } else {
            i += 1;
        }
    }
    out
}

#[test]
fn the_alert_rules_are_complete_and_name_real_metrics() {
    let text =
        std::fs::read_to_string(root().join("deploy/monitoring/kavach-alerts.rules.yml")).unwrap();
    let doc: Value = serde_yaml::from_str(&text).expect("the rules are YAML");
    let known = registered();
    let mut alerts = BTreeSet::new();
    let mut count = 0;
    for group in doc["groups"].as_array().expect("groups") {
        for rule in group["rules"].as_array().expect("rules") {
            count += 1;
            let name = rule["alert"].as_str().expect("an alert name");
            assert!(alerts.insert(name.to_string()), "{name} twice");
            let expr = rule["expr"].as_str().expect("an expression");
            assert!(
                matches!(
                    rule["labels"]["severity"].as_str(),
                    Some("critical" | "warning")
                ),
                "{name}: a severity of critical or warning"
            );
            assert!(
                rule["annotations"]["summary"].is_string()
                    && rule["annotations"]["description"].is_string(),
                "{name}: a summary and a description"
            );
            for metric in used(expr) {
                assert!(
                    known.contains(&metric),
                    "{name} uses {metric}, which the API does not register"
                );
            }
        }
    }
    assert!(count >= 12, "{count} rules");
    // The rules this deployment's guarantees lean on must exist.
    for must in [
        "KavachCheckpointStalled",
        "KavachRevocationRecordMissing",
        "KavachOutcomeWriteFailures",
        "KavachCredentialIdConflict",
    ] {
        assert!(alerts.contains(must), "{must} is shipped");
    }
}

#[test]
fn the_dashboard_is_valid_and_names_real_metrics() {
    let text =
        std::fs::read_to_string(root().join("deploy/monitoring/kavach-dashboard.json")).unwrap();
    let doc: Value = serde_json::from_str(&text).expect("the dashboard is JSON");
    let known = registered();
    let panels = doc["panels"].as_array().expect("panels");
    assert!(panels.len() >= 8);
    let mut ids = BTreeSet::new();
    for panel in panels {
        assert!(
            ids.insert(panel["id"].as_i64().unwrap()),
            "panel ids differ"
        );
        assert!(panel["title"].is_string());
        for target in panel["targets"].as_array().expect("targets") {
            let expr = target["expr"].as_str().expect("an expression");
            for metric in used(expr) {
                assert!(
                    known.contains(&metric),
                    "{}: {metric} is not registered",
                    panel["title"]
                );
            }
        }
    }
}

#[test]
fn the_name_scanner_finds_what_it_should() {
    assert_eq!(
        used(
            "histogram_quantile(0.99, sum by (le) (rate(kavach_gateway_stage_seconds_bucket[5m])))"
        )
        .into_iter()
        .collect::<Vec<_>>(),
        ["kavach_gateway_stage_seconds"]
    );
    assert!(
        used("up{job=\"kavach-api\"} == 0").is_empty(),
        "labels are not metrics"
    );
}

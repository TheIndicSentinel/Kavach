//! Fairness batch report golden tests.

use std::path::{Path, PathBuf};

use kavach_batch::{
    run_disparity_report, run_inclusion_report, DisparityReport, FairnessConfig, FairnessReport,
    InclusionReport,
};

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../golden/finance/fairness")
}

fn load_oracle() -> (PathBuf, serde_json::Value) {
    let dir = fixture_dir();
    let oracle: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dir.join("disparity_customer_segment.json")).unwrap(),
    )
    .unwrap();
    (dir, oracle)
}

fn load_config(config_value: &serde_json::Value) -> FairnessConfig {
    FairnessConfig {
        attribute: config_value["attribute"].as_str().unwrap().into(),
        inclusion_field: config_value["inclusion_field"].as_str().unwrap().into(),
        min_sample_size: usize::try_from(config_value["min_sample_size"].as_u64().unwrap())
            .unwrap(),
        disparity_threshold: config_value["disparity_threshold"].as_f64().unwrap(),
    }
}

fn assert_disparity(disparity: &DisparityReport, expect: &serde_json::Value) {
    assert_eq!(
        disparity.total_evaluated,
        usize::try_from(expect["total_evaluated"].as_u64().unwrap()).unwrap()
    );
    assert_eq!(
        disparity.reference_group,
        expect["reference_group"].as_str().unwrap()
    );
    assert!(
        (disparity.overall_approval_rate - expect["overall_approval_rate"].as_f64().unwrap()).abs()
            < f64::EPSILON
    );
    assert!(
        (disparity.max_disparity_gap - expect["max_disparity_gap"].as_f64().unwrap()).abs()
            < f64::EPSILON
    );
    let flagged: Vec<&str> = disparity
        .flagged
        .iter()
        .map(|group| group.group_value.as_str())
        .collect();
    let expected_flagged: Vec<&str> = expect["flagged_groups"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    assert_eq!(flagged, expected_flagged);

    for group in &disparity.groups {
        let expected = &expect["groups"][&group.group_value];
        assert_eq!(
            group.count,
            usize::try_from(expected["count"].as_u64().unwrap()).unwrap()
        );
        assert!(
            (group.approval_rate - expected["approval_rate"].as_f64().unwrap()).abs()
                < f64::EPSILON
        );
    }
}

fn assert_inclusion(inclusion: &InclusionReport, expect: &serde_json::Value) {
    assert_eq!(
        inclusion.inclusion_count,
        usize::try_from(expect["inclusion_count"].as_u64().unwrap()).unwrap()
    );
    assert_eq!(
        inclusion.non_inclusion_count,
        usize::try_from(expect["non_inclusion_count"].as_u64().unwrap()).unwrap()
    );
    assert!(
        (inclusion.inclusion_approval_rate - expect["inclusion_approval_rate"].as_f64().unwrap())
            .abs()
            < f64::EPSILON
    );
    assert!(
        (inclusion.non_inclusion_approval_rate
            - expect["non_inclusion_approval_rate"].as_f64().unwrap())
        .abs()
            < f64::EPSILON
    );
    assert!(
        (inclusion.approval_gap - expect["approval_gap"].as_f64().unwrap()).abs() < f64::EPSILON
    );
    assert_eq!(inclusion.flagged, expect["flagged"].as_bool().unwrap());
}

fn run_reports(dir: &Path, config: &FairnessConfig) -> (DisparityReport, InclusionReport) {
    let disparity = run_disparity_report(
        &dir.join("sample_requests.ndjson"),
        &dir.join("sample_results.ndjson"),
        config,
    )
    .expect("disparity report");
    let inclusion = run_inclusion_report(
        &dir.join("sample_requests.ndjson"),
        &dir.join("sample_results.ndjson"),
        config,
    )
    .expect("inclusion report");
    (disparity, inclusion)
}

#[test]
fn golden_disparity_customer_segment_report() {
    let (dir, oracle) = load_oracle();
    let config = load_config(&oracle["config"]);
    let (disparity, inclusion) = run_reports(&dir, &config);

    assert_disparity(&disparity, &oracle["expect_disparity"]);
    assert_inclusion(&inclusion, &oracle["expect_inclusion"]);

    let wrapped = FairnessReport::Disparity(disparity);
    let serialized = serde_json::to_value(wrapped).unwrap();
    assert_eq!(serialized["report_type"], "disparity");
}

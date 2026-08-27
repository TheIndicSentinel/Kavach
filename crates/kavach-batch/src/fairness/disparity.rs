use std::path::Path;

use chrono::Utc;
use polars::prelude::*;

use super::join::{evaluable_row, is_approved, join_batch_rows, FairnessRow};
use super::report::{DisparityReport, FairnessConfig, FlaggedGroup, GroupMetric};
use crate::error::BatchError;

pub fn run_disparity_report(
    requests_path: &Path,
    results_path: &Path,
    config: &FairnessConfig,
) -> Result<DisparityReport, BatchError> {
    let rows = join_batch_rows(
        requests_path,
        results_path,
        &config.attribute,
        &config.inclusion_field,
    )?;
    build_disparity_report(&rows, config)
}

pub fn build_disparity_report(
    rows: &[FairnessRow],
    config: &FairnessConfig,
) -> Result<DisparityReport, BatchError> {
    let evaluable: Vec<&FairnessRow> = rows.iter().filter(|row| evaluable_row(row)).collect();
    if evaluable.is_empty() {
        return Err(BatchError::Fairness(
            "no evaluable rows for disparity report".into(),
        ));
    }

    let metrics = aggregate_group_metrics(&evaluable, config.min_sample_size)?;
    let overall_approval_rate = approval_rate(&evaluable);
    let reference_group = metrics
        .first()
        .map(|metric| metric.group_value.clone())
        .ok_or_else(|| BatchError::Fairness("no groups computed".into()))?;
    let reference_rate = metrics
        .first()
        .map_or(overall_approval_rate, |metric| metric.approval_rate);
    let (groups, max_disparity_gap, flagged) =
        annotate_disparity_gaps(metrics, &reference_group, reference_rate, config);

    Ok(DisparityReport {
        attribute: config.attribute.clone(),
        min_sample_size: config.min_sample_size,
        disparity_threshold: config.disparity_threshold,
        total_evaluated: evaluable.len(),
        overall_approval_rate,
        reference_group,
        groups,
        max_disparity_gap,
        flagged,
        generated_at: Utc::now(),
    })
}

fn aggregate_group_metrics(
    evaluable: &[&FairnessRow],
    min_sample_size: usize,
) -> Result<Vec<GroupMetric>, BatchError> {
    let groups: Vec<String> = evaluable
        .iter()
        .map(|row| row.attribute_value.clone())
        .collect();
    let approved: Vec<f64> = evaluable
        .iter()
        .map(|row| f64::from(is_approved(row.returned_decision)))
        .collect();

    let df = df!("group" => groups, "approved" => approved)
        .map_err(|err| BatchError::Fairness(err.to_string()))?;
    let grouped = df
        .lazy()
        .group_by([col("group")])
        .agg([
            col("approved").mean().alias("approval_rate"),
            col("approved").count().alias("count"),
        ])
        .sort(["count"], SortMultipleOptions::default())
        .collect()
        .map_err(|err| BatchError::Fairness(err.to_string()))?;

    let mut metrics = Vec::with_capacity(grouped.height());
    for index in 0..grouped.height() {
        metrics.push(read_group_metric(&grouped, index, min_sample_size)?);
    }
    metrics.sort_by_key(|metric| std::cmp::Reverse(metric.count));
    Ok(metrics)
}

fn read_group_metric(
    grouped: &DataFrame,
    index: usize,
    min_sample_size: usize,
) -> Result<GroupMetric, BatchError> {
    let group_value = grouped
        .column("group")
        .map_err(|err| BatchError::Fairness(err.to_string()))?
        .str()
        .map_err(|err| BatchError::Fairness(err.to_string()))?
        .get(index)
        .ok_or_else(|| BatchError::Fairness("missing group value".into()))?
        .to_string();
    let approval_rate = grouped
        .column("approval_rate")
        .map_err(|err| BatchError::Fairness(err.to_string()))?
        .f64()
        .map_err(|err| BatchError::Fairness(err.to_string()))?
        .get(index)
        .ok_or_else(|| BatchError::Fairness("missing approval_rate".into()))?;
    let count = grouped
        .column("count")
        .map_err(|err| BatchError::Fairness(err.to_string()))?
        .u32()
        .map_err(|err| BatchError::Fairness(err.to_string()))?
        .get(index)
        .ok_or_else(|| BatchError::Fairness("missing count".into()))?
        as usize;
    Ok(GroupMetric {
        group_value,
        count,
        approval_rate,
        sample_sufficient: count >= min_sample_size,
        gap_from_reference: None,
    })
}

fn annotate_disparity_gaps(
    mut metrics: Vec<GroupMetric>,
    reference_group: &str,
    reference_rate: f64,
    config: &FairnessConfig,
) -> (Vec<GroupMetric>, f64, Vec<FlaggedGroup>) {
    let mut max_disparity_gap = 0.0_f64;
    let mut flagged = Vec::new();
    for metric in &mut metrics {
        if metric.group_value == reference_group {
            metric.gap_from_reference = Some(0.0);
            continue;
        }
        let gap = (reference_rate - metric.approval_rate).abs();
        metric.gap_from_reference = Some(gap);
        if metric.sample_sufficient {
            max_disparity_gap = max_disparity_gap.max(gap);
            if gap >= config.disparity_threshold {
                flagged.push(FlaggedGroup {
                    group_value: metric.group_value.clone(),
                    gap_from_reference: gap,
                    approval_rate: metric.approval_rate,
                    reference_approval_rate: reference_rate,
                });
            }
        }
    }
    (metrics, max_disparity_gap, flagged)
}

fn approval_rate(rows: &[&FairnessRow]) -> f64 {
    let approved = rows
        .iter()
        .filter(|row| is_approved(row.returned_decision))
        .count();
    #[allow(clippy::cast_precision_loss)]
    {
        approved as f64 / rows.len() as f64
    }
}

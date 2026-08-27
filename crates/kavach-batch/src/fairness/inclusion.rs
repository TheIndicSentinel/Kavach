use std::path::Path;

use chrono::Utc;

use super::join::{evaluable_row, is_approved, join_batch_rows, FairnessRow};
use super::report::{FairnessConfig, InclusionReport};
use crate::error::BatchError;

pub fn run_inclusion_report(
    requests_path: &Path,
    results_path: &Path,
    config: &FairnessConfig,
) -> Result<InclusionReport, BatchError> {
    let rows = join_batch_rows(
        requests_path,
        results_path,
        &config.attribute,
        &config.inclusion_field,
    )?;
    build_inclusion_report(&rows, config)
}

pub fn build_inclusion_report(
    rows: &[FairnessRow],
    config: &FairnessConfig,
) -> Result<InclusionReport, BatchError> {
    let evaluable: Vec<&FairnessRow> = rows
        .iter()
        .filter(|row| evaluable_row(row) && row.inclusion_value.is_some())
        .collect();

    if evaluable.is_empty() {
        return Err(BatchError::Fairness(
            "no evaluable rows with inclusion field for inclusion report".into(),
        ));
    }

    let mut inclusion_approved = 0usize;
    let mut inclusion_total = 0usize;
    let mut non_inclusion_approved = 0usize;
    let mut non_inclusion_total = 0usize;

    for row in evaluable {
        let approved = is_approved(row.returned_decision);
        if row.inclusion_value == Some(true) {
            inclusion_total += 1;
            if approved {
                inclusion_approved += 1;
            }
        } else {
            non_inclusion_total += 1;
            if approved {
                non_inclusion_approved += 1;
            }
        }
    }

    let inclusion_approval_rate = rate(inclusion_approved, inclusion_total);
    let non_inclusion_approval_rate = rate(non_inclusion_approved, non_inclusion_total);
    let approval_gap = (non_inclusion_approval_rate - inclusion_approval_rate).abs();
    let inclusion_sample_sufficient = inclusion_total >= config.min_sample_size;
    let non_inclusion_sample_sufficient = non_inclusion_total >= config.min_sample_size;
    let flagged = inclusion_sample_sufficient
        && non_inclusion_sample_sufficient
        && approval_gap >= config.disparity_threshold;

    Ok(InclusionReport {
        segment_field: config.inclusion_field.clone(),
        min_sample_size: config.min_sample_size,
        total_evaluated: inclusion_total + non_inclusion_total,
        inclusion_count: inclusion_total,
        inclusion_approval_rate,
        non_inclusion_count: non_inclusion_total,
        non_inclusion_approval_rate,
        approval_gap,
        inclusion_sample_sufficient,
        non_inclusion_sample_sufficient,
        flagged,
        generated_at: Utc::now(),
    })
}

fn rate(approved: usize, total: usize) -> f64 {
    if total == 0 {
        0.0
    } else {
        #[allow(clippy::cast_precision_loss)]
        {
            approved as f64 / total as f64
        }
    }
}

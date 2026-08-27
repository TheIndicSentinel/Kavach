use chrono::{DateTime, Utc};
use serde::Serialize;

#[derive(Debug, Clone)]
pub struct FairnessConfig {
    pub attribute: String,
    pub min_sample_size: usize,
    pub disparity_threshold: f64,
    pub inclusion_field: String,
}

impl Default for FairnessConfig {
    fn default() -> Self {
        Self {
            attribute: "input.customer_segment".into(),
            min_sample_size: 30,
            disparity_threshold: 0.10,
            inclusion_field: "input.informal_sector".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(tag = "report_type", rename_all = "snake_case")]
pub enum FairnessReport {
    Disparity(DisparityReport),
    Inclusion(InclusionReport),
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct DisparityReport {
    pub attribute: String,
    pub min_sample_size: usize,
    pub disparity_threshold: f64,
    pub total_evaluated: usize,
    pub overall_approval_rate: f64,
    pub reference_group: String,
    pub groups: Vec<GroupMetric>,
    pub max_disparity_gap: f64,
    pub flagged: Vec<FlaggedGroup>,
    pub generated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct GroupMetric {
    pub group_value: String,
    pub count: usize,
    pub approval_rate: f64,
    pub sample_sufficient: bool,
    pub gap_from_reference: Option<f64>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct FlaggedGroup {
    pub group_value: String,
    pub gap_from_reference: f64,
    pub approval_rate: f64,
    pub reference_approval_rate: f64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct InclusionReport {
    pub segment_field: String,
    pub min_sample_size: usize,
    pub total_evaluated: usize,
    pub inclusion_count: usize,
    pub inclusion_approval_rate: f64,
    pub non_inclusion_count: usize,
    pub non_inclusion_approval_rate: f64,
    pub approval_gap: f64,
    pub inclusion_sample_sufficient: bool,
    pub non_inclusion_sample_sufficient: bool,
    pub flagged: bool,
    pub generated_at: DateTime<Utc>,
}

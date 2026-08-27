//! Polars-backed fairness batch reports — disparity and inclusion monitoring.

mod disparity;
mod inclusion;
mod join;
mod report;

pub use disparity::{build_disparity_report, run_disparity_report};
pub use inclusion::{build_inclusion_report, run_inclusion_report};
pub use report::{DisparityReport, FairnessConfig, FairnessReport, InclusionReport};

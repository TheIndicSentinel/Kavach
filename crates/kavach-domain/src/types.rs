use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::response::{GovernanceMode, ModelOrigin};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskTier {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelStatus {
    Draft,
    Production,
    Retired,
}

/// Authoritative governance mode — callers cannot override (ADR-001).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelRecord {
    pub model_id: String,
    pub version: String,
    pub sector: String,
    pub owner: String,
    pub risk_tier: RiskTier,
    pub origin: ModelOrigin,
    pub governance_mode: GovernanceMode,
    pub input_schema: Value,
    pub human_review_hold_policy: Option<String>,
    pub status: ModelStatus,
    pub pack_id: String,
    pub purpose: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyPack {
    pub id: String,
    pub version: String,
    pub sector: String,
    pub jurisdiction: String,
    pub effective_from: chrono::DateTime<chrono::Utc>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub cel_runtime_limits: Option<CelRuntimeLimits>,
    pub rules: Vec<PolicyRule>,
    #[serde(default)]
    pub control_mappings: Option<serde_json::Map<String, Value>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CelRuntimeLimits {
    pub timeout_ms: u64,
    pub max_alloc_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: String,
    pub expression: String,
    pub decision: crate::decision::Decision,
    pub reason_code: String,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub control_mappings: Vec<String>,
}

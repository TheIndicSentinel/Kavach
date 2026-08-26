use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::decision::Decision;

pub const SCHEMA_VERSION: &str = "1.0.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceMode {
    Shadow,
    Enforce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelOrigin {
    InHouse,
    Vendor,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvaluateResponse {
    pub policy_decision: Decision,
    pub returned_decision: Decision,
    pub evidence_id: Option<String>,
    pub reason_codes: Vec<String>,
    pub policy_hits: Vec<String>,
    pub latency_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecisionEvent {
    pub schema_version: String,
    pub event_id: String,
    pub evidence_id: String,
    pub prev_hash: String,
    pub hash: String,
    pub pack_id: String,
    pub pack_version: String,
    pub sector: String,
    pub model_id: String,
    pub model_version: String,
    pub model_origin: ModelOrigin,
    pub governance_mode: GovernanceMode,
    pub policy_decision: Decision,
    pub returned_decision: Decision,
    pub reason_codes: Vec<String>,
    pub policy_hits: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pii_tokens: Vec<String>,
    pub input_digest: String,
    pub latency_ms: u64,
    pub decision_time: DateTime<Utc>,
    pub evaluated_at: DateTime<Utc>,
    pub service_identity_id: String,
    pub correlation_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

impl DecisionEvent {
    #[must_use]
    pub fn schema_version_current() -> String {
        SCHEMA_VERSION.to_string()
    }
}

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::DomainError;

/// Public evaluate request — no caller-controlled mode (ADR-001).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvaluateRequest {
    pub model_id: String,
    pub model_version: String,
    pub purpose: String,
    pub consent: Consent,
    pub input: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
    pub decision_time: DateTime<Utc>,
    pub correlation_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Consent {
    pub purpose_id: String,
    pub timestamp: DateTime<Utc>,
    /// Ignored in v1 — reserved for future Consent Manager integration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid: Option<bool>,
}

impl EvaluateRequest {
    /// Consent presence + purpose match only (ADR-001 §9).
    pub fn validate_consent(&self) -> Result<(), DomainError> {
        if self.consent.purpose_id != self.purpose {
            return Err(DomainError::ConsentPurposeMismatch {
                expected: self.purpose.clone(),
                actual: self.consent.purpose_id.clone(),
            });
        }
        Ok(())
    }

    pub fn check_clock_skew(
        &self,
        server_now: DateTime<Utc>,
        max_seconds: i64,
    ) -> Result<(), DomainError> {
        let skew = (self.decision_time - server_now).num_seconds().abs();
        if skew > max_seconds {
            return Err(DomainError::ClockSkew {
                skew_seconds: skew,
                max_seconds,
            });
        }
        Ok(())
    }
}

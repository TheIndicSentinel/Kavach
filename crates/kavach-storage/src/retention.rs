use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TombstoneReason {
    DpdpErasure,
    Retention,
}

impl TombstoneReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DpdpErasure => "dpdp_erasure",
            Self::Retention => "retention",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "dpdp_erasure" => Some(Self::DpdpErasure),
            "retention" => Some(Self::Retention),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RetentionSettings {
    pub evidence_retention_days: u32,
    pub updated_at: DateTime<Utc>,
    pub updated_by: Option<String>,
    pub approved_by: Option<String>,
}

impl Default for RetentionSettings {
    fn default() -> Self {
        Self {
            evidence_retention_days: 365,
            updated_at: Utc::now(),
            updated_by: None,
            approved_by: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TombstoneRecord {
    pub evidence_id: String,
    pub reason: TombstoneReason,
    pub actor_principal: String,
    pub approver_principal: String,
    pub tombstoned_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RetentionApplyReport {
    pub tombstoned_count: usize,
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum RetentionStoreError {
    #[error("retention store io: {0}")]
    Io(String),

    #[error("evidence not found: {0}")]
    NotFound(String),

    #[error("evidence already tombstoned: {0}")]
    AlreadyTombstoned(String),
}

#[derive(Default)]
pub struct MemoryRetentionStore {
    settings: Mutex<RetentionSettings>,
    tombstones: Mutex<HashMap<String, TombstoneRecord>>,
}

impl MemoryRetentionStore {
    pub fn get_settings(&self) -> Result<RetentionSettings, RetentionStoreError> {
        self.settings
            .lock()
            .map_err(|_| RetentionStoreError::Io("lock poisoned".into()))
            .map(|settings| settings.clone())
    }

    pub fn set_settings(
        &self,
        evidence_retention_days: u32,
        actor: &str,
        approver: &str,
    ) -> Result<RetentionSettings, RetentionStoreError> {
        let mut settings = self
            .settings
            .lock()
            .map_err(|_| RetentionStoreError::Io("lock poisoned".into()))?;
        settings.evidence_retention_days = evidence_retention_days;
        settings.updated_at = Utc::now();
        settings.updated_by = Some(actor.into());
        settings.approved_by = Some(approver.into());
        Ok(settings.clone())
    }

    pub fn tombstone(
        &self,
        evidence_id: &str,
        reason: TombstoneReason,
        actor: &str,
        approver: &str,
    ) -> Result<TombstoneRecord, RetentionStoreError> {
        let mut tombstones = self
            .tombstones
            .lock()
            .map_err(|_| RetentionStoreError::Io("lock poisoned".into()))?;
        if tombstones.contains_key(evidence_id) {
            return Err(RetentionStoreError::AlreadyTombstoned(evidence_id.into()));
        }
        let record = TombstoneRecord {
            evidence_id: evidence_id.into(),
            reason,
            actor_principal: actor.into(),
            approver_principal: approver.into(),
            tombstoned_at: Utc::now(),
        };
        tombstones.insert(evidence_id.into(), record.clone());
        Ok(record)
    }

    pub fn is_tombstoned(&self, evidence_id: &str) -> Result<bool, RetentionStoreError> {
        let tombstones = self
            .tombstones
            .lock()
            .map_err(|_| RetentionStoreError::Io("lock poisoned".into()))?;
        Ok(tombstones.contains_key(evidence_id))
    }

    pub fn list_tombstones(&self, limit: u32) -> Result<Vec<TombstoneRecord>, RetentionStoreError> {
        let tombstones = self
            .tombstones
            .lock()
            .map_err(|_| RetentionStoreError::Io("lock poisoned".into()))?;
        let mut records: Vec<_> = tombstones.values().cloned().collect();
        records.sort_by_key(|record| std::cmp::Reverse(record.tombstoned_at));
        records.truncate(limit as usize);
        Ok(records)
    }

    pub fn apply_retention(
        &self,
        candidate_ids: &[String],
        actor: &str,
        approver: &str,
    ) -> Result<RetentionApplyReport, RetentionStoreError> {
        let existing: HashSet<String> = self
            .tombstones
            .lock()
            .map_err(|_| RetentionStoreError::Io("lock poisoned".into()))?
            .keys()
            .cloned()
            .collect();

        let mut evidence_ids = Vec::new();
        for evidence_id in candidate_ids {
            if existing.contains(evidence_id) {
                continue;
            }
            self.tombstone(evidence_id, TombstoneReason::Retention, actor, approver)?;
            evidence_ids.push(evidence_id.clone());
        }

        Ok(RetentionApplyReport {
            tombstoned_count: evidence_ids.len(),
            evidence_ids,
        })
    }
}

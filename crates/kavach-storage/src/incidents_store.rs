use chrono::{DateTime, Utc};
use kavach_evaluate::{EvaluateIncident, IncidentRecorder};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IncidentRecord {
    pub id: i64,
    pub correlation_id: String,
    pub model_id: String,
    pub reason: String,
    pub recorded_at: DateTime<Utc>,
}

#[derive(Debug, thiserror::Error)]
pub enum IncidentStoreError {
    #[error("incident store io: {0}")]
    Io(String),
}

#[derive(Default)]
pub struct MemoryIncidentStore {
    incidents: Mutex<Vec<IncidentRecord>>,
    next_id: Mutex<i64>,
}

impl MemoryIncidentStore {
    pub fn list(&self, limit: u32) -> Result<Vec<IncidentRecord>, IncidentStoreError> {
        let incidents = self
            .incidents
            .lock()
            .map_err(|_| IncidentStoreError::Io("lock poisoned".into()))?;
        let start = incidents.len().saturating_sub(limit as usize);
        Ok(incidents[start..].to_vec())
    }

    pub fn record_incident(&self, incident: EvaluateIncident) -> Result<(), IncidentStoreError> {
        let mut next_id = self
            .next_id
            .lock()
            .map_err(|_| IncidentStoreError::Io("lock poisoned".into()))?;
        *next_id += 1;
        let record = IncidentRecord {
            id: *next_id,
            correlation_id: incident.correlation_id,
            model_id: incident.model_id,
            reason: incident.reason,
            recorded_at: Utc::now(),
        };
        self.incidents
            .lock()
            .map_err(|_| IncidentStoreError::Io("lock poisoned".into()))?
            .push(record);
        Ok(())
    }
}

impl IncidentRecorder for MemoryIncidentStore {
    fn record(&mut self, incident: EvaluateIncident) {
        let _ = self.record_incident(incident);
    }
}

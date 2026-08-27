use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: i64,
    pub action: String,
    pub resource_type: String,
    pub resource_id: String,
    pub actor_principal: String,
    pub approver_principal: String,
    pub payload: Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct AuditInsert {
    pub action: String,
    pub resource_type: String,
    pub resource_id: String,
    pub actor_principal: String,
    pub approver_principal: String,
    pub payload: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimePointers {
    pub pack_path: String,
    pub model_path: String,
    pub previous_pack_path: Option<String>,
    pub updated_at: DateTime<Utc>,
    pub updated_by: String,
    pub approved_by: String,
}

#[derive(Debug, thiserror::Error)]
pub enum AdminStoreError {
    #[error("admin store io: {0}")]
    Io(String),
}

#[derive(Default)]
pub struct MemoryAdminStore {
    audit: Mutex<Vec<AuditEntry>>,
    pointers: Mutex<Option<RuntimePointers>>,
    next_id: Mutex<i64>,
}

impl MemoryAdminStore {
    pub fn append_audit(&self, insert: AuditInsert) -> Result<AuditEntry, AdminStoreError> {
        let mut next_id = self
            .next_id
            .lock()
            .map_err(|_| AdminStoreError::Io("lock poisoned".into()))?;
        *next_id += 1;
        let entry = AuditEntry {
            id: *next_id,
            action: insert.action,
            resource_type: insert.resource_type,
            resource_id: insert.resource_id,
            actor_principal: insert.actor_principal,
            approver_principal: insert.approver_principal,
            payload: insert.payload,
            created_at: Utc::now(),
        };
        self.audit
            .lock()
            .map_err(|_| AdminStoreError::Io("lock poisoned".into()))?
            .push(entry.clone());
        Ok(entry)
    }

    pub fn list_audit(&self, limit: u32) -> Result<Vec<AuditEntry>, AdminStoreError> {
        let audit = self
            .audit
            .lock()
            .map_err(|_| AdminStoreError::Io("lock poisoned".into()))?;
        let start = audit.len().saturating_sub(limit as usize);
        Ok(audit[start..].to_vec())
    }

    pub fn get_runtime_pointers(&self) -> Result<Option<RuntimePointers>, AdminStoreError> {
        Ok(self
            .pointers
            .lock()
            .map_err(|_| AdminStoreError::Io("lock poisoned".into()))?
            .clone())
    }

    pub fn set_runtime_pointers(&self, pointers: RuntimePointers) -> Result<(), AdminStoreError> {
        *self
            .pointers
            .lock()
            .map_err(|_| AdminStoreError::Io("lock poisoned".into()))? = Some(pointers);
        Ok(())
    }
}

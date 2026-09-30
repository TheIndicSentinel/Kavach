use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Mutex;

use kavach_domain::{GovernanceMode, ModelStatus};

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
    /// `sha256:<hex>` of the active pack file at activation time.
    pub pack_sha256: Option<String>,
    /// `sha256:<hex>` of the previous pack file, checked on rollback.
    pub previous_pack_sha256: Option<String>,
    /// `sha256:<hex>` of the active model file (`None`: pinned at next start).
    #[serde(default)]
    pub model_sha256: Option<String>,
    pub updated_at: DateTime<Utc>,
    pub updated_by: String,
    pub approved_by: String,
    /// Monotonic version assigned by the store on every write (the value
    /// passed in is ignored). Change requests bind to it.
    #[serde(default)]
    pub version: i64,
}

/// Governed mutable fields of a model record (ADR-010).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelState {
    pub model_id: String,
    pub status: ModelStatus,
    pub governance_mode: GovernanceMode,
    pub updated_at: DateTime<Utc>,
    pub updated_by: String,
    pub approved_by: String,
}

#[must_use]
pub fn status_str(status: ModelStatus) -> &'static str {
    match status {
        ModelStatus::Draft => "draft",
        ModelStatus::Production => "production",
        ModelStatus::Retired => "retired",
    }
}

#[must_use]
pub fn mode_str(mode: GovernanceMode) -> &'static str {
    match mode {
        GovernanceMode::Shadow => "shadow",
        GovernanceMode::Enforce => "enforce",
    }
}

pub fn parse_status(value: &str) -> Option<ModelStatus> {
    match value {
        "draft" => Some(ModelStatus::Draft),
        "production" => Some(ModelStatus::Production),
        "retired" => Some(ModelStatus::Retired),
        _ => None,
    }
}

pub fn parse_mode(value: &str) -> Option<GovernanceMode> {
    match value {
        "shadow" => Some(GovernanceMode::Shadow),
        "enforce" => Some(GovernanceMode::Enforce),
        _ => None,
    }
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
    models: Mutex<HashMap<String, ModelState>>,
}

fn poisoned<T>(_: T) -> AdminStoreError {
    AdminStoreError::Io("lock poisoned".into())
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
        let mut current = self
            .pointers
            .lock()
            .map_err(|_| AdminStoreError::Io("lock poisoned".into()))?;
        let version = current.as_ref().map_or(0, |p| p.version) + 1;
        *current = Some(RuntimePointers {
            version,
            ..pointers
        });
        Ok(())
    }

    /// Writes the pointer only if none exists; returns whether it wrote.
    pub fn insert_pointers_if_absent(
        &self,
        pointers: RuntimePointers,
    ) -> Result<bool, AdminStoreError> {
        let mut current = self.pointers.lock().map_err(poisoned)?;
        if current.is_some() {
            return Ok(false);
        }
        *current = Some(RuntimePointers {
            version: 1,
            ..pointers
        });
        Ok(true)
    }

    pub fn get_model_state(&self, model_id: &str) -> Result<Option<ModelState>, AdminStoreError> {
        Ok(self.models.lock().map_err(poisoned)?.get(model_id).cloned())
    }

    pub fn list_model_states(&self) -> Result<Vec<ModelState>, AdminStoreError> {
        Ok(self
            .models
            .lock()
            .map_err(poisoned)?
            .values()
            .cloned()
            .collect())
    }

    /// Inserts unless a state exists; returns whether it inserted.
    pub fn insert_model_state_if_absent(&self, state: ModelState) -> Result<bool, AdminStoreError> {
        let mut models = self.models.lock().map_err(poisoned)?;
        if models.contains_key(&state.model_id) {
            return Ok(false);
        }
        models.insert(state.model_id.clone(), state);
        Ok(true)
    }

    pub fn set_model_state(&self, state: ModelState) -> Result<(), AdminStoreError> {
        self.models
            .lock()
            .map_err(poisoned)?
            .insert(state.model_id.clone(), state);
        Ok(())
    }

    pub fn last_audit(
        &self,
        action: &str,
        resource_id: &str,
    ) -> Result<Option<AuditEntry>, AdminStoreError> {
        Ok(self
            .audit
            .lock()
            .map_err(poisoned)?
            .iter()
            .rev()
            .find(|e| e.action == action && e.resource_id == resource_id)
            .cloned())
    }
}

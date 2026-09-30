use chrono::{DateTime, Utc};
use sqlx::PgPool;

use crate::admin::{
    mode_str, parse_mode, parse_status, status_str, AdminStoreError, AuditEntry, AuditInsert,
    ModelState, RuntimePointers,
};

#[derive(Clone)]
pub struct PostgresAdminStore {
    pool: PgPool,
}

impl PostgresAdminStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn append_audit(&self, insert: AuditInsert) -> Result<AuditEntry, AdminStoreError> {
        let row = sqlx::query_as::<_, AuditRow>(
            "INSERT INTO admin_audit_log \
                (action, resource_type, resource_id, actor_principal, approver_principal, payload) \
            VALUES ($1, $2, $3, $4, $5, $6) \
            RETURNING id, action, resource_type, resource_id, actor_principal, approver_principal, payload, created_at",
        )
        .bind(&insert.action)
        .bind(&insert.resource_type)
        .bind(&insert.resource_id)
        .bind(&insert.actor_principal)
        .bind(&insert.approver_principal)
        .bind(insert.payload)
        .fetch_one(&self.pool)
        .await
        .map_err(|err| AdminStoreError::Io(err.to_string()))?;

        Ok(row.into_entry())
    }

    pub async fn list_audit(&self, limit: i64) -> Result<Vec<AuditEntry>, AdminStoreError> {
        let rows = sqlx::query_as::<_, AuditRow>(
            "SELECT id, action, resource_type, resource_id, actor_principal, approver_principal, payload, created_at \
            FROM admin_audit_log ORDER BY created_at DESC LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|err| AdminStoreError::Io(err.to_string()))?;

        Ok(rows.into_iter().map(AuditRow::into_entry).collect())
    }

    pub async fn get_runtime_pointers(&self) -> Result<Option<RuntimePointers>, AdminStoreError> {
        let row = sqlx::query_as::<_, PointerRow>(
            "SELECT pack_path, model_path, previous_pack_path, pack_sha256, previous_pack_sha256, \
            model_sha256, updated_at, updated_by, approved_by, version \
            FROM runtime_pointers WHERE id = 1",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|err| AdminStoreError::Io(err.to_string()))?;

        Ok(row.map(PointerRow::into_pointers))
    }

    pub async fn set_runtime_pointers(
        &self,
        pointers: RuntimePointers,
    ) -> Result<(), AdminStoreError> {
        upsert_pointers(&self.pool, &pointers).await
    }

    /// Writes the pointer only if none exists (concurrent first starts);
    /// returns whether this call wrote it.
    pub async fn insert_pointers_if_absent(
        &self,
        pointers: &RuntimePointers,
    ) -> Result<bool, AdminStoreError> {
        let result = sqlx::query(
            "INSERT INTO runtime_pointers (id, pack_path, model_path, previous_pack_path, \
                pack_sha256, previous_pack_sha256, model_sha256, updated_at, updated_by, \
                approved_by, version) \
            VALUES (1, $1, $2, NULL, $3, NULL, $4, $5, $6, $7, 1) \
            ON CONFLICT (id) DO NOTHING",
        )
        .bind(&pointers.pack_path)
        .bind(&pointers.model_path)
        .bind(&pointers.pack_sha256)
        .bind(&pointers.model_sha256)
        .bind(pointers.updated_at)
        .bind(&pointers.updated_by)
        .bind(&pointers.approved_by)
        .execute(&self.pool)
        .await
        .map_err(|err| AdminStoreError::Io(err.to_string()))?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn get_model_state(
        &self,
        model_id: &str,
    ) -> Result<Option<ModelState>, AdminStoreError> {
        let row = sqlx::query_as::<_, ModelStateRow>(
            "SELECT model_id, status, governance_mode, updated_at, updated_by, approved_by \
            FROM model_state WHERE tenant_id = 'default' AND model_id = $1",
        )
        .bind(model_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|err| AdminStoreError::Io(err.to_string()))?;
        row.map(ModelStateRow::into_state).transpose()
    }

    pub async fn list_model_states(&self) -> Result<Vec<ModelState>, AdminStoreError> {
        let rows = sqlx::query_as::<_, ModelStateRow>(
            "SELECT model_id, status, governance_mode, updated_at, updated_by, approved_by \
            FROM model_state WHERE tenant_id = 'default' ORDER BY model_id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|err| AdminStoreError::Io(err.to_string()))?;
        rows.into_iter().map(ModelStateRow::into_state).collect()
    }

    /// Inserts unless a state exists (concurrent first starts); returns
    /// whether this call inserted it.
    pub async fn insert_model_state_if_absent(
        &self,
        state: &ModelState,
    ) -> Result<bool, AdminStoreError> {
        let result = sqlx::query(
            "INSERT INTO model_state (model_id, status, governance_mode, updated_at, updated_by, \
                approved_by) VALUES ($1, $2, $3, $4, $5, $6) \
            ON CONFLICT (tenant_id, model_id) DO NOTHING",
        )
        .bind(&state.model_id)
        .bind(status_str(state.status))
        .bind(mode_str(state.governance_mode))
        .bind(state.updated_at)
        .bind(&state.updated_by)
        .bind(&state.approved_by)
        .execute(&self.pool)
        .await
        .map_err(|err| AdminStoreError::Io(err.to_string()))?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn last_audit(
        &self,
        action: &str,
        resource_id: &str,
    ) -> Result<Option<AuditEntry>, AdminStoreError> {
        let row = sqlx::query_as::<_, AuditRow>(
            "SELECT id, action, resource_type, resource_id, actor_principal, approver_principal, \
                payload, created_at \
            FROM admin_audit_log WHERE action = $1 AND resource_id = $2 ORDER BY id DESC LIMIT 1",
        )
        .bind(action)
        .bind(resource_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|err| AdminStoreError::Io(err.to_string()))?;
        Ok(row.map(AuditRow::into_entry))
    }
}

/// Upserts a model's governed state (inside the approval transaction).
pub(crate) async fn upsert_model_state<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    state: &ModelState,
) -> Result<(), AdminStoreError> {
    sqlx::query(
        "INSERT INTO model_state (model_id, status, governance_mode, updated_at, updated_by, \
            approved_by) VALUES ($1, $2, $3, $4, $5, $6) \
        ON CONFLICT (tenant_id, model_id) DO UPDATE SET status = EXCLUDED.status, \
            governance_mode = EXCLUDED.governance_mode, updated_at = EXCLUDED.updated_at, \
            updated_by = EXCLUDED.updated_by, approved_by = EXCLUDED.approved_by",
    )
    .bind(&state.model_id)
    .bind(status_str(state.status))
    .bind(mode_str(state.governance_mode))
    .bind(state.updated_at)
    .bind(&state.updated_by)
    .bind(&state.approved_by)
    .execute(executor)
    .await
    .map_err(|err| AdminStoreError::Io(err.to_string()))?;
    Ok(())
}

#[derive(sqlx::FromRow)]
struct ModelStateRow {
    model_id: String,
    status: String,
    governance_mode: String,
    updated_at: DateTime<Utc>,
    updated_by: String,
    approved_by: String,
}

impl ModelStateRow {
    fn into_state(self) -> Result<ModelState, AdminStoreError> {
        Ok(ModelState {
            status: parse_status(&self.status)
                .ok_or_else(|| AdminStoreError::Io(format!("model status {}", self.status)))?,
            governance_mode: parse_mode(&self.governance_mode).ok_or_else(|| {
                AdminStoreError::Io(format!("governance mode {}", self.governance_mode))
            })?,
            model_id: self.model_id,
            updated_at: self.updated_at,
            updated_by: self.updated_by,
            approved_by: self.approved_by,
        })
    }
}

/// Writes the singleton pointer row and increments its version.
pub(crate) async fn upsert_pointers<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    pointers: &RuntimePointers,
) -> Result<(), AdminStoreError> {
    sqlx::query(
        "INSERT INTO runtime_pointers (id, pack_path, model_path, previous_pack_path, \
                pack_sha256, previous_pack_sha256, updated_at, updated_by, approved_by, version, \
                model_sha256) \
            VALUES (1, $1, $2, $3, $4, $5, $6, $7, $8, 1, $9) \
            ON CONFLICT (id) DO UPDATE SET \
                pack_path = EXCLUDED.pack_path, \
                model_path = EXCLUDED.model_path, \
                previous_pack_path = EXCLUDED.previous_pack_path, \
                pack_sha256 = EXCLUDED.pack_sha256, \
                previous_pack_sha256 = EXCLUDED.previous_pack_sha256, \
                updated_at = EXCLUDED.updated_at, \
                updated_by = EXCLUDED.updated_by, \
                approved_by = EXCLUDED.approved_by, \
                model_sha256 = EXCLUDED.model_sha256, \
                version = runtime_pointers.version + 1",
    )
    .bind(&pointers.pack_path)
    .bind(&pointers.model_path)
    .bind(&pointers.previous_pack_path)
    .bind(&pointers.pack_sha256)
    .bind(&pointers.previous_pack_sha256)
    .bind(pointers.updated_at)
    .bind(&pointers.updated_by)
    .bind(&pointers.approved_by)
    .bind(&pointers.model_sha256)
    .execute(executor)
    .await
    .map_err(|err| AdminStoreError::Io(err.to_string()))?;
    Ok(())
}

/// Appends one audit row (inside a caller's transaction when given one).
pub(crate) async fn insert_audit<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    insert: &AuditInsert,
) -> Result<(), AdminStoreError> {
    sqlx::query(
        "INSERT INTO admin_audit_log \
            (action, resource_type, resource_id, actor_principal, approver_principal, payload) \
        VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(&insert.action)
    .bind(&insert.resource_type)
    .bind(&insert.resource_id)
    .bind(&insert.actor_principal)
    .bind(&insert.approver_principal)
    .bind(&insert.payload)
    .execute(executor)
    .await
    .map_err(|err| AdminStoreError::Io(err.to_string()))?;
    Ok(())
}

#[derive(sqlx::FromRow)]
struct AuditRow {
    id: i64,
    action: String,
    resource_type: String,
    resource_id: String,
    actor_principal: String,
    approver_principal: String,
    payload: serde_json::Value,
    created_at: DateTime<Utc>,
}

impl AuditRow {
    fn into_entry(self) -> AuditEntry {
        AuditEntry {
            id: self.id,
            action: self.action,
            resource_type: self.resource_type,
            resource_id: self.resource_id,
            actor_principal: self.actor_principal,
            approver_principal: self.approver_principal,
            payload: self.payload,
            created_at: self.created_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct PointerRow {
    pack_path: String,
    model_path: String,
    previous_pack_path: Option<String>,
    pack_sha256: Option<String>,
    previous_pack_sha256: Option<String>,
    model_sha256: Option<String>,
    updated_at: DateTime<Utc>,
    updated_by: String,
    approved_by: String,
    version: i64,
}

impl PointerRow {
    fn into_pointers(self) -> RuntimePointers {
        RuntimePointers {
            pack_path: self.pack_path,
            model_path: self.model_path,
            previous_pack_path: self.previous_pack_path,
            pack_sha256: self.pack_sha256,
            previous_pack_sha256: self.previous_pack_sha256,
            model_sha256: self.model_sha256,
            updated_at: self.updated_at,
            updated_by: self.updated_by,
            approved_by: self.approved_by,
            version: self.version,
        }
    }
}

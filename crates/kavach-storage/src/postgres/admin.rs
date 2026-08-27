use chrono::{DateTime, Utc};
use sqlx::PgPool;

use crate::admin::{AdminStoreError, AuditEntry, AuditInsert, RuntimePointers};

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
            "SELECT pack_path, model_path, previous_pack_path, updated_at, updated_by, approved_by \
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
        sqlx::query(
            "INSERT INTO runtime_pointers (id, pack_path, model_path, previous_pack_path, updated_at, updated_by, approved_by) \
            VALUES (1, $1, $2, $3, $4, $5, $6) \
            ON CONFLICT (id) DO UPDATE SET \
                pack_path = EXCLUDED.pack_path, \
                model_path = EXCLUDED.model_path, \
                previous_pack_path = EXCLUDED.previous_pack_path, \
                updated_at = EXCLUDED.updated_at, \
                updated_by = EXCLUDED.updated_by, \
                approved_by = EXCLUDED.approved_by",
        )
        .bind(&pointers.pack_path)
        .bind(&pointers.model_path)
        .bind(&pointers.previous_pack_path)
        .bind(pointers.updated_at)
        .bind(&pointers.updated_by)
        .bind(&pointers.approved_by)
        .execute(&self.pool)
        .await
        .map_err(|err| AdminStoreError::Io(err.to_string()))?;
        Ok(())
    }
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
    updated_at: DateTime<Utc>,
    updated_by: String,
    approved_by: String,
}

impl PointerRow {
    fn into_pointers(self) -> RuntimePointers {
        RuntimePointers {
            pack_path: self.pack_path,
            model_path: self.model_path,
            previous_pack_path: self.previous_pack_path,
            updated_at: self.updated_at,
            updated_by: self.updated_by,
            approved_by: self.approved_by,
        }
    }
}

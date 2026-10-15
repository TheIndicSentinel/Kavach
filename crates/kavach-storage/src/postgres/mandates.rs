//! Postgres `MandateStore` and `ReplayGuard` (ADR-011).
//!
//! Store invariant: a mandate is `Active` only if every ancestor is `Active`.
//! `insert_child` and `revoke_tree` serialise per tenant on a transaction
//! advisory lock, so a child is never inserted under a parent that a
//! concurrent revocation is revoking (and never missed by it). Delegation and
//! revocation are rare; root issuance and reads take no lock.

use chrono::{DateTime, Utc};
use kavach_domain::mandate::{Mandate, MandateStatus, RevocationReason};
use kavach_ports::{
    AppliedRevocation, MandateStore, PortError, ReplayGuard, RevocationApply, RevocationCursor,
    StoredMandate, StoredRevocation,
};
use sqlx::{PgPool, Postgres, Row, Transaction};

/// Bound on recursive walks (above the delegation depth cap), so a corrupted
/// cycle cannot recurse forever.
const WALK_LIMIT: i32 = 16;

fn unavailable(err: &sqlx::Error) -> PortError {
    PortError::unavailable(format!("mandate store: {err}"))
}

fn is_unique_violation(err: &sqlx::Error) -> bool {
    matches!(err, sqlx::Error::Database(db) if db.code().as_deref() == Some("23505"))
}

fn reason_str(reason: RevocationReason) -> String {
    serde_json::to_value(reason)
        .ok()
        .and_then(|v| v.as_str().map(ToString::to_string))
        .unwrap_or_default()
}

fn parse_reason(value: &str) -> Option<RevocationReason> {
    serde_json::from_value(serde_json::Value::String(value.into())).ok()
}

#[derive(Clone)]
pub struct PostgresMandateStore {
    pool: PgPool,
}

impl PostgresMandateStore {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    async fn lock_tenant(
        tx: &mut Transaction<'_, Postgres>,
        tenant_id: &str,
    ) -> Result<(), PortError> {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('kavach-mandates:' || $1, 0))")
            .bind(tenant_id)
            .execute(&mut **tx)
            .await
            .map_err(|e| unavailable(&e))?;
        Ok(())
    }

    /// Revokes `id` and its active descendants inside a transaction that
    /// already holds the tenant lock.
    async fn revoke_tree_in(
        tx: &mut Transaction<'_, Postgres>,
        tenant_id: &str,
        id: &str,
        reason: RevocationReason,
    ) -> Result<Vec<(String, RevocationReason)>, PortError> {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM mandates WHERE tenant_id = $1 AND id = $2)",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| unavailable(&e))?;
        if !exists {
            return Err(PortError::rejected(format!("unknown mandate {id}")));
        }
        let rows = sqlx::query(
            "WITH RECURSIVE sub AS ( \
                SELECT id, 0 AS lvl FROM mandates WHERE tenant_id = $1 AND id = $2 \
              UNION ALL \
                SELECT m.id, sub.lvl + 1 FROM mandates m JOIN sub ON m.parent_id = sub.id \
                WHERE m.tenant_id = $1 AND sub.lvl < $5 \
            ) \
            UPDATE mandates SET status = 'revoked', \
                revoked_reason = CASE WHEN id = $2 THEN $3 ELSE $4 END \
            WHERE tenant_id = $1 AND status = 'active' AND id IN (SELECT id FROM sub) \
            RETURNING id, revoked_reason",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(reason_str(reason))
        .bind(reason_str(RevocationReason::ParentRevoked))
        .bind(WALK_LIMIT)
        .fetch_all(&mut **tx)
        .await
        .map_err(|e| unavailable(&e))?;
        rows.iter()
            .map(|row| {
                let id: String = row.try_get("id").map_err(|e| unavailable(&e))?;
                let why: String = row.try_get("revoked_reason").map_err(|e| unavailable(&e))?;
                Ok((
                    id,
                    parse_reason(&why).unwrap_or(RevocationReason::ParentRevoked),
                ))
            })
            .collect()
    }

    async fn insert_row<'e>(
        executor: impl sqlx::PgExecutor<'e>,
        record: &StoredMandate,
    ) -> Result<(), PortError> {
        let m = &record.mandate;
        let json = serde_json::to_value(m)
            .map_err(|e| PortError::invalid(format!("mandate json: {e}")))?;
        let status = match record.status {
            MandateStatus::Active => "active",
            MandateStatus::Revoked => "revoked",
        };
        sqlx::query(
            "INSERT INTO mandates (tenant_id, id, parent_id, depth, status, revoked_reason, token, \
                mandate, source_system, source_event_id) \
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(&m.tenant_id)
        .bind(&m.id)
        .bind(&m.parent_id)
        .bind(i16::from(m.depth))
        .bind(status)
        .bind(record.revoked_reason.map(reason_str))
        .bind(&record.token)
        .bind(json)
        .bind(&m.source.system)
        .bind(&m.source.event_id)
        .execute(executor)
        .await
        .map_err(|e| {
            if is_unique_violation(&e) {
                PortError::rejected(format!(
                    "mandate {} exists, or event {} already issued a mandate",
                    m.id, m.source.event_id
                ))
            } else {
                unavailable(&e)
            }
        })?;
        Ok(())
    }
}

fn row_to_stored(row: &sqlx::postgres::PgRow) -> Result<StoredMandate, PortError> {
    let json: serde_json::Value = row.try_get("mandate").map_err(|e| unavailable(&e))?;
    let mandate: Mandate = serde_json::from_value(json)
        .map_err(|e| PortError::invalid(format!("stored mandate json: {e}")))?;
    let status: String = row.try_get("status").map_err(|e| unavailable(&e))?;
    let reason: Option<String> = row.try_get("revoked_reason").map_err(|e| unavailable(&e))?;
    Ok(StoredMandate {
        mandate,
        token: row.try_get("token").map_err(|e| unavailable(&e))?,
        status: if status == "active" {
            MandateStatus::Active
        } else {
            MandateStatus::Revoked
        },
        revoked_reason: reason.as_deref().and_then(parse_reason),
    })
}

impl MandateStore for PostgresMandateStore {
    async fn insert(&self, record: StoredMandate) -> Result<(), PortError> {
        if record.mandate.parent_id.is_some() {
            return Err(PortError::rejected(
                "a delegated mandate needs insert_child",
            ));
        }
        Self::insert_row(&self.pool, &record).await
    }

    async fn insert_child(&self, record: StoredMandate) -> Result<(), PortError> {
        let Some(parent_id) = record.mandate.parent_id.clone() else {
            return Err(PortError::rejected("insert_child needs a parent"));
        };
        let tenant = record.mandate.tenant_id.clone();
        let mut tx = self.pool.begin().await.map_err(|e| unavailable(&e))?;
        Self::lock_tenant(&mut tx, &tenant).await?;
        let status: Option<String> =
            sqlx::query_scalar("SELECT status FROM mandates WHERE tenant_id = $1 AND id = $2")
                .bind(&tenant)
                .bind(&parent_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| unavailable(&e))?;
        if status.as_deref() != Some("active") {
            return Err(PortError::rejected(format!(
                "parent mandate {parent_id} is not active"
            )));
        }
        Self::insert_row(&mut *tx, &record).await?;
        tx.commit().await.map_err(|e| unavailable(&e))
    }

    async fn get(&self, tenant_id: &str, id: &str) -> Result<Option<StoredMandate>, PortError> {
        let row = sqlx::query(
            "SELECT mandate, token, status, revoked_reason FROM mandates \
            WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| unavailable(&e))?;
        row.as_ref().map(row_to_stored).transpose()
    }

    async fn root_for_event(
        &self,
        tenant_id: &str,
        system: &str,
        event_id: &str,
    ) -> Result<Option<StoredMandate>, PortError> {
        let row = sqlx::query(
            "SELECT mandate, token, status, revoked_reason FROM mandates \
            WHERE tenant_id = $1 AND source_system = $2 AND source_event_id = $3 \
            AND parent_id IS NULL",
        )
        .bind(tenant_id)
        .bind(system)
        .bind(event_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| unavailable(&e))?;
        row.as_ref().map(row_to_stored).transpose()
    }

    async fn ancestors(
        &self,
        tenant_id: &str,
        id: &str,
        limit: usize,
    ) -> Result<Vec<StoredMandate>, PortError> {
        let limit = i32::try_from(limit).unwrap_or(WALK_LIMIT).min(WALK_LIMIT);
        let rows = sqlx::query(
            "WITH RECURSIVE up AS ( \
                SELECT p.tenant_id, p.id, p.parent_id, p.mandate, p.token, p.status, \
                    p.revoked_reason, 1 AS n \
                FROM mandates c JOIN mandates p ON p.tenant_id = c.tenant_id AND p.id = c.parent_id \
                WHERE c.tenant_id = $1 AND c.id = $2 \
              UNION ALL \
                SELECT p.tenant_id, p.id, p.parent_id, p.mandate, p.token, p.status, \
                    p.revoked_reason, up.n + 1 \
                FROM up JOIN mandates p ON p.tenant_id = up.tenant_id AND p.id = up.parent_id \
                WHERE up.n < $3 \
            ) SELECT mandate, token, status, revoked_reason FROM up ORDER BY n",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| unavailable(&e))?;
        rows.iter().map(row_to_stored).collect()
    }

    async fn revoke_tree(
        &self,
        tenant_id: &str,
        id: &str,
        reason: RevocationReason,
    ) -> Result<Vec<(String, RevocationReason)>, PortError> {
        let mut tx = self.pool.begin().await.map_err(|e| unavailable(&e))?;
        Self::lock_tenant(&mut tx, tenant_id).await?;
        let changed = Self::revoke_tree_in(&mut tx, tenant_id, id, reason).await?;
        tx.commit().await.map_err(|e| unavailable(&e))?;
        Ok(changed)
    }

    async fn apply_revocation(
        &self,
        request: RevocationApply,
    ) -> Result<AppliedRevocation, PortError> {
        let mut tx = self.pool.begin().await.map_err(|e| unavailable(&e))?;
        // The tenant lock every mandate write takes (delegation, revoke
        // tree), so the revocation serialises with all of them.
        Self::lock_tenant(&mut tx, &request.tenant_id).await?;
        let existing = sqlx::query(&format!(
            "SELECT {REVOCATION_COLUMNS} FROM mandate_revocations \
            WHERE tenant_id = $1 AND source_system = $2 AND event_id = $3"
        ))
        .bind(&request.tenant_id)
        .bind(&request.system)
        .bind(&request.event_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| unavailable(&e))?;
        if let Some(row) = existing {
            let stored = row_to_revocation(&row)?;
            if stored.event_digest != request.event_digest
                && stored.event_digest != request.legacy_digest
            {
                return Err(PortError::rejected(format!(
                    "event {} was already used with different content",
                    request.event_id
                )));
            }
            return Ok(AppliedRevocation {
                stored,
                changed: Vec::new(),
                replayed: true,
            });
        }
        let rows = sqlx::query(
            "SELECT id, mandate, token, status, revoked_reason FROM mandates \
            WHERE tenant_id = $1 AND source_system = $2 \
            AND mandate -> 'source' ->> 'record_ref' = $3 \
            AND parent_id IS NULL AND status = 'active' \
            ORDER BY created_at, id",
        )
        .bind(&request.tenant_id)
        .bind(&request.system)
        .bind(&request.record_ref)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| unavailable(&e))?;
        let mut changed = Vec::new();
        for row in &rows {
            let root = row_to_stored(row)?;
            // A revocation never reaches forward (ADR-012 §3).
            if root.mandate.nbf <= request.occurred_at {
                changed.extend(
                    Self::revoke_tree_in(
                        &mut tx,
                        &request.tenant_id,
                        &root.mandate.id,
                        request.reason,
                    )
                    .await?,
                );
            }
        }
        let stored = StoredRevocation {
            tenant_id: request.tenant_id,
            system: request.system,
            event_id: request.event_id,
            event_digest: request.event_digest,
            event_type: request.event_type,
            record_ref: request.record_ref,
            occurred_at: request.occurred_at,
            revoked: changed.iter().map(|(id, _)| id.clone()).collect(),
            revoked_at: request.revoked_at,
            clock_synced: Some(request.clock_synced),
        };
        let revoked = serde_json::to_value(&stored.revoked)
            .map_err(|e| PortError::invalid(format!("revoked ids: {e}")))?;
        sqlx::query(
            "INSERT INTO mandate_revocations (tenant_id, source_system, event_id, \
            content_sha256, event_type, record_ref, occurred_at, revoked, created_at, \
            clock_synced) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(&stored.tenant_id)
        .bind(&stored.system)
        .bind(&stored.event_id)
        .bind(&stored.event_digest)
        .bind(&stored.event_type)
        .bind(&stored.record_ref)
        .bind(stored.occurred_at)
        .bind(revoked)
        .bind(stored.revoked_at)
        .bind(stored.clock_synced)
        .execute(&mut *tx)
        .await
        .map_err(|e| unavailable(&e))?;
        // Commits the revocation and its record together, or neither.
        tx.commit().await.map_err(|e| unavailable(&e))?;
        Ok(AppliedRevocation {
            stored,
            changed,
            replayed: false,
        })
    }

    async fn live_roots_for_record(
        &self,
        tenant_id: &str,
        system: &str,
        record_ref: &str,
    ) -> Result<Vec<StoredMandate>, PortError> {
        let rows = sqlx::query(
            "SELECT mandate, token, status, revoked_reason FROM mandates \
            WHERE tenant_id = $1 AND source_system = $2 \
            AND mandate -> 'source' ->> 'record_ref' = $3 \
            AND parent_id IS NULL AND status = 'active' \
            ORDER BY created_at",
        )
        .bind(tenant_id)
        .bind(system)
        .bind(record_ref)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| unavailable(&e))?;
        rows.iter().map(row_to_stored).collect()
    }

    async fn active_held_by(
        &self,
        tenant_id: &str,
        holder: &str,
    ) -> Result<Vec<String>, PortError> {
        let rows = sqlx::query(
            "SELECT id FROM mandates \
            WHERE tenant_id = $1 AND mandate ->> 'holder' = $2 AND status = 'active' \
            ORDER BY created_at, id",
        )
        .bind(tenant_id)
        .bind(holder)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| unavailable(&e))?;
        rows.iter()
            .map(|row| row.try_get("id").map_err(|e| unavailable(&e)))
            .collect()
    }

    async fn record_revocation(&self, revocation: StoredRevocation) -> Result<(), PortError> {
        let revoked = serde_json::to_value(&revocation.revoked)
            .map_err(|e| PortError::invalid(format!("revoked ids: {e}")))?;
        let inserted = sqlx::query(
            "INSERT INTO mandate_revocations (tenant_id, source_system, event_id, \
            content_sha256, event_type, record_ref, occurred_at, revoked, created_at, \
            clock_synced) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(&revocation.tenant_id)
        .bind(&revocation.system)
        .bind(&revocation.event_id)
        .bind(&revocation.event_digest)
        .bind(&revocation.event_type)
        .bind(&revocation.record_ref)
        .bind(revocation.occurred_at)
        .bind(revoked)
        .bind(revocation.revoked_at)
        .bind(revocation.clock_synced)
        .execute(&self.pool)
        .await;
        match inserted {
            Ok(_) => Ok(()),
            Err(e) if is_unique_violation(&e) => Err(PortError::rejected(format!(
                "revocation event {} was recorded already",
                revocation.event_id
            ))),
            Err(e) => Err(unavailable(&e)),
        }
    }

    async fn revocation_for_event(
        &self,
        tenant_id: &str,
        system: &str,
        event_id: &str,
    ) -> Result<Option<StoredRevocation>, PortError> {
        let row = sqlx::query(&format!(
            "SELECT {REVOCATION_COLUMNS} FROM mandate_revocations \
            WHERE tenant_id = $1 AND source_system = $2 AND event_id = $3"
        ))
        .bind(tenant_id)
        .bind(system)
        .bind(event_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| unavailable(&e))?;
        row.as_ref().map(row_to_revocation).transpose()
    }

    async fn revocations_after(
        &self,
        after: Option<RevocationCursor>,
        limit: u32,
    ) -> Result<Vec<StoredRevocation>, PortError> {
        let after = after.unwrap_or_else(|| RevocationCursor::at(DateTime::<Utc>::UNIX_EPOCH));
        let rows = sqlx::query(&format!(
            "SELECT {REVOCATION_COLUMNS} FROM mandate_revocations \
            WHERE (created_at, tenant_id, source_system, event_id) > ($1, $2, $3, $4) \
            ORDER BY created_at, tenant_id, source_system, event_id LIMIT $5"
        ))
        .bind(after.revoked_at)
        .bind(&after.tenant_id)
        .bind(&after.system)
        .bind(&after.event_id)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(|e| unavailable(&e))?;
        rows.iter().map(row_to_revocation).collect()
    }
}

const REVOCATION_COLUMNS: &str = "tenant_id, source_system, event_id, content_sha256, \
    event_type, record_ref, occurred_at, revoked, created_at, clock_synced";

fn row_to_revocation(row: &sqlx::postgres::PgRow) -> Result<StoredRevocation, PortError> {
    let revoked: serde_json::Value = row.try_get("revoked").map_err(|e| unavailable(&e))?;
    Ok(StoredRevocation {
        tenant_id: row.try_get("tenant_id").map_err(|e| unavailable(&e))?,
        system: row.try_get("source_system").map_err(|e| unavailable(&e))?,
        event_id: row.try_get("event_id").map_err(|e| unavailable(&e))?,
        event_digest: row.try_get("content_sha256").map_err(|e| unavailable(&e))?,
        event_type: row.try_get("event_type").map_err(|e| unavailable(&e))?,
        record_ref: row.try_get("record_ref").map_err(|e| unavailable(&e))?,
        occurred_at: row.try_get("occurred_at").map_err(|e| unavailable(&e))?,
        revoked: serde_json::from_value(revoked)
            .map_err(|e| PortError::invalid(format!("stored revoked ids: {e}")))?,
        revoked_at: row.try_get("created_at").map_err(|e| unavailable(&e))?,
        clock_synced: row.try_get("clock_synced").map_err(|e| unavailable(&e))?,
    })
}

/// One-time identifiers shared by every replica and surviving restarts.
#[derive(Clone)]
pub struct PostgresReplayGuard {
    pool: PgPool,
}

impl PostgresReplayGuard {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Deletes identifiers that expired before `before`; returns how many.
    pub async fn purge_expired(&self, before: DateTime<Utc>) -> Result<u64, PortError> {
        sqlx::query("DELETE FROM replay_guard WHERE expires_at < $1")
            .bind(before)
            .execute(&self.pool)
            .await
            .map(|r| r.rows_affected())
            .map_err(|e| unavailable(&e))
    }
}

impl ReplayGuard for PostgresReplayGuard {
    async fn check_and_record(
        &self,
        tenant_id: &str,
        key: &str,
        now: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<(), PortError> {
        // Inserts, or takes over an expired entry; a live entry is a replay.
        let recorded = sqlx::query(
            "INSERT INTO replay_guard (tenant_id, key, expires_at) VALUES ($1, $2, $3) \
            ON CONFLICT (tenant_id, key) DO UPDATE SET expires_at = EXCLUDED.expires_at \
            WHERE replay_guard.expires_at <= $4",
        )
        .bind(tenant_id)
        .bind(key)
        .bind(expires_at)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| PortError::unavailable(format!("replay guard: {e}")))?;
        if recorded.rows_affected() == 1 {
            Ok(())
        } else {
            Err(PortError::rejected(format!("replayed identifier {key}")))
        }
    }
}

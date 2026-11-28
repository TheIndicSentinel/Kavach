//! PostgreSQL adapter for tenant-scoped encrypted D17 review snapshots.

use chrono::{DateTime, Utc};
use kavach_ports::{EncryptedReviewSnapshot, PortError, ReviewSnapshotStore};
use sqlx::{PgPool, Row};

#[derive(Clone)]
pub struct PostgresReviewSnapshotStore {
    pool: PgPool,
}

impl PostgresReviewSnapshotStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl ReviewSnapshotStore for PostgresReviewSnapshotStore {
    async fn insert(
        &self,
        snapshot: EncryptedReviewSnapshot,
        now: DateTime<Utc>,
    ) -> Result<(), PortError> {
        snapshot.validate(now)?;
        let result = sqlx::query(
            "INSERT INTO human_review_snapshots \
                (tenant_id, record_id, action_hash, key_id, version, nonce, ciphertext, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(snapshot.tenant_id)
        .bind(snapshot.record_id)
        .bind(snapshot.action_hash)
        .bind(snapshot.key_id)
        .bind(i16::from(snapshot.version))
        .bind(snapshot.nonce.to_vec())
        .bind(snapshot.ciphertext)
        .bind(snapshot.expires_at)
        .execute(&self.pool)
        .await;
        result.map(|_| ()).map_err(|error| {
            if error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .as_deref()
                == Some("23505")
            {
                PortError::rejected("review snapshot already exists")
            } else {
                PortError::unavailable("review snapshot storage is unavailable")
            }
        })
    }

    async fn get_live(
        &self,
        tenant_id: &str,
        record_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<EncryptedReviewSnapshot>, PortError> {
        let row = sqlx::query(
            "SELECT tenant_id, record_id, action_hash, key_id, version, nonce, ciphertext, expires_at \
             FROM human_review_snapshots \
             WHERE tenant_id = $1 AND record_id = $2 AND expires_at > $3",
        )
        .bind(tenant_id)
        .bind(record_id)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| PortError::unavailable("review snapshot storage is unavailable"))?;
        row.as_ref().map(read_snapshot).transpose()
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> Result<u64, PortError> {
        sqlx::query("DELETE FROM human_review_snapshots WHERE expires_at <= $1")
            .bind(now)
            .execute(&self.pool)
            .await
            .map(|result| result.rows_affected())
            .map_err(|_| PortError::unavailable("review snapshot storage is unavailable"))
    }
}

fn read_snapshot(row: &sqlx::postgres::PgRow) -> Result<EncryptedReviewSnapshot, PortError> {
    let version: i16 = row
        .try_get("version")
        .map_err(|_| PortError::unavailable("stored review snapshot is malformed"))?;
    let nonce: Vec<u8> = row
        .try_get("nonce")
        .map_err(|_| PortError::unavailable("stored review snapshot is malformed"))?;
    let nonce: [u8; 12] = nonce
        .try_into()
        .map_err(|_| PortError::unavailable("stored review snapshot is malformed"))?;
    let snapshot = EncryptedReviewSnapshot {
        tenant_id: row
            .try_get("tenant_id")
            .map_err(|_| PortError::unavailable("stored review snapshot is malformed"))?,
        record_id: row
            .try_get("record_id")
            .map_err(|_| PortError::unavailable("stored review snapshot is malformed"))?,
        action_hash: row
            .try_get("action_hash")
            .map_err(|_| PortError::unavailable("stored review snapshot is malformed"))?,
        key_id: row
            .try_get("key_id")
            .map_err(|_| PortError::unavailable("stored review snapshot is malformed"))?,
        version: u8::try_from(version)
            .map_err(|_| PortError::unavailable("stored review snapshot is malformed"))?,
        nonce,
        ciphertext: row
            .try_get("ciphertext")
            .map_err(|_| PortError::unavailable("stored review snapshot is malformed"))?,
        expires_at: row
            .try_get("expires_at")
            .map_err(|_| PortError::unavailable("stored review snapshot is malformed"))?,
    };
    snapshot
        .validate(snapshot.expires_at - chrono::Duration::microseconds(1))
        .map_err(|_| PortError::unavailable("stored review snapshot is malformed"))?;
    Ok(snapshot)
}

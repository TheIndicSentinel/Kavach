use chrono::{DateTime, Duration, Utc};
use sqlx::PgPool;

/// Database-issued lease epoch and expiry returned to the active process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveApiLease {
    pub epoch: i64,
    pub lease_expires_at: DateTime<Utc>,
}

/// Postgres lease operations. The caller supplies only the SHA-256 token hash;
/// raw process tokens must remain in process memory.
#[derive(Clone)]
pub struct PostgresActiveLeaseStore {
    pool: PgPool,
}

impl PostgresActiveLeaseStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Claims an absent or expired tenant lease. `None` means another holder
    /// still owns an unexpired lease.
    pub async fn claim(
        &self,
        tenant_id: &str,
        holder_id: &str,
        token_hash: &[u8; 32],
        ttl: Duration,
    ) -> Result<Option<ActiveApiLease>, sqlx::Error> {
        sqlx::query_as::<_, ActiveApiLeaseRow>(
            "SELECT epoch, lease_expires_at FROM kavach_claim_active_lease($1, $2, $3, $4)",
        )
        .bind(tenant_id)
        .bind(holder_id)
        .bind(token_hash.as_slice())
        .bind(ttl)
        .fetch_optional(&self.pool)
        .await
        .map(|row| row.map(Into::into))
    }

    /// Renews only the same live holder, epoch, and token hash.
    pub async fn renew(
        &self,
        tenant_id: &str,
        holder_id: &str,
        epoch: i64,
        token_hash: &[u8; 32],
        ttl: Duration,
    ) -> Result<bool, sqlx::Error> {
        sqlx::query_scalar("SELECT kavach_renew_active_lease($1, $2, $3, $4, $5)")
            .bind(tenant_id)
            .bind(holder_id)
            .bind(epoch)
            .bind(token_hash.as_slice())
            .bind(ttl)
            .fetch_one(&self.pool)
            .await
    }
}

#[derive(sqlx::FromRow)]
struct ActiveApiLeaseRow {
    epoch: i64,
    lease_expires_at: DateTime<Utc>,
}

impl From<ActiveApiLeaseRow> for ActiveApiLease {
    fn from(row: ActiveApiLeaseRow) -> Self {
        Self {
            epoch: row.epoch,
            lease_expires_at: row.lease_expires_at,
        }
    }
}

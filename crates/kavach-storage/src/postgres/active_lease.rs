use chrono::{DateTime, Duration, Utc};
use sqlx::{PgConnection, PgPool};
use std::sync::Arc;
use tokio::sync::RwLock;

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
    write_context: LeaseConnectionContext,
}

#[derive(Clone, Default)]
pub(super) struct LeaseConnectionContext(Arc<RwLock<LeaseConnectionState>>);

#[derive(Clone, Default)]
enum LeaseConnectionState {
    #[default]
    Unconfigured,
    Fenced,
    Active(LeaseWriteIdentity),
}

#[derive(Clone)]
struct LeaseWriteIdentity {
    tenant_id: String,
    holder_id: String,
    epoch: i64,
    token_hash: [u8; 32],
}

impl LeaseConnectionContext {
    pub(super) async fn enable(&self) {
        *self.0.write().await = LeaseConnectionState::Fenced;
    }

    async fn install(&self, identity: LeaseWriteIdentity) {
        *self.0.write().await = LeaseConnectionState::Active(identity);
    }

    async fn clear(&self) {
        *self.0.write().await = LeaseConnectionState::Fenced;
    }

    pub(super) async fn bind(&self, connection: &mut PgConnection) -> Result<(), sqlx::Error> {
        let (enabled, tenant, holder, epoch, token_hash) = match self.0.read().await.clone() {
            LeaseConnectionState::Unconfigured => return Ok(()),
            LeaseConnectionState::Active(identity) => (
                "on",
                identity.tenant_id,
                identity.holder_id,
                identity.epoch.to_string(),
                hex::encode(identity.token_hash),
            ),
            // HA stays enabled while standby/fenced; an empty identity makes
            // the future trigger reject writes. A never-configured context
            // leaves the custom setting untouched for single-instance mode.
            LeaseConnectionState::Fenced => (
                "on",
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            ),
        };
        sqlx::query(
            "SELECT set_config('kavach.fencing_enabled', $1, false), \
                    set_config('kavach.tenant_id', $2, false), \
                    set_config('kavach.holder_id', $3, false), \
                    set_config('kavach.lease_epoch', $4, false), \
                    set_config('kavach.token_hash', $5, false)",
        )
        .bind(enabled)
        .bind(tenant)
        .bind(holder)
        .bind(epoch)
        .bind(token_hash)
        .execute(&mut *connection)
        .await?;
        Ok(())
    }
}

impl PostgresActiveLeaseStore {
    pub(super) fn new(pool: PgPool, write_context: LeaseConnectionContext) -> Self {
        Self {
            pool,
            write_context,
        }
    }

    /// Enables connection tagging before the process starts claiming a lease.
    pub async fn enable_write_fencing(&self) {
        self.write_context.enable().await;
    }

    /// Installs the exact lease identity to be applied on each API pool
    /// checkout. The raw process token is never passed to this method.
    pub async fn bind_write_identity(
        &self,
        tenant_id: &str,
        holder_id: &str,
        epoch: i64,
        token_hash: &[u8; 32],
    ) {
        self.write_context
            .install(LeaseWriteIdentity {
                tenant_id: tenant_id.to_owned(),
                holder_id: holder_id.to_owned(),
                epoch,
                token_hash: *token_hash,
            })
            .await;
    }

    /// Clears identity on subsequent pool checkouts after self-fencing.
    pub async fn clear_write_identity(&self) {
        self.write_context.clear().await;
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

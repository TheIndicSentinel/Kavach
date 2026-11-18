//! Transactional signed preference updates. Consent writes and withdrawal
//! revocation follow in a separate slice.

use kavach_domain::authority::AuthorityChange;
use kavach_domain::mandate::{ConsentRecord, ContactPreferenceRecord, ContactPreferenceStatus};
use kavach_mandate::VerifiedAuthorityUpdate;
use kavach_ports::PortError;
use sqlx::{PgPool, Postgres, Row, Transaction};

fn unavailable() -> PortError {
    PortError::unavailable("authority update store is unavailable")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppliedPreferenceUpdate {
    pub replayed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppliedConsentGrant {
    pub replayed: bool,
}

#[derive(Clone)]
pub struct PostgresAuthorityUpdateStore {
    pool: PgPool,
}

impl PostgresAuthorityUpdateStore {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Stores a signed grant. A withdrawal is refused until mandate
    /// revocation can share this transaction.
    pub async fn apply_consent_grant(
        &self,
        verified: &VerifiedAuthorityUpdate,
    ) -> Result<AppliedConsentGrant, PortError> {
        let event = verified.event();
        let AuthorityChange::Consent(record) = &event.change else {
            return Err(PortError::invalid(
                "authority update is not a consent change",
            ));
        };
        if !record.active {
            return Err(PortError::rejected(
                "consent withdrawal requires atomic mandate revocation",
            ));
        }
        let mut tx = self.pool.begin().await.map_err(|_| unavailable())?;
        Self::lock_tenant(&mut tx, &event.tenant_id).await?;
        if Self::is_replay(&mut tx, verified).await? {
            return Ok(AppliedConsentGrant { replayed: true });
        }
        let version = Self::consent_version(&mut tx, verified, record).await?;
        let next_version = version.checked_add(1).ok_or_else(unavailable)?;
        Self::write_consent(&mut tx, verified, record, version, next_version).await?;
        tx.commit().await.map_err(|_| unavailable())?;
        Ok(AppliedConsentGrant { replayed: false })
    }

    async fn consent_version(
        tx: &mut Transaction<'_, Postgres>,
        verified: &VerifiedAuthorityUpdate,
        record: &ConsentRecord,
    ) -> Result<i64, PortError> {
        let event = verified.event();
        let current = sqlx::query(
            "SELECT c.version, c.source_system, c.record AS current_record, \
                    u.record AS history_record, u.kind AS source_kind, \
                    u.occurred_at AS source_time \
             FROM consent_current c JOIN authority_updates u \
               ON u.tenant_id = c.tenant_id AND u.source_system = c.source_system \
               AND u.update_id = c.update_id \
             WHERE c.tenant_id = $1 AND c.consent_id = $2 FOR UPDATE OF c",
        )
        .bind(&event.tenant_id)
        .bind(&record.consent_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| unavailable())?;
        let Some(row) = current else { return Ok(0) };
        let version: i64 = row.try_get("version").map_err(|_| unavailable())?;
        let source_system: String = row.try_get("source_system").map_err(|_| unavailable())?;
        let current_record: serde_json::Value =
            row.try_get("current_record").map_err(|_| unavailable())?;
        let history_record: serde_json::Value =
            row.try_get("history_record").map_err(|_| unavailable())?;
        let source_kind: String = row.try_get("source_kind").map_err(|_| unavailable())?;
        let source_time: chrono::DateTime<chrono::Utc> =
            row.try_get("source_time").map_err(|_| unavailable())?;
        let previous: ConsentRecord =
            serde_json::from_value(current_record.clone()).map_err(|_| unavailable())?;
        if current_record != history_record
            || source_kind != "consent"
            || previous.tenant_id != event.tenant_id
            || previous.consent_id != record.consent_id
            || previous.validate().is_err()
        {
            return Err(unavailable());
        }
        if source_system != event.system {
            return Err(PortError::rejected("consent source system changed"));
        }
        if !previous.active || event.occurred_at <= source_time {
            return Err(PortError::rejected("consent grant is not a new authority"));
        }
        Ok(version)
    }

    async fn write_consent(
        tx: &mut Transaction<'_, Postgres>,
        verified: &VerifiedAuthorityUpdate,
        record: &ConsentRecord,
        previous_version: i64,
        next_version: i64,
    ) -> Result<(), PortError> {
        let event = verified.event();
        let json = serde_json::to_value(record).map_err(|_| unavailable())?;
        sqlx::query(
            "INSERT INTO authority_updates \
             (tenant_id, source_system, update_id, kind, consent_id, payload_sha256, record, occurred_at) \
             VALUES ($1, $2, $3, 'consent', $4, $5, $6, $7)",
        )
        .bind(&event.tenant_id)
        .bind(&event.system)
        .bind(&event.update_id)
        .bind(&record.consent_id)
        .bind(verified.payload_sha256())
        .bind(&json)
        .bind(event.occurred_at)
        .execute(&mut **tx)
        .await
        .map_err(|_| unavailable())?;
        if previous_version == 0 {
            sqlx::query(
                "INSERT INTO consent_current \
                 (tenant_id, consent_id, record, source_system, update_id, version) \
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(&event.tenant_id)
            .bind(&record.consent_id)
            .bind(&json)
            .bind(&event.system)
            .bind(&event.update_id)
            .bind(next_version)
            .execute(&mut **tx)
            .await
            .map_err(|_| unavailable())?;
        } else {
            let updated = sqlx::query(
                "UPDATE consent_current SET record = $3, source_system = $4, \
                    update_id = $5, version = $6, updated_at = NOW() \
                 WHERE tenant_id = $1 AND consent_id = $2 AND version = $7",
            )
            .bind(&event.tenant_id)
            .bind(&record.consent_id)
            .bind(&json)
            .bind(&event.system)
            .bind(&event.update_id)
            .bind(next_version)
            .bind(previous_version)
            .execute(&mut **tx)
            .await
            .map_err(|_| unavailable())?;
            if updated.rows_affected() != 1 {
                return Err(unavailable());
            }
        }
        Ok(())
    }

    /// Persists only a previously verified preference event. Its history and
    /// current projection commit together. A stop may arrive late; an allow
    /// cannot reopen an opt-out in this slice.
    pub async fn apply_preference(
        &self,
        verified: &VerifiedAuthorityUpdate,
    ) -> Result<AppliedPreferenceUpdate, PortError> {
        let event = verified.event();
        let AuthorityChange::ContactPreference(record) = &event.change else {
            return Err(PortError::invalid(
                "authority update is not a preference change",
            ));
        };
        let mut tx = self.pool.begin().await.map_err(|_| unavailable())?;
        Self::lock_tenant(&mut tx, &event.tenant_id).await?;
        if Self::is_replay(&mut tx, verified).await? {
            return Ok(AppliedPreferenceUpdate { replayed: true });
        }
        let previous_version = Self::current_version(&mut tx, verified, record).await?;
        let next_version = previous_version.checked_add(1).ok_or_else(unavailable)?;
        Self::write_change(&mut tx, verified, record, previous_version, next_version).await?;
        tx.commit().await.map_err(|_| unavailable())?;
        Ok(AppliedPreferenceUpdate { replayed: false })
    }

    async fn is_replay(
        tx: &mut Transaction<'_, Postgres>,
        verified: &VerifiedAuthorityUpdate,
    ) -> Result<bool, PortError> {
        let event = verified.event();
        let old_digest: Option<String> = sqlx::query_scalar(
            "SELECT payload_sha256 FROM authority_updates \
             WHERE tenant_id = $1 AND source_system = $2 AND update_id = $3",
        )
        .bind(&event.tenant_id)
        .bind(&event.system)
        .bind(&event.update_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| unavailable())?;
        match old_digest {
            Some(digest) if digest == verified.payload_sha256() => Ok(true),
            Some(_) => Err(PortError::rejected(
                "update id reused with different content",
            )),
            None => Ok(false),
        }
    }

    async fn current_version(
        tx: &mut Transaction<'_, Postgres>,
        verified: &VerifiedAuthorityUpdate,
        record: &ContactPreferenceRecord,
    ) -> Result<i64, PortError> {
        let event = verified.event();
        let current = sqlx::query(
            "SELECT c.version, c.source_system, c.record AS current_record, \
                    u.record AS history_record, u.kind AS source_kind, \
                    u.occurred_at AS source_time \
             FROM contact_preference_current c \
             JOIN authority_updates u ON u.tenant_id = c.tenant_id \
               AND u.source_system = c.source_system AND u.update_id = c.update_id \
             WHERE c.tenant_id = $1 AND c.subject_ref = $2 AND c.channel = $3 \
             FOR UPDATE OF c",
        )
        .bind(&event.tenant_id)
        .bind(&record.subject_ref)
        .bind(&record.channel)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| unavailable())?;
        let Some(row) = current else { return Ok(0) };
        let version: i64 = row.try_get("version").map_err(|_| unavailable())?;
        let source_system: String = row.try_get("source_system").map_err(|_| unavailable())?;
        let current_record: serde_json::Value =
            row.try_get("current_record").map_err(|_| unavailable())?;
        let history_record: serde_json::Value =
            row.try_get("history_record").map_err(|_| unavailable())?;
        let source_kind: String = row.try_get("source_kind").map_err(|_| unavailable())?;
        let source_time: chrono::DateTime<chrono::Utc> =
            row.try_get("source_time").map_err(|_| unavailable())?;
        let previous: ContactPreferenceRecord =
            serde_json::from_value(current_record.clone()).map_err(|_| unavailable())?;
        if current_record != history_record
            || source_kind != "contact_preference"
            || previous.tenant_id != event.tenant_id
            || previous.subject_ref != record.subject_ref
            || previous.channel != record.channel
            || previous.validate().is_err()
        {
            return Err(unavailable());
        }
        if source_system != event.system {
            return Err(PortError::rejected("preference source system changed"));
        }
        if record.status == ContactPreferenceStatus::Allowed
            && (previous.status == ContactPreferenceStatus::OptedOut
                || event.occurred_at <= source_time)
        {
            return Err(PortError::rejected(
                "preference allow is not a new authority",
            ));
        }
        Ok(version)
    }

    async fn write_change(
        tx: &mut Transaction<'_, Postgres>,
        verified: &VerifiedAuthorityUpdate,
        record: &ContactPreferenceRecord,
        previous_version: i64,
        next_version: i64,
    ) -> Result<(), PortError> {
        let event = verified.event();
        let json = serde_json::to_value(record).map_err(|_| unavailable())?;
        sqlx::query(
            "INSERT INTO authority_updates \
             (tenant_id, source_system, update_id, kind, subject_ref, channel, \
              payload_sha256, record, occurred_at) \
             VALUES ($1, $2, $3, 'contact_preference', $4, $5, $6, $7, $8)",
        )
        .bind(&event.tenant_id)
        .bind(&event.system)
        .bind(&event.update_id)
        .bind(&record.subject_ref)
        .bind(&record.channel)
        .bind(verified.payload_sha256())
        .bind(&json)
        .bind(event.occurred_at)
        .execute(&mut **tx)
        .await
        .map_err(|_| unavailable())?;
        if previous_version == 0 {
            sqlx::query(
                "INSERT INTO contact_preference_current \
                 (tenant_id, subject_ref, channel, record, source_system, update_id, version) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
            )
            .bind(&event.tenant_id)
            .bind(&record.subject_ref)
            .bind(&record.channel)
            .bind(&json)
            .bind(&event.system)
            .bind(&event.update_id)
            .bind(next_version)
            .execute(&mut **tx)
            .await
            .map_err(|_| unavailable())?;
        } else {
            let updated = sqlx::query(
                "UPDATE contact_preference_current \
                 SET record = $4, source_system = $5, update_id = $6, \
                     version = $7, updated_at = NOW() \
                 WHERE tenant_id = $1 AND subject_ref = $2 AND channel = $3 AND version = $8",
            )
            .bind(&event.tenant_id)
            .bind(&record.subject_ref)
            .bind(&record.channel)
            .bind(&json)
            .bind(&event.system)
            .bind(&event.update_id)
            .bind(next_version)
            .bind(previous_version)
            .execute(&mut **tx)
            .await
            .map_err(|_| unavailable())?;
            if updated.rows_affected() != 1 {
                return Err(unavailable());
            }
        }
        Ok(())
    }

    async fn lock_tenant(
        tx: &mut Transaction<'_, Postgres>,
        tenant_id: &str,
    ) -> Result<(), PortError> {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('kavach-authority:' || $1, 0))")
            .bind(tenant_id)
            .execute(&mut **tx)
            .await
            .map_err(|_| unavailable())?;
        Ok(())
    }
}

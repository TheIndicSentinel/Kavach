//! Read-only pilot projections for consent and contact preferences.
//!
//! Writes are reserved for the signed system-of-record update slice. Reads
//! compare each projection with its immutable source row and refuse corrupt
//! records without disclosing their contents.

use kavach_domain::mandate::{ConsentRecord, ContactPreferenceRecord};
use kavach_ports::{ConsentSource, ContactPreferenceSource, PortError};
use sqlx::{PgPool, Row};

fn unreadable() -> PortError {
    PortError::unavailable("authority projection is unreadable")
}

#[derive(Clone)]
pub struct PostgresConsentSource {
    pool: PgPool,
}

impl PostgresConsentSource {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl ConsentSource for PostgresConsentSource {
    async fn get(
        &self,
        tenant_id: &str,
        consent_id: &str,
    ) -> Result<Option<ConsentRecord>, PortError> {
        let row = sqlx::query(
            "SELECT c.record AS current_record, u.record AS history_record, \
                    u.kind AS source_kind, u.consent_id AS source_consent_id \
                 FROM consent_current c JOIN authority_updates u \
                   ON u.tenant_id = c.tenant_id AND u.source_system = c.source_system \
                   AND u.update_id = c.update_id \
                 WHERE c.tenant_id = $1 AND c.consent_id = $2",
        )
        .bind(tenant_id)
        .bind(consent_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| unreadable())?;
        let Some(row) = row else { return Ok(None) };
        let current: serde_json::Value = row.try_get("current_record").map_err(|_| unreadable())?;
        let history: serde_json::Value = row.try_get("history_record").map_err(|_| unreadable())?;
        let kind: String = row.try_get("source_kind").map_err(|_| unreadable())?;
        let source_id: Option<String> =
            row.try_get("source_consent_id").map_err(|_| unreadable())?;
        if kind != "consent" || source_id.as_deref() != Some(consent_id) || current != history {
            return Err(unreadable());
        }
        let record: ConsentRecord = serde_json::from_value(current).map_err(|_| unreadable())?;
        if record.tenant_id != tenant_id
            || record.consent_id != consent_id
            || record.validate().is_err()
        {
            return Err(unreadable());
        }
        Ok(Some(record))
    }
}

#[derive(Clone)]
pub struct PostgresContactPreferenceSource {
    pool: PgPool,
}

impl PostgresContactPreferenceSource {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl ContactPreferenceSource for PostgresContactPreferenceSource {
    async fn get(
        &self,
        tenant_id: &str,
        subject_ref: &str,
        channel: &str,
    ) -> Result<Option<ContactPreferenceRecord>, PortError> {
        let row = sqlx::query(
            "SELECT c.record AS current_record, u.record AS history_record, \
                    u.kind AS source_kind, u.subject_ref AS source_subject_ref, \
                    u.channel AS source_channel \
                 FROM contact_preference_current c JOIN authority_updates u \
                   ON u.tenant_id = c.tenant_id AND u.source_system = c.source_system \
                   AND u.update_id = c.update_id \
                 WHERE c.tenant_id = $1 AND c.subject_ref = $2 AND c.channel = $3",
        )
        .bind(tenant_id)
        .bind(subject_ref)
        .bind(channel)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| unreadable())?;
        let Some(row) = row else { return Ok(None) };
        let current: serde_json::Value = row.try_get("current_record").map_err(|_| unreadable())?;
        let history: serde_json::Value = row.try_get("history_record").map_err(|_| unreadable())?;
        let kind: String = row.try_get("source_kind").map_err(|_| unreadable())?;
        let source_ref: Option<String> = row
            .try_get("source_subject_ref")
            .map_err(|_| unreadable())?;
        let source_channel: Option<String> =
            row.try_get("source_channel").map_err(|_| unreadable())?;
        if kind != "contact_preference"
            || source_ref.as_deref() != Some(subject_ref)
            || source_channel.as_deref() != Some(channel)
            || current != history
        {
            return Err(unreadable());
        }
        let record: ContactPreferenceRecord =
            serde_json::from_value(current).map_err(|_| unreadable())?;
        if record.tenant_id != tenant_id
            || record.subject_ref != subject_ref
            || record.channel != channel
            || record.validate().is_err()
        {
            return Err(unreadable());
        }
        Ok(Some(record))
    }
}

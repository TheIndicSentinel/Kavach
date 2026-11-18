//! Signed system-of-record change payloads for pilot consent and preferences.
//! No destination or raw customer value belongs in this contract.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::mandate::{
    is_capability_ref, ConsentRecord, ConsentStatus, ContactPreferenceRecord,
    ContactPreferenceStatus,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityUpdateEvent {
    pub update_id: String,
    pub tenant_id: String,
    pub system: String,
    pub occurred_at: DateTime<Utc>,
    pub nonce: String,
    pub change: AuthorityChange,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "record", rename_all = "snake_case")]
pub enum AuthorityChange {
    Consent(ConsentRecord),
    ContactPreference(ContactPreferenceRecord),
}

impl AuthorityUpdateEvent {
    pub fn validate(&self) -> Result<(), &'static str> {
        let opaque_id = |value: &str| {
            !value.is_empty()
                && value.len() <= 128
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        };
        if !opaque_id(&self.update_id)
            || self.tenant_id.trim().is_empty()
            || self.system.trim().is_empty()
            || !opaque_id(&self.nonce)
        {
            return Err("authority update envelope is invalid");
        }
        match &self.change {
            AuthorityChange::Consent(record) => {
                record.validate()?;
                let artefact = record
                    .artefact
                    .as_ref()
                    .ok_or("signed consent update requires an explicit artefact")?;
                if record.tenant_id != self.tenant_id
                    || !is_capability_ref(&record.subject_ref)
                    || record.consent_id.is_empty()
                    || record.purposes.is_empty()
                    || record
                        .purposes
                        .iter()
                        .any(|purpose| purpose.trim().is_empty())
                    || artefact.status == ConsentStatus::Expired
                {
                    return Err("authority consent record is invalid");
                }
            }
            AuthorityChange::ContactPreference(record) => {
                record.validate()?;
                if record.tenant_id != self.tenant_id {
                    return Err("authority preference tenant disagrees with envelope");
                }
            }
        }
        Ok(())
    }

    /// Restrictive updates stop authority or contact. They remain admissible
    /// when their source clock is stale or Kavach's clock is unsynchronised.
    pub fn is_restrictive(&self) -> bool {
        match &self.change {
            AuthorityChange::Consent(record) => !record.active,
            AuthorityChange::ContactPreference(record) => {
                record.status == ContactPreferenceStatus::OptedOut
            }
        }
    }
}

//! Signed system-of-record change payloads for pilot consent, preferences,
//! and reference destinations. Destination values are transient signed input:
//! they must be encrypted before persistence and never logged or returned.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroize;

use crate::mandate::{
    is_capability_ref, ConsentRecord, ConsentStatus, ContactPreferenceRecord,
    ContactPreferenceStatus, ALLOWED_CHANNELS,
};

/// A transient destination carried by a signed system-of-record update.
/// Serialization is required for JWS verification; debug output is redacted
/// and the in-memory string is zeroized on drop.
#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SensitiveDestination(String);

impl SensitiveDestination {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SensitiveDestination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SensitiveDestination(<redacted>)")
    }
}

impl Drop for SensitiveDestination {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceDestinationRecord {
    pub tenant_id: String,
    pub subject_ref: String,
    pub channel: String,
    pub destination: SensitiveDestination,
}

impl ReferenceDestinationRecord {
    pub fn validate(&self) -> Result<(), &'static str> {
        let value = self.destination.expose();
        if self.tenant_id.trim().is_empty()
            || !is_capability_ref(&self.subject_ref)
            || !ALLOWED_CHANNELS.contains(&self.channel.as_str())
            || value.is_empty()
            || value.len() > 4096
            || value.chars().any(char::is_control)
        {
            return Err("authority reference destination record is invalid");
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityUpdateEvent {
    pub update_id: String,
    pub tenant_id: String,
    pub system: String,
    pub occurred_at: DateTime<Utc>,
    pub nonce: String,
    pub change: AuthorityChange,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "record", rename_all = "snake_case")]
pub enum AuthorityChange {
    Consent(ConsentRecord),
    ContactPreference(ContactPreferenceRecord),
    ReferenceDestination(ReferenceDestinationRecord),
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
            AuthorityChange::ReferenceDestination(record) => {
                record.validate()?;
                if record.tenant_id != self.tenant_id {
                    return Err("authority destination tenant disagrees with envelope");
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
            AuthorityChange::ReferenceDestination(_) => false,
        }
    }
}

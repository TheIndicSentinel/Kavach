//! Tenant and channel scoped contact preference lookup.

use std::future::Future;

use chrono::{DateTime, Utc};
use kavach_domain::mandate::ContactPreferenceRecord;

use crate::PortError;

/// Returns the current authoritative record. Callers must deny outbound
/// contact on `None`, an expired or opted-out record, or any lookup error.
pub trait ContactPreferenceSource: Send + Sync {
    fn get(
        &self,
        tenant_id: &str,
        subject_ref: &str,
        channel: &str,
    ) -> impl Future<Output = Result<Option<ContactPreferenceRecord>, PortError>> + Send;
}

/// Fails closed for a missing, malformed, expired, opted-out, or mismatched
/// record. A source failure remains unavailable to the caller.
pub async fn require_contact_permission<S: ContactPreferenceSource>(
    source: &S,
    tenant_id: &str,
    subject_ref: &str,
    channel: &str,
    now: DateTime<Utc>,
) -> Result<(), PortError> {
    let record = source
        .get(tenant_id, subject_ref, channel)
        .await?
        .ok_or_else(|| PortError::rejected("contact preference unavailable"))?;
    if record.validate().is_err()
        || record.tenant_id != tenant_id
        || record.subject_ref != subject_ref
        || record.channel != channel
        || !record.allows_contact_at(now)
    {
        return Err(PortError::rejected(
            "contact preference does not permit contact",
        ));
    }
    Ok(())
}

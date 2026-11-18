//! Verification boundary for signed consent and preference updates.
//! Persistence and live selection follow in later pilot slices.

use chrono::Duration;
use kavach_domain::authority::AuthorityUpdateEvent;
use kavach_ports::{ErrorClass, PortError, TrustedNow};
use sha2::{Digest, Sha256};

use crate::config::MandateConfig;
use crate::jws::{self, TYP_AUTHORITY_UPDATE};
use crate::UNTRUSTED_ISSUER;

#[derive(Debug)]
pub struct VerifiedAuthorityUpdate {
    event: AuthorityUpdateEvent,
    payload_sha256: String,
    clock_synced: bool,
}

impl VerifiedAuthorityUpdate {
    pub fn event(&self) -> &AuthorityUpdateEvent {
        &self.event
    }

    /// Hex SHA-256 of the canonical signed payload; the persistent update id
    /// will be idempotent only for this same digest.
    pub fn payload_sha256(&self) -> &str {
        &self.payload_sha256
    }

    /// Whether Kavach's clock met the configured bound when this update was
    /// verified. Restrictive updates are still accepted when this is false.
    pub fn clock_synced(&self) -> bool {
        self.clock_synced
    }
}

pub struct AuthorityVerifier {
    tenant_id: String,
    config: MandateConfig,
}

impl AuthorityVerifier {
    pub fn new(tenant_id: impl Into<String>, config: MandateConfig) -> Result<Self, PortError> {
        let tenant_id = tenant_id.into();
        if tenant_id.is_empty() {
            return Err(PortError::invalid("authority verifier tenant is required"));
        }
        config.validate()?;
        Ok(Self { tenant_id, config })
    }

    pub fn verify(
        &self,
        token: &str,
        now: TrustedNow,
    ) -> Result<VerifiedAuthorityUpdate, PortError> {
        let (kid, event): (String, AuthorityUpdateEvent) =
            match jws::verify(token, TYP_AUTHORITY_UPDATE, &self.config.sor_keys()) {
                Ok(verified) => verified,
                Err(err) if err.class == ErrorClass::Rejected => {
                    return Err(PortError::rejected(UNTRUSTED_ISSUER));
                }
                Err(err) => return Err(err),
            };
        if event.tenant_id != self.tenant_id
            || self
                .config
                .sor_issuer(&event.tenant_id, &event.system, &kid)
                .is_none()
        {
            return Err(PortError::rejected(UNTRUSTED_ISSUER));
        }
        event.validate().map_err(PortError::invalid)?;
        if !event.is_restrictive() {
            now.require_synced(self.config.max_clock_error_ms)?;
            let age = now.utc - event.occurred_at;
            let future_bound = self.config.event_freshness_seconds.min(60);
            if age > Duration::seconds(self.config.event_freshness_seconds)
                || age < -Duration::seconds(future_bound)
            {
                return Err(PortError::rejected(
                    "authority update is stale or from the future",
                ));
            }
        }
        let bytes = kavach_ports::jcs::to_vec(&event)?;
        let clock_synced = now.require_synced(self.config.max_clock_error_ms).is_ok();
        Ok(VerifiedAuthorityUpdate {
            event,
            payload_sha256: hex::encode(Sha256::digest(bytes)),
            clock_synced,
        })
    }
}

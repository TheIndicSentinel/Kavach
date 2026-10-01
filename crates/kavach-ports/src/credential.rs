//! Credential broker port (H5b, FR-4, ADR-006).
//!
//! After a committed allow, the gateway asks the broker for a short-lived
//! credential that lets exactly one forwarded request through to a resource
//! provider. The agent never sees it. The credential is bound to the
//! decision (tenant, agent, mandate, evidence record, `jti` = the record's
//! `credential_id`), to its audience and to the whole request (destination,
//! channel, template), and it expires within [`MAX_CREDENTIAL_TTL_SECONDS`]
//! and never after `send_by`.
//!
//! The request, destination included, must be readable only by the
//! audience (the JOSE adapter encrypts the signed credential to the
//! provider's key). A credential is still a bearer secret until it expires:
//! it is never logged, displayed or returned to the agent ([`TokenSecret`]).

use std::fmt;
use std::future::Future;

use chrono::{DateTime, Utc};
use zeroize::Zeroize;

use crate::PortError;

/// Longest credential lifetime: the gateway forwards at once.
pub const MAX_CREDENTIAL_TTL_SECONDS: i64 = 15;

/// A resolved destination (phone number, channel address). Personal data:
/// no `Display`, `Serialize` or revealing `Debug`; zeroised on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct Destination(String);

impl Destination {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The value itself, for the forwarded request and the binding digest
    /// only. Never log, record or return it.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Destination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Destination(<redacted>)")
    }
}

impl Drop for Destination {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A credential token: a bearer secret that may reveal personal data.
#[derive(Clone, PartialEq, Eq)]
pub struct TokenSecret(String);

impl TokenSecret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The token, for the forwarded request's header only.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for TokenSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TokenSecret(<redacted>)")
    }
}

impl Drop for TokenSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// What the credential is for. Built by the gateway from a committed allow.
#[derive(Debug, Clone)]
pub struct CredentialRequest<'a> {
    pub tenant_id: &'a str,
    pub agent_id: &'a str,
    pub mandate_id: &'a str,
    /// The evidence record that allowed the call.
    pub record_id: &'a str,
    /// The record's `credential_id`; becomes the `jti`.
    pub credential_id: &'a str,
    /// The resource provider (`aud`).
    pub audience: &'a str,
    pub action: &'a str,
    pub destination: &'a Destination,
    pub channel: &'a str,
    pub template_id: &'a str,
    /// The grant's expiry (from the authorization core).
    pub expires_at: DateTime<Utc>,
    /// No credential is valid at or after this instant.
    pub send_by: Option<DateTime<Utc>>,
    /// Trusted time of issuance.
    pub now: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct IssuedCredential {
    pub credential_id: String,
    pub token: TokenSecret,
    /// `min(expires_at, send_by, now + MAX_CREDENTIAL_TTL_SECONDS)`.
    pub expires_at: DateTime<Utc>,
}

/// Issues request-bound credentials (ADR-006: security-critical; every
/// adapter must pass `kavach_ports_testkit::credential_broker::conformance`).
///
/// Errors: `Rejected` when no credential may be issued (at or after
/// `send_by`, already expired, a `credential_id` issued before, a revoked
/// mandate); `Invalid` for a malformed request; `Unavailable` when a
/// dependency (key store, vault) fails. No error ever carries the
/// destination.
pub trait CredentialBroker: Send + Sync {
    fn issue(
        &self,
        request: &CredentialRequest<'_>,
    ) -> impl Future<Output = Result<IssuedCredential, PortError>> + Send;

    /// Stops issuing for a mandate (and revokes what a vault-backed adapter
    /// can revoke). Returns how many live credentials were revoked; a
    /// signed-token adapter has none to revoke and returns 0, but refuses
    /// further issuance for that mandate.
    fn revoke_by_mandate(
        &self,
        tenant_id: &str,
        mandate_id: &str,
    ) -> impl Future<Output = Result<u64, PortError>> + Send;

    /// True for test doubles; production startup refuses them.
    fn is_test_double(&self) -> bool {
        false
    }
}

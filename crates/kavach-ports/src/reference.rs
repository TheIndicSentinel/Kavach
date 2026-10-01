//! Reference resolver port (H5b, ADR-004 §7, D11).
//!
//! Agents only ever hold capability references (`ref:borrower:B-9382`).
//! After a committed allow, the gateway resolves the reference to a
//! destination for the channel, inside the gateway, and puts it only into
//! the credential encrypted to the provider. The resolved value never
//! reaches evidence, logs, error messages or the agent.

use std::future::Future;

use crate::{Destination, PortError};

/// Resolves capability references to destinations (every adapter must pass
/// `kavach_ports_testkit::reference_resolver::conformance`).
///
/// Errors: `Invalid` for a malformed reference or channel; `Rejected` when
/// there is no destination (unknown reference, another tenant's reference,
/// no address for the channel); `Unavailable` when the vault is down. No
/// error carries a destination.
pub trait ReferenceResolver: Send + Sync {
    fn resolve(
        &self,
        tenant_id: &str,
        subject_ref: &str,
        channel: &str,
    ) -> impl Future<Output = Result<Destination, PortError>> + Send;

    /// What backs this resolver, for the startup banner (never a value).
    fn describe(&self) -> String;
}

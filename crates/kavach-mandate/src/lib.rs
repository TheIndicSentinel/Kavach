//! Task Mandates (ADR-004): the root of an agent's authority.
//!
//! - [`jws`]: strict compact JWS (EdDSA, JCS-canonical) for mandates and
//!   system-of-record events.
//! - [`MandateService`]: issuance from signed SoR events, verification
//!   (signature + stored status + trusted time), delegation, revocation.
//! - [`delegation`]: pure narrowing rules (child ⊆ parent ∩ passport).
//! - [`memory`]: in-memory adapters (M1); Postgres adapters arrive in M2.

mod config;
pub mod delegation;
pub mod jws;
pub mod memory;
mod service;

pub use config::{MandateConfig, SorIssuer};
pub use service::{
    is_revoking_event, IssuedMandate, MandateDeps, MandateService, RevokedByEvent, REVOKING_EVENTS,
};

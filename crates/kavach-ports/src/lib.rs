//! Port traits and typed errors for Kavach adapters (ADR-006).
//!
//! This crate defines interfaces only. Adapters live in their own crates
//! (e.g. `kavach-keys`, `kavach-storage`); test doubles and shared
//! conformance suites live in `kavach-ports-testkit`.

pub mod agent_evidence;
pub mod bundle;
pub mod bundle_verify;
pub mod chain_record;
pub mod checkpoint;
pub mod credential;
mod error;
mod evidence;
pub mod jcs;
mod keys;
mod mandate;
mod policy;
mod reference;
mod replay;
mod time;

pub use credential::{
    CredentialBroker, CredentialRequest, Destination, IssuedCredential, TokenSecret,
    MAX_CREDENTIAL_TTL_SECONDS,
};
pub use error::{ErrorClass, PortError};
pub use evidence::{
    EvaluateIncident, EvidenceStore, IncidentRecorder, IncidentWriteError, NoopIncidentRecorder,
    VecIncidentRecorder,
};
pub use keys::{verify_ed25519, KeyAlgorithm, KeyProvider, PublicKey};
pub use mandate::{
    ConsentSource, DomainEvent, EventBus, MandateStore, RevocationCursor, StoredMandate,
    StoredRevocation,
};
pub use policy::PolicyEngine;
pub use reference::ReferenceResolver;
pub use replay::ReplayGuard;
pub use time::{SyncStatus, SystemClock, TimeSource, TrustedNow};

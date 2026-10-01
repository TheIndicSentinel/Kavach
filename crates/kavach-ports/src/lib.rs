//! Port traits and typed errors for Kavach adapters (ADR-006).
//!
//! This crate defines interfaces only. Adapters live in their own crates
//! (e.g. `kavach-keys`, `kavach-storage`); test doubles and shared
//! conformance suites live in `kavach-ports-testkit`.

pub mod agent_evidence;
mod error;
mod evidence;
mod keys;
mod mandate;
mod policy;
mod replay;
mod time;

pub use error::{ErrorClass, PortError};
pub use evidence::{
    EvaluateIncident, EvidenceStore, IncidentRecorder, IncidentWriteError, NoopIncidentRecorder,
    VecIncidentRecorder,
};
pub use keys::{verify_ed25519, KeyAlgorithm, KeyProvider, PublicKey};
pub use mandate::{ConsentSource, DomainEvent, EventBus, MandateStore, StoredMandate};
pub use policy::PolicyEngine;
pub use replay::ReplayGuard;
pub use time::{SyncStatus, SystemClock, TimeSource, TrustedNow};

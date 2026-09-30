//! Port traits and typed errors for Kavach adapters (ADR-006).
//!
//! This crate defines interfaces only. Adapters live in their own crates
//! (e.g. `kavach-keys`, `kavach-storage`); test doubles and shared
//! conformance suites live in `kavach-ports-testkit`.

mod error;
mod evidence;
mod keys;
mod policy;
mod replay;
mod time;

pub use error::{ErrorClass, PortError};
pub use evidence::{
    EvaluateIncident, EvidenceStore, IncidentRecorder, NoopIncidentRecorder, VecIncidentRecorder,
};
pub use keys::{verify_ed25519, KeyAlgorithm, KeyProvider, PublicKey};
pub use policy::PolicyEngine;
pub use replay::ReplayGuard;
pub use time::{SyncStatus, SystemClock, TimeSource, TrustedNow};

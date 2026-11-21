//! Port traits and typed errors for Kavach adapters (ADR-006).
//!
//! This crate defines interfaces only. Adapters live in their own crates
//! (e.g. `kavach-keys`, `kavach-storage`); test doubles and shared
//! conformance suites live in `kavach-ports-testkit`.

pub mod agent_evidence;
pub mod agent_state;
pub mod approval;
pub mod bundle;
pub mod bundle_verify;
pub mod chain_record;
pub mod checkpoint;
mod contact_preference;
pub mod credential;
mod error;
mod evidence;
pub mod jcs;
mod keys;
mod mandate;
pub mod outcome_resolution;
mod policy;
pub mod provider_secret;
mod reference;
mod replay;
pub mod task_taint;
mod time;

pub use approval::{
    EncryptedReviewSnapshot, ReviewApprovalRecord, ReviewApprovalStore, ReviewDecision,
    ReviewReleaseRecord, ReviewSnapshotStore, StepUpChallenge, StepUpChallengeState,
    StepUpChallengeStore, StepUpProof, StepUpProvider, StepUpRequest, VerifiedStepUp,
};
pub use contact_preference::{require_contact_permission, ContactPreferenceSource};
pub use credential::{
    CredentialBroker, CredentialRequest, Destination, InternalCredentialBroker,
    InternalCredentialFuture, InternalCredentialReceipt, IssuedCredential, StatusQuestions,
    TokenSecret, MAX_CREDENTIAL_TTL_SECONDS,
};
pub use error::{ErrorClass, PortError};
pub use evidence::{
    EvaluateIncident, EvidenceStore, IncidentRecorder, IncidentWriteError, NoopIncidentRecorder,
    VecIncidentRecorder,
};
pub use keys::{verify_ed25519, KeyAlgorithm, KeyProvider, PublicKey};
pub use mandate::{
    scope_time, AppliedRevocation, ClosureRule, ConsentSource, DomainEvent, EventBus, MandateStore,
    RevocationApply, RevocationCursor, ScopedRoot, StoredMandate, StoredRevocation,
};
pub use policy::PolicyEngine;
pub use provider_secret::{ProviderSecretFuture, ProviderSecretStore};
pub use reference::ReferenceResolver;
pub use replay::ReplayGuard;
pub use task_taint::{TaskTaint, TaskTaintSource, TaskTaintStore};
pub use time::{SyncStatus, SystemClock, TimeSource, TrustedNow};

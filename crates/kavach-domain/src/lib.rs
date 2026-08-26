//! Kavach domain layer — types, invariants, and golden test fixtures.
//!
//! No I/O, no HTTP, no database. Follows SOLID: single responsibility,
//! dependency inversion via traits in future crates.

pub mod decision;
pub mod error;
pub mod golden;
pub mod request;
pub mod response;
pub mod types;

pub use decision::Decision;
pub use error::DomainError;
pub use request::{Consent, EvaluateRequest};
pub use response::{DecisionEvent, EvaluateResponse, GovernanceMode, ModelOrigin, SCHEMA_VERSION};
pub use types::{ModelRecord, ModelStatus, PolicyPack, RiskTier};

//! CEL-based policy pack loader and evaluator.

mod cel_context;
mod engine;
mod error;
mod loader;

pub use engine::{PolicyEngine, PolicyEvaluation};
pub use error::PolicyError;
pub use loader::{LoadedPolicyPack, PackLoader};

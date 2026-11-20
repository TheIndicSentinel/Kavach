//! The `kavach-evidence` command (ADR-005 §13).
//!
//! - `verify`: checks a v1 `decision_events` export (hash chain).
//! - [`writer`]: writes an evidence bundle of the agent chain. The format
//!   is specified in `docs/EVIDENCE_BUNDLE.md`; the manifest logic is in
//!   `kavach_ports::bundle`.
//! - [`verify`]: `verify-bundle`, the offline check of a bundle with keys
//!   the operator supplies. No database, no network.
//! - [`export`]: reads one consistent snapshot of the agent chain and writes
//!   a bundle. With the `export` feature, agent export/checkpoints use the
//!   agent-only auditor; `export-decision-events` streams a partition-scoped
//!   v1 credit chain through its separate read-only role.
//!
//! The binary lives here rather than in the `kavach-evidence` library
//! because the ports and storage crates depend on that library.

pub mod export;
#[cfg(feature = "export")]
pub mod postgres;
pub mod verify;
pub mod writer;

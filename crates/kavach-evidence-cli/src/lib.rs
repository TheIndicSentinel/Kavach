//! The `kavach-evidence` command (ADR-005 §13).
//!
//! - `verify`: checks a v1 `decision_events` export (hash chain).
//! - [`writer`]: writes an evidence bundle of the agent chain. The format
//!   is specified in `docs/EVIDENCE_BUNDLE.md`; the manifest logic is in
//!   `kavach_ports::bundle`.
//! - [`export`]: reads one consistent snapshot of a chain and writes it as
//!   a bundle. With the `export` feature (default), the `export` and
//!   `checkpoints` commands read Postgres as a read-only role.
//!
//! The binary lives here rather than in the `kavach-evidence` library
//! because the ports and storage crates depend on that library.

pub mod export;
#[cfg(feature = "export")]
pub mod postgres;
pub mod writer;

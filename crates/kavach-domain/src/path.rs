//! Evaluate transport path — sync RPC vs batch ingest (ADR-001 §2, §6).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvaluatePath {
    /// Sync HTTP/gRPC evaluate (`kavach-api`).
    Sync,
    /// NDJSON batch ingest (`kavach-batch`).
    Batch,
}

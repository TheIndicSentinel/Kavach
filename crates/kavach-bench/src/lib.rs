//! Benchmark harness for the Kavach gateway path (not shipped).
//!
//! Runs the real API in-process (agent and system-of-record listeners on
//! loopback HTTP), with the real gateway, evidence commit, credential
//! broker and mock provider, against Postgres (or the memory store for a
//! smoke run). Each scenario runs at fixed concurrency levels and reports
//! p50/p95/p99/max latency and requests per second, with the environment
//! that produced them. See `docs/PERFORMANCE.md`.

pub mod load;
pub mod micro;
pub mod report;
pub mod stack;

//! Mandate and system-of-record token types over the shared strict JWS
//! codec (`kavach-jws`).

pub use kavach_jws::{sign, verify, KeySet, MAX_TOKEN_BYTES};

pub const TYP_MANDATE: &str = "kavach-mandate+jws";
pub const TYP_SOR_EVENT: &str = "kavach-sor-event+jws";

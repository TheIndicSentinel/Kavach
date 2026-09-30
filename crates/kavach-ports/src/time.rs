use chrono::{DateTime, Utc};

use crate::error::PortError;

/// Clock synchronisation status as reported by the time source (ADR-003 §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncStatus {
    Synced { max_error_ms: u64 },
    Unsynced,
    Unknown,
}

/// A timestamp from the authoritative server-side clock plus its sync status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedNow {
    pub utc: DateTime<Utc>,
    pub sync: SyncStatus,
}

impl TrustedNow {
    /// Returns the time only if the clock is synced within `max_error_ms`;
    /// otherwise `Unavailable` (critical actions fail closed).
    pub fn require_synced(&self, max_error_ms: u64) -> Result<DateTime<Utc>, PortError> {
        match self.sync {
            SyncStatus::Synced { max_error_ms: err } if err <= max_error_ms => Ok(self.utc),
            SyncStatus::Synced { max_error_ms: err } => Err(PortError::unavailable(format!(
                "clock max error {err}ms exceeds {max_error_ms}ms"
            ))),
            SyncStatus::Unsynced => Err(PortError::unavailable("clock not synchronised")),
            SyncStatus::Unknown => Err(PortError::unavailable("clock sync status unknown")),
        }
    }
}

/// The authoritative clock for authorization (ADR-003 §7). Agent- or
/// client-supplied timestamps are never a substitute.
pub trait TimeSource: Send + Sync {
    fn now(&self) -> TrustedNow;
}

/// System clock without sync status (`Unknown`). Suitable for development
/// and non-critical paths; critical actions require a sync-aware source
/// (kernel adapter, M3).
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl TimeSource for SystemClock {
    fn now(&self) -> TrustedNow {
        TrustedNow {
            utc: Utc::now(),
            sync: SyncStatus::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn require_synced_enforces_threshold_and_status() {
        let utc = Utc::now();
        let synced = |ms| TrustedNow {
            utc,
            sync: SyncStatus::Synced { max_error_ms: ms },
        };
        assert_eq!(synced(500).require_synced(1000), Ok(utc));
        assert!(synced(1500).require_synced(1000).is_err());
        for sync in [SyncStatus::Unsynced, SyncStatus::Unknown] {
            let err = TrustedNow { utc, sync }.require_synced(1000).unwrap_err();
            assert_eq!(err.class, crate::ErrorClass::Unavailable);
        }
        assert_eq!(SystemClock.now().sync, SyncStatus::Unknown);
    }
}

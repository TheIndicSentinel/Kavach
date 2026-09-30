//! Kernel clock-synchronisation status (ADR-003 §7, ADR-006).
//!
//! On Linux the kernel NTP state is read with `adjtimex` in read-only mode
//! (`modes = 0`; no `CAP_SYS_TIME` needed): the call returns the clock state
//! and fills `status` (`STA_UNSYNC`) and `maxerror` (microseconds). Anything
//! that cannot be read — another OS, a seccomp profile that denies the
//! syscall — is `Unknown`, and critical actions fail closed on it.

use chrono::Utc;
use kavach_ports::{SyncStatus, TimeSource, TrustedNow};

const TIME_ERROR: i32 = 5;
const STA_UNSYNC: i64 = 0x0040;

/// One read of the kernel clock state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncReading {
    pub status: SyncStatus,
    /// Why the status is what it is (for logs and the probe binary).
    pub detail: String,
}

/// Raw result of the read-only `adjtimex` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawAdjtimex {
    /// The call succeeded: return value (clock state), `status` bits and
    /// `maxerror` in microseconds.
    Ok {
        state: i32,
        status: i64,
        max_error_us: i64,
    },
    /// The call failed with this errno (e.g. `EPERM` under seccomp).
    Err { errno: i32 },
    /// Not available on this platform.
    Unsupported,
}

/// Classifies a raw reading. Pure, so every branch is unit-tested.
#[must_use]
pub fn classify(raw: RawAdjtimex) -> SyncReading {
    match raw {
        RawAdjtimex::Unsupported => SyncReading {
            status: SyncStatus::Unknown,
            detail: "kernel clock status is not available on this platform".into(),
        },
        RawAdjtimex::Err { errno } => SyncReading {
            status: SyncStatus::Unknown,
            detail: format!("adjtimex failed (errno {errno}); a seccomp profile may deny it"),
        },
        RawAdjtimex::Ok { state, status, .. }
            if state == TIME_ERROR || status & STA_UNSYNC != 0 =>
        {
            SyncReading {
                status: SyncStatus::Unsynced,
                detail: format!(
                    "kernel reports unsynchronised (state {state}, status {status:#x})"
                ),
            }
        }
        RawAdjtimex::Ok {
            state,
            max_error_us,
            ..
        } => {
            let max_error_ms = u64::try_from(max_error_us.max(0))
                .unwrap_or(u64::MAX)
                .div_ceil(1000);
            SyncReading {
                status: SyncStatus::Synced { max_error_ms },
                detail: format!("synchronised (state {state}, max error {max_error_us}us)"),
            }
        }
    }
}

/// Reads the kernel clock state once.
#[must_use]
pub fn read() -> SyncReading {
    classify(read_raw())
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn read_raw() -> RawAdjtimex {
    // SAFETY: `timex` is a plain C struct; zeroed is a valid value, and
    // `modes = 0` makes the call read-only. The pointer is to a live, owned
    // local for the duration of the call, and nothing is retained after it.
    let mut buf: libc::timex = unsafe { std::mem::zeroed() };
    buf.modes = 0;
    let state = unsafe { libc::adjtimex(&raw mut buf) };
    if state < 0 {
        return RawAdjtimex::Err {
            errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
        };
    }
    // `c_long` is 64-bit on x86_64 but 32-bit on some Linux targets.
    #[allow(clippy::useless_conversion)]
    let max_error_us = i64::from(buf.maxerror);
    RawAdjtimex::Ok {
        state,
        status: i64::from(buf.status),
        max_error_us,
    }
}

#[cfg(not(target_os = "linux"))]
fn read_raw() -> RawAdjtimex {
    RawAdjtimex::Unsupported
}

/// `TimeSource` backed by the system clock and the kernel sync status.
#[derive(Debug, Default, Clone, Copy)]
pub struct KernelClock;

impl TimeSource for KernelClock {
    fn now(&self) -> TrustedNow {
        TrustedNow {
            utc: Utc::now(),
            sync: read().status,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification_is_fail_closed() {
        assert_eq!(
            classify(RawAdjtimex::Unsupported).status,
            SyncStatus::Unknown
        );
        assert_eq!(
            classify(RawAdjtimex::Err { errno: 1 }).status,
            SyncStatus::Unknown
        );
        let ok = |state, status, max_error_us| RawAdjtimex::Ok {
            state,
            status,
            max_error_us,
        };
        assert_eq!(classify(ok(TIME_ERROR, 0, 0)).status, SyncStatus::Unsynced);
        assert_eq!(classify(ok(0, STA_UNSYNC, 0)).status, SyncStatus::Unsynced);
        assert_eq!(
            classify(ok(0, 0x2001, 1_500)).status,
            SyncStatus::Synced { max_error_ms: 2 }
        );
        assert_eq!(
            classify(ok(0, 0, -5)).status,
            SyncStatus::Synced { max_error_ms: 0 }
        );
    }

    #[test]
    fn reading_the_host_never_panics() {
        let reading = read();
        assert!(!reading.detail.is_empty());
    }
}

//! Startup source of truth for the active pack (PR #26 review, option B).
//!
//! In Postgres mode the persisted runtime pointer — written only by
//! dual-controlled activate/rollback — decides which pack may run. A process
//! started with a different `--pack` path, or with bytes that differ from the
//! digest recorded at activation, is refused.

use std::path::Path;

use crate::admin::RuntimePointers;

/// Result of comparing the startup pack with the persisted pointer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartupPackCheck {
    /// No pointer row yet (first start in this database).
    NoPointer,
    /// Path matches; `pinned` is false when the pointer predates digests.
    Matches { pinned: bool },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StartupPackError {
    #[error(
        "startup pack {startup} differs from the active pack {active} recorded by governance; \
         start with the active pack, or use --bootstrap-pack for audited recovery"
    )]
    PathMismatch { startup: String, active: String },

    #[error(
        "pack bytes differ from the digest recorded at activation: expected {expected}, got {actual}"
    )]
    DigestMismatch { expected: String, actual: String },
}

fn same_path(a: &str, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => Path::new(a) == b,
    }
}

/// Compares the startup pack (`path` and the digest of its bytes) with the
/// persisted runtime pointer.
pub fn check_startup_pack(
    pointers: Option<&RuntimePointers>,
    path: &Path,
    digest: Option<&str>,
) -> Result<StartupPackCheck, StartupPackError> {
    let Some(pointers) = pointers else {
        return Ok(StartupPackCheck::NoPointer);
    };
    if !same_path(&pointers.pack_path, path) {
        return Err(StartupPackError::PathMismatch {
            startup: path.display().to_string(),
            active: pointers.pack_path.clone(),
        });
    }
    match (&pointers.pack_sha256, digest) {
        (Some(expected), Some(actual)) if expected == actual => {
            Ok(StartupPackCheck::Matches { pinned: true })
        }
        (Some(expected), actual) => Err(StartupPackError::DigestMismatch {
            expected: expected.clone(),
            actual: actual.unwrap_or("none").to_string(),
        }),
        (None, _) => Ok(StartupPackCheck::Matches { pinned: false }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn pointers(path: &str, digest: Option<&str>) -> RuntimePointers {
        RuntimePointers {
            pack_path: path.into(),
            model_path: "m.yaml".into(),
            previous_pack_path: None,
            pack_sha256: digest.map(Into::into),
            previous_pack_sha256: None,
            updated_at: Utc::now(),
            updated_by: "admin-1".into(),
            approved_by: "admin-2".into(),
        }
    }

    #[test]
    fn startup_pack_rules() {
        let p = Path::new("/packs/finance/v0.yaml");
        assert_eq!(
            check_startup_pack(None, p, Some("sha256:a")),
            Ok(StartupPackCheck::NoPointer)
        );
        let active = pointers("/packs/finance/v0.yaml", Some("sha256:a"));
        assert_eq!(
            check_startup_pack(Some(&active), p, Some("sha256:a")),
            Ok(StartupPackCheck::Matches { pinned: true })
        );
        assert!(matches!(
            check_startup_pack(Some(&active), p, Some("sha256:b")),
            Err(StartupPackError::DigestMismatch { .. })
        ));
        assert!(matches!(
            check_startup_pack(
                Some(&active),
                Path::new("/packs/finance/v1.yaml"),
                Some("sha256:a")
            ),
            Err(StartupPackError::PathMismatch { .. })
        ));
        let legacy = pointers("/packs/finance/v0.yaml", None);
        assert_eq!(
            check_startup_pack(Some(&legacy), p, Some("sha256:a")),
            Ok(StartupPackCheck::Matches { pinned: false })
        );
    }
}

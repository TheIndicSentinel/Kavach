use std::collections::BTreeMap;
use std::future::{ready, Future};
#[cfg(feature = "test-support")]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use kavach_ports::{PortError, TaskTaint, TaskTaintSource, TaskTaintStore};

#[derive(Default)]
pub struct MemoryTaskTaintStore {
    rows: Mutex<BTreeMap<(String, String), TaskTaint>>,
    #[cfg(feature = "test-support")]
    fail_next_write: AtomicBool,
    #[cfg(feature = "test-support")]
    fail_next_read: AtomicBool,
}

impl MemoryTaskTaintStore {
    /// Injects one storage error for a test that exercises a caller's
    /// fail-closed behavior. Compiled only with the `test-support` feature.
    #[cfg(feature = "test-support")]
    pub fn fail_next_write_for_tests(&self) {
        self.fail_next_write.store(true, Ordering::SeqCst);
    }

    /// Injects one storage error for a test that exercises a caller's
    /// fail-closed behavior. Compiled only with the `test-support` feature.
    #[cfg(feature = "test-support")]
    pub fn fail_next_read_for_tests(&self) {
        self.fail_next_read.store(true, Ordering::SeqCst);
    }
}

impl TaskTaintStore for MemoryTaskTaintStore {
    fn mark_tainted(
        &self,
        tenant_id: &str,
        mandate_id: &str,
        source: TaskTaintSource,
        at: DateTime<Utc>,
    ) -> impl Future<Output = Result<TaskTaint, PortError>> + Send {
        #[cfg(feature = "test-support")]
        if self.fail_next_write.swap(false, Ordering::SeqCst) {
            return ready(Err(PortError::unavailable(
                "injected task taint write failure",
            )));
        }
        let result = self
            .rows
            .lock()
            .map_err(|_| PortError::unavailable("task taint store is unavailable"))
            .map(|mut rows| {
                rows.entry((tenant_id.to_owned(), mandate_id.to_owned()))
                    .or_insert_with(|| TaskTaint {
                        tenant_id: tenant_id.to_owned(),
                        mandate_id: mandate_id.to_owned(),
                        first_tainted_at: at,
                        source,
                    })
                    .clone()
            });
        ready(result)
    }

    fn get_taint(
        &self,
        tenant_id: &str,
        mandate_id: &str,
    ) -> impl Future<Output = Result<Option<TaskTaint>, PortError>> + Send {
        #[cfg(feature = "test-support")]
        if self.fail_next_read.swap(false, Ordering::SeqCst) {
            return ready(Err(PortError::unavailable(
                "injected task taint read failure",
            )));
        }
        let result = self
            .rows
            .lock()
            .map_err(|_| PortError::unavailable("task taint store is unavailable"))
            .map(|rows| {
                rows.get(&(tenant_id.to_owned(), mandate_id.to_owned()))
                    .cloned()
            });
        ready(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn first_taint_is_tenant_scoped_and_cannot_be_cleared_or_replaced() {
        let store = MemoryTaskTaintStore::default();
        let first_at = DateTime::parse_from_rfc3339("2026-11-21T10:00:00Z")
            .unwrap()
            .to_utc();
        let later_at = DateTime::parse_from_rfc3339("2026-11-21T10:01:00Z")
            .unwrap()
            .to_utc();
        let first = store
            .mark_tainted(
                "tenant-a",
                "mandate-1",
                TaskTaintSource::UserContent,
                first_at,
            )
            .await
            .unwrap();
        let replay = store
            .mark_tainted(
                "tenant-a",
                "mandate-1",
                TaskTaintSource::GovernedModelOutput,
                later_at,
            )
            .await
            .unwrap();
        assert_eq!(replay, first);
        assert!(store
            .get_taint("tenant-a", "mandate-1")
            .await
            .unwrap()
            .is_some());
        assert!(store
            .get_taint("tenant-b", "mandate-1")
            .await
            .unwrap()
            .is_none());
    }
}

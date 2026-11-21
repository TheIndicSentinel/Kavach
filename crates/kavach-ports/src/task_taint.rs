//! Monotonic server-derived taint state for an authorized task (PRD FR-5).

use std::future::Future;

use chrono::{DateTime, Utc};

use crate::PortError;

/// A bounded reason category for why Kavach marked a task as tainted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskTaintSource {
    /// Output returned by a mandate-governed model invocation.
    GovernedModelOutput,
    /// Content returned from a registered external-untrusted tool.
    ExternalUntrusted,
    /// Content returned from a registered user-content tool.
    UserContent,
}

impl TaskTaintSource {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GovernedModelOutput => "governed_model_output",
            Self::ExternalUntrusted => "external_untrusted",
            Self::UserContent => "user_content",
        }
    }
}

/// The first server-observed taint for a tenant-scoped mandate/task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskTaint {
    pub tenant_id: String,
    pub mandate_id: String,
    pub first_tainted_at: DateTime<Utc>,
    pub source: TaskTaintSource,
}

/// A monotonic task-taint projection. `mark_tainted` is idempotent: later
/// writes cannot clear or replace the first taint event.
pub trait TaskTaintStore: Send + Sync {
    fn mark_tainted(
        &self,
        tenant_id: &str,
        mandate_id: &str,
        source: TaskTaintSource,
        at: DateTime<Utc>,
    ) -> impl Future<Output = Result<TaskTaint, PortError>> + Send;

    fn get_taint(
        &self,
        tenant_id: &str,
        mandate_id: &str,
    ) -> impl Future<Output = Result<Option<TaskTaint>, PortError>> + Send;
}

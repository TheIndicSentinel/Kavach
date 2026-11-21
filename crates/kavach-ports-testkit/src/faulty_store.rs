//! A store double that delegates everything to a real store and fails on
//! command (fault injection for the gateway and the reconcilers).
//!
//! It adds no behaviour of its own: with no fault set it is the store it
//! wraps, so a test that passes through it exercises the real contract. A
//! fault makes one operation answer `Unavailable("injected")` for the next
//! `n` calls, before the wrapped store is touched, so nothing is half done.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU32, Ordering};

use chrono::NaiveDate;
use kavach_ports::agent_evidence::{
    AgentDecisionRecord, AgentEvidenceStore, CommitRequest, CommitResult, EvidenceSigner,
    ModelInvocationAppend, OutcomeRecord, UnknownOutcomeReview, UnresolvedOutcome,
};
use kavach_ports::agent_state::{
    AgentChangeCursor, AgentState, AgentStateChange, AgentStateStore, Recording, StoredAgentChange,
    StoredAgentState,
};
use kavach_ports::chain_record::{
    AgentStateDraft, AgentStateRecord, ChainRecord, ModelInvocationDraft, ModelOutcomeDraft,
    ModelOutcomeRecord, RevocationDraft, RevocationRecord,
};
use kavach_ports::outcome_resolution::{ResolutionRecord, ResolutionSummary};
use kavach_ports::{PortError, TimeSource};

/// How many more calls of each operation fail. Set with [`Faults::fail`].
#[derive(Debug, Default)]
pub struct Faults {
    /// The evidence commit.
    pub commit: AtomicU32,
    /// Writing an outcome.
    pub record_outcome: AtomicU32,
    /// Reading an outcome (the retry path's lookup).
    pub read_outcome: AtomicU32,
    /// Every read or write of an agent's state, after `agent_state_skip`
    /// calls have been let through (the decision reads it first).
    pub agent_state: AtomicU32,
    pub agent_state_skip: AtomicU32,
    /// When set, `stuck_allows` answers with this list whatever the store
    /// holds: a replica that read its work list before another replica wrote.
    pub stale_stuck_allows: std::sync::Mutex<Option<Vec<AgentDecisionRecord>>>,
}

impl Faults {
    /// Fails the next `n` calls of `which`.
    pub fn fail(which: &AtomicU32, n: u32) {
        which.store(n, Ordering::SeqCst);
    }

    /// Fails every call from now on (until set to 0).
    pub const FOREVER: u32 = u32::MAX;

    /// As [`Faults::hit`] for the agent state, letting `agent_state_skip`
    /// calls through first.
    fn hit_state(&self) -> Result<(), PortError> {
        let skip = self.agent_state_skip.load(Ordering::SeqCst);
        if skip > 0 {
            self.agent_state_skip.store(skip - 1, Ordering::SeqCst);
            return Ok(());
        }
        Self::hit(&self.agent_state)
    }

    fn hit(which: &AtomicU32) -> Result<(), PortError> {
        let left = which.load(Ordering::SeqCst);
        if left == 0 {
            return Ok(());
        }
        if left != Self::FOREVER {
            which.store(left - 1, Ordering::SeqCst);
        }
        Err(PortError::unavailable("injected"))
    }
}

/// The wrapped store, and the faults to inject.
#[derive(Debug, Default)]
pub struct FaultyStore<S> {
    pub inner: S,
    pub faults: Faults,
}

impl<S> FaultyStore<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            faults: Faults::default(),
        }
    }
}

impl<S: AgentEvidenceStore> AgentEvidenceStore for FaultyStore<S> {
    async fn commit(
        &self,
        request: CommitRequest,
        clock: &dyn TimeSource,
        signer: &dyn EvidenceSigner,
    ) -> Result<CommitResult, PortError> {
        Faults::hit(&self.faults.commit)?;
        self.inner.commit(request, clock, signer).await
    }

    async fn get_by_request(
        &self,
        tenant_id: &str,
        agent_id: &str,
        request_id: &str,
    ) -> Result<Option<AgentDecisionRecord>, PortError> {
        self.inner
            .get_by_request(tenant_id, agent_id, request_id)
            .await
    }

    async fn record_outcome(&self, outcome: OutcomeRecord) -> Result<(), PortError> {
        Faults::hit(&self.faults.record_outcome)?;
        self.inner.record_outcome(outcome).await
    }

    async fn outcome(
        &self,
        tenant_id: &str,
        credential_id: &str,
    ) -> Result<Option<OutcomeRecord>, PortError> {
        Faults::hit(&self.faults.read_outcome)?;
        self.inner.outcome(tenant_id, credential_id).await
    }

    async fn record_resolution(&self, resolution: ResolutionRecord) -> Result<bool, PortError> {
        self.inner.record_resolution(resolution).await
    }

    async fn resolutions(
        &self,
        tenant_id: &str,
        credential_id: &str,
    ) -> Result<Vec<ResolutionRecord>, PortError> {
        self.inner.resolutions(tenant_id, credential_id).await
    }

    async fn unresolved_outcomes(
        &self,
        tenant_id: &str,
        limit: u32,
    ) -> Result<Vec<UnresolvedOutcome>, PortError> {
        self.inner.unresolved_outcomes(tenant_id, limit).await
    }

    async fn unknown_outcome_reviews(
        &self,
        tenant_id: &str,
        after: Option<&str>,
        limit: u32,
    ) -> Result<Vec<UnknownOutcomeReview>, PortError> {
        self.inner
            .unknown_outcome_reviews(tenant_id, after, limit)
            .await
    }

    async fn stuck_allows(
        &self,
        tenant_id: &str,
        decided_after: chrono::DateTime<chrono::Utc>,
        decided_before: chrono::DateTime<chrono::Utc>,
        limit: u32,
    ) -> Result<Vec<AgentDecisionRecord>, PortError> {
        if let Some(stale) = self
            .faults
            .stale_stuck_allows
            .lock()
            .map_err(|_| PortError::unavailable("injected lock"))?
            .clone()
        {
            return Ok(stale);
        }
        self.inner
            .stuck_allows(tenant_id, decided_after, decided_before, limit)
            .await
    }

    async fn resolution_summary(&self, tenant_id: &str) -> Result<ResolutionSummary, PortError> {
        self.inner.resolution_summary(tenant_id).await
    }

    async fn records(
        &self,
        tenant_id: &str,
        partition_id: i32,
    ) -> Result<Vec<ChainRecord>, PortError> {
        self.inner.records(tenant_id, partition_id).await
    }

    async fn append_model_invocation(
        &self,
        draft: ModelInvocationDraft,
        clock: &dyn TimeSource,
        signer: &dyn EvidenceSigner,
    ) -> Result<ModelInvocationAppend, PortError> {
        self.inner
            .append_model_invocation(draft, clock, signer)
            .await
    }

    async fn append_model_outcome(
        &self,
        draft: ModelOutcomeDraft,
        clock: &dyn TimeSource,
        signer: &dyn EvidenceSigner,
    ) -> Result<ModelOutcomeRecord, PortError> {
        self.inner.append_model_outcome(draft, clock, signer).await
    }

    async fn append_revocation(
        &self,
        draft: RevocationDraft,
        clock: &dyn TimeSource,
        signer: &dyn EvidenceSigner,
    ) -> Result<RevocationRecord, PortError> {
        self.inner.append_revocation(draft, clock, signer).await
    }

    async fn revocation_record(
        &self,
        tenant_id: &str,
        source_system: &str,
        event_id: &str,
    ) -> Result<Option<RevocationRecord>, PortError> {
        self.inner
            .revocation_record(tenant_id, source_system, event_id)
            .await
    }

    async fn append_agent_state(
        &self,
        draft: AgentStateDraft,
        clock: &dyn TimeSource,
        signer: &dyn EvidenceSigner,
    ) -> Result<AgentStateRecord, PortError> {
        self.inner.append_agent_state(draft, clock, signer).await
    }

    async fn agent_state_record(
        &self,
        tenant_id: &str,
        agent_id: &str,
        change_no: i64,
    ) -> Result<Option<AgentStateRecord>, PortError> {
        self.inner
            .agent_state_record(tenant_id, agent_id, change_no)
            .await
    }

    async fn record(
        &self,
        tenant_id: &str,
        record_id: &str,
    ) -> Result<Option<AgentDecisionRecord>, PortError> {
        self.inner.record(tenant_id, record_id).await
    }

    async fn contacts_on(
        &self,
        tenant_id: &str,
        subject_pseudonym: &str,
        ist_date: NaiveDate,
    ) -> Result<u32, PortError> {
        self.inner
            .contacts_on(tenant_id, subject_pseudonym, ist_date)
            .await
    }
}

impl<S: AgentStateStore> AgentStateStore for FaultyStore<S> {
    async fn states(
        &self,
        tenant_id: &str,
        agent_ids: &[String],
    ) -> Result<BTreeMap<String, AgentState>, PortError> {
        self.faults.hit_state()?;
        self.inner.states(tenant_id, agent_ids).await
    }

    async fn current(
        &self,
        tenant_id: &str,
        agent_id: &str,
    ) -> Result<Option<StoredAgentState>, PortError> {
        self.faults.hit_state()?;
        self.inner.current(tenant_id, agent_id).await
    }

    async fn set(&self, change: AgentStateChange) -> Result<StoredAgentState, PortError> {
        self.faults.hit_state()?;
        self.inner.set(change).await
    }

    async fn set_recorded(
        &self,
        change: AgentStateChange,
        recording: Recording<'_>,
    ) -> Result<(StoredAgentState, AgentStateRecord), PortError> {
        self.faults.hit_state()?;
        self.inner.set_recorded(change, recording).await
    }

    async fn changes_after(
        &self,
        after: Option<AgentChangeCursor>,
        limit: u32,
    ) -> Result<Vec<StoredAgentChange>, PortError> {
        self.inner.changes_after(after, limit).await
    }
}

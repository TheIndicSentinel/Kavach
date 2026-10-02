//! In-memory `AgentEvidenceStore` (tests and development; agent routes refuse
//! it at startup, ADR-007). One mutex makes each commit atomic.

use std::collections::HashMap;
use std::future::{ready, Future};
use std::sync::Mutex;

use chrono::NaiveDate;
use kavach_domain::Decision;
use kavach_ports::agent_evidence::{
    complete_payload, finalise, is_allow, seal, AgentDecisionRecord, AgentEvidenceStore,
    CommitRequest, CommitResult, EvidenceSigner, OutcomeRecord, RequestBinding, GENESIS,
};
use kavach_ports::checkpoint::{
    check_follows, check_storable, Appended, Checkpoint, CheckpointStore, Scope,
    CHAIN_AGENT_DECISIONS,
};
use kavach_ports::{PortError, TimeSource};

type RequestKey = (String, String, String);

#[derive(Default)]
struct State {
    heads: HashMap<(String, i32), (i64, String)>,
    records: Vec<AgentDecisionRecord>,
    requests: HashMap<RequestKey, (usize, RequestBinding)>,
    counters: HashMap<(String, String, NaiveDate), u32>,
    outcomes: HashMap<(String, String), OutcomeRecord>,
    checkpoints: Vec<Checkpoint>,
}

fn in_scope(checkpoint: &Checkpoint, scope: Scope<'_>) -> bool {
    let p = &checkpoint.payload;
    p.tenant_id == scope.tenant_id && p.partition_id == scope.partition_id && p.chain == scope.chain
}

#[derive(Default)]
pub struct MemoryAgentEvidenceStore {
    state: Mutex<State>,
}

fn poisoned<T>(_: T) -> PortError {
    PortError::unavailable("agent evidence lock poisoned")
}

/// Same request → replay; same id, other content → conflict.
pub(crate) fn classify(
    record: AgentDecisionRecord,
    stored: &RequestBinding,
    requested: &RequestBinding,
) -> CommitResult {
    if stored == requested {
        CommitResult::Replayed(Box::new(record))
    } else {
        CommitResult::Conflict(Box::new(record))
    }
}

fn request_key(request: &CommitRequest) -> RequestKey {
    (
        request.tenant_id.clone(),
        request.draft.actor.agent_id.clone(),
        request.draft.request_id.clone(),
    )
}

impl MemoryAgentEvidenceStore {
    fn commit_sync(
        &self,
        request: CommitRequest,
        clock: &dyn TimeSource,
        signer: &dyn EvidenceSigner,
    ) -> Result<CommitResult, PortError> {
        let mut state = self.state.lock().map_err(poisoned)?;
        let key = request_key(&request);
        if let Some((index, binding)) = state.requests.get(&key) {
            return Ok(classify(
                state.records[*index].clone(),
                binding,
                &request.binding,
            ));
        }
        let head_key = (request.tenant_id.clone(), request.partition_id);
        let (head_seq, head_hash) = state
            .heads
            .get(&head_key)
            .cloned()
            .unwrap_or((0, GENESIS.to_string()));

        let now = clock.now();
        let (mut decision, mut reason) = finalise(request.draft.pre_commit_decision, &request, now);
        let mut reserved = None;
        if let (true, Some(contact)) = (is_allow(decision), &request.contact) {
            let counter_key = (
                request.tenant_id.clone(),
                request.draft.subject_pseudonym.clone(),
                contact.ist_date,
            );
            let used = state.counters.get(&counter_key).copied().unwrap_or(0);
            if used < contact.max_per_day {
                reserved = Some((counter_key, used + 1));
            } else {
                decision = Decision::Block;
                reason = Some("contact_cap_reached");
            }
        }
        let payload = complete_payload(&request, head_seq + 1, &head_hash, decision, reason, now);
        // Sign before mutating anything: a signing failure leaves no trace.
        let record = seal(payload, signer)?;
        if let Some((counter_key, count)) = reserved {
            state.counters.insert(counter_key, count);
        }
        state
            .heads
            .insert(head_key, (record.payload.seq, record.hash.clone()));
        state.records.push(record.clone());
        let index = state.records.len() - 1;
        state.requests.insert(key, (index, request.binding));
        Ok(CommitResult::Committed(Box::new(record)))
    }

    fn get_by_request_sync(
        &self,
        tenant_id: &str,
        agent_id: &str,
        request_id: &str,
    ) -> Result<Option<AgentDecisionRecord>, PortError> {
        let state = self.state.lock().map_err(poisoned)?;
        Ok(state
            .requests
            .get(&(tenant_id.into(), agent_id.into(), request_id.into()))
            .map(|(index, _)| state.records[*index].clone()))
    }

    fn record_outcome_sync(&self, outcome: OutcomeRecord) -> Result<(), PortError> {
        let mut state = self.state.lock().map_err(poisoned)?;
        let matches = state.records.iter().any(|r| {
            r.payload.tenant_id == outcome.tenant_id
                && r.payload.credential_id.as_deref() == Some(outcome.credential_id.as_str())
                && r.hash == outcome.record_hash
        });
        if !matches {
            return Err(PortError::rejected("no allowed record for this credential"));
        }
        let key = (outcome.tenant_id.clone(), outcome.credential_id.clone());
        if state.outcomes.contains_key(&key) {
            return Err(PortError::rejected("outcome already recorded"));
        }
        state.outcomes.insert(key, outcome);
        Ok(())
    }

    fn outcome_sync(
        &self,
        tenant_id: &str,
        credential_id: &str,
    ) -> Result<Option<OutcomeRecord>, PortError> {
        let state = self.state.lock().map_err(poisoned)?;
        Ok(state
            .outcomes
            .get(&(tenant_id.into(), credential_id.into()))
            .cloned())
    }

    fn records_sync(
        &self,
        tenant_id: &str,
        partition_id: i32,
    ) -> Result<Vec<AgentDecisionRecord>, PortError> {
        let state = self.state.lock().map_err(poisoned)?;
        Ok(state
            .records
            .iter()
            .filter(|r| r.payload.tenant_id == tenant_id && r.payload.partition_id == partition_id)
            .cloned()
            .collect())
    }

    fn contacts_on_sync(
        &self,
        tenant_id: &str,
        subject_pseudonym: &str,
        ist_date: NaiveDate,
    ) -> Result<u32, PortError> {
        let state = self.state.lock().map_err(poisoned)?;
        Ok(state
            .counters
            .get(&(tenant_id.into(), subject_pseudonym.into(), ist_date))
            .copied()
            .unwrap_or(0))
    }
}

impl MemoryAgentEvidenceStore {
    fn head_sync(&self, scope: Scope<'_>) -> Result<Option<(i64, String)>, PortError> {
        if scope.chain != CHAIN_AGENT_DECISIONS {
            return Ok(None);
        }
        let state = self.state.lock().map_err(poisoned)?;
        Ok(state
            .heads
            .get(&(scope.tenant_id.to_string(), scope.partition_id))
            .filter(|(seq, _)| *seq > 0)
            .cloned())
    }

    fn latest_sync(&self, scope: Scope<'_>) -> Result<Option<Checkpoint>, PortError> {
        let state = self.state.lock().map_err(poisoned)?;
        Ok(state
            .checkpoints
            .iter()
            .rfind(|c| in_scope(c, scope))
            .cloned())
    }

    fn append_sync(&self, checkpoint: &Checkpoint) -> Result<Appended, PortError> {
        check_storable(checkpoint)?;
        let p = &checkpoint.payload;
        let mut state = self.state.lock().map_err(poisoned)?;
        let covered = state.records.iter().any(|r| {
            r.payload.tenant_id == p.tenant_id
                && r.payload.partition_id == p.partition_id
                && r.payload.seq == p.seq
                && r.hash == p.head_hash
        });
        if !covered {
            return Err(PortError::rejected(
                "no record with this seq and hash to checkpoint",
            ));
        }
        let scope = Scope {
            tenant_id: &p.tenant_id,
            partition_id: p.partition_id,
            chain: &p.chain,
        };
        let latest = state.checkpoints.iter().rfind(|c| in_scope(c, scope));
        let result = check_follows(checkpoint, latest)?;
        if result == Appended::Written {
            state.checkpoints.push(checkpoint.clone());
        }
        Ok(result)
    }

    fn list_sync(
        &self,
        scope: Scope<'_>,
        after_seq: i64,
        limit: u32,
    ) -> Result<Vec<Checkpoint>, PortError> {
        let state = self.state.lock().map_err(poisoned)?;
        Ok(state
            .checkpoints
            .iter()
            .filter(|c| in_scope(c, scope) && c.payload.seq > after_seq)
            .take(usize::try_from(limit).unwrap_or(usize::MAX))
            .cloned()
            .collect())
    }
}

impl CheckpointStore for MemoryAgentEvidenceStore {
    fn head(
        &self,
        scope: Scope<'_>,
    ) -> impl Future<Output = Result<Option<(i64, String)>, PortError>> + Send {
        ready(self.head_sync(scope))
    }

    fn latest(
        &self,
        scope: Scope<'_>,
    ) -> impl Future<Output = Result<Option<Checkpoint>, PortError>> + Send {
        ready(self.latest_sync(scope))
    }

    fn append(
        &self,
        checkpoint: &Checkpoint,
    ) -> impl Future<Output = Result<Appended, PortError>> + Send {
        ready(self.append_sync(checkpoint))
    }

    fn list(
        &self,
        scope: Scope<'_>,
        after_seq: i64,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<Checkpoint>, PortError>> + Send {
        ready(self.list_sync(scope, after_seq, limit))
    }
}

impl AgentEvidenceStore for MemoryAgentEvidenceStore {
    fn commit(
        &self,
        request: CommitRequest,
        clock: &dyn TimeSource,
        signer: &dyn EvidenceSigner,
    ) -> impl Future<Output = Result<CommitResult, PortError>> + Send {
        ready(self.commit_sync(request, clock, signer))
    }

    fn get_by_request(
        &self,
        tenant_id: &str,
        agent_id: &str,
        request_id: &str,
    ) -> impl Future<Output = Result<Option<AgentDecisionRecord>, PortError>> + Send {
        ready(self.get_by_request_sync(tenant_id, agent_id, request_id))
    }

    fn record_outcome(
        &self,
        outcome: OutcomeRecord,
    ) -> impl Future<Output = Result<(), PortError>> + Send {
        ready(self.record_outcome_sync(outcome))
    }

    fn outcome(
        &self,
        tenant_id: &str,
        credential_id: &str,
    ) -> impl Future<Output = Result<Option<OutcomeRecord>, PortError>> + Send {
        ready(self.outcome_sync(tenant_id, credential_id))
    }

    fn records(
        &self,
        tenant_id: &str,
        partition_id: i32,
    ) -> impl Future<Output = Result<Vec<AgentDecisionRecord>, PortError>> + Send {
        ready(self.records_sync(tenant_id, partition_id))
    }

    fn contacts_on(
        &self,
        tenant_id: &str,
        subject_pseudonym: &str,
        ist_date: NaiveDate,
    ) -> impl Future<Output = Result<u32, PortError>> + Send {
        ready(self.contacts_on_sync(tenant_id, subject_pseudonym, ist_date))
    }
}

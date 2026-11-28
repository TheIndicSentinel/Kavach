//! Postgres `AgentEvidenceStore` (H5a-3b, ADR-005 §6 phase 1).
//!
//! `commit` is one transaction. **Lock order: the partition head row first,
//! then the contact counter row** — any future resource must come after
//! these, or concurrent commits can deadlock.

use std::collections::BTreeMap;

use chrono::{DateTime, NaiveDate, Utc};
use kavach_domain::Decision;
use kavach_domain::ReasonCode;
use kavach_ports::agent_evidence::{
    complete_payload, finalise, is_allow, seal, AgentDecisionRecord, AgentEvidenceStore,
    CommitRequest, CommitResult, EvidenceSigner, Outcome, OutcomeRecord, RequestBinding,
    UnknownOutcomeReview, UnresolvedOutcome, GENESIS,
};
use kavach_ports::agent_state::{
    AgentChangeCursor, AgentState, AgentStateChange, AgentStateStore, Recording, StoredAgentChange,
    StoredAgentState,
};
use kavach_ports::chain_record::{
    seal_agent_state, seal_revocation, AgentStateDraft, AgentStateRecord, ChainRecord,
    RevocationDraft, RevocationRecord,
};
use kavach_ports::checkpoint::{
    check_follows, check_storable, Appended, Checkpoint, CheckpointStore, Scope,
    CHAIN_AGENT_DECISIONS,
};
use kavach_ports::outcome_resolution::{
    check_against_outcome, check_form, summarise, OutcomeRows, ResolutionRecord, ResolutionSource,
    ResolutionState, ResolutionSummary,
};
use kavach_ports::{PortError, TimeSource};
use sqlx::{PgPool, Postgres, Row, Transaction};

use crate::agent_evidence::classify;

fn unavailable(err: &sqlx::Error) -> PortError {
    PortError::unavailable(format!("agent evidence: {err}"))
}

fn is_unique_violation(err: &sqlx::Error) -> bool {
    matches!(err, sqlx::Error::Database(db) if db.code().as_deref() == Some("23505"))
}

fn json<T: serde::Serialize>(value: &T) -> Result<serde_json::Value, PortError> {
    serde_json::to_value(value).map_err(|e| PortError::invalid(format!("evidence json: {e}")))
}

fn decision_str(decision: Decision) -> String {
    serde_json::to_value(decision)
        .ok()
        .and_then(|v| v.as_str().map(ToString::to_string))
        .unwrap_or_default()
}

#[derive(Clone)]
pub struct PostgresAgentEvidenceStore {
    pool: PgPool,
}

type Existing = (AgentDecisionRecord, RequestBinding);

fn row_to_record(row: &sqlx::postgres::PgRow) -> Result<AgentDecisionRecord, PortError> {
    let payload: serde_json::Value = row.try_get("payload").map_err(|e| unavailable(&e))?;
    Ok(AgentDecisionRecord {
        payload: serde_json::from_value(payload)
            .map_err(|e| PortError::invalid(format!("stored payload: {e}")))?,
        hash: row.try_get("hash").map_err(|e| unavailable(&e))?,
        sig: row.try_get("sig").map_err(|e| unavailable(&e))?,
    })
}

/// A stored record of any kind, read by the kind its payload states; a kind
/// this build does not know is an error, never skipped.
pub(super) fn row_to_chain_record(row: &sqlx::postgres::PgRow) -> Result<ChainRecord, PortError> {
    let mut value: serde_json::Value = row.try_get("payload").map_err(|e| unavailable(&e))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| PortError::invalid("stored payload is not an object"))?;
    let hash: String = row.try_get("hash").map_err(|e| unavailable(&e))?;
    let sig: String = row.try_get("sig").map_err(|e| unavailable(&e))?;
    object.insert("hash".into(), hash.into());
    object.insert("sig".into(), sig.into());
    serde_json::from_value(value).map_err(|e| PortError::invalid(format!("stored record: {e}")))
}

fn row_to_revocation(row: &sqlx::postgres::PgRow) -> Result<RevocationRecord, PortError> {
    match row_to_chain_record(row)? {
        ChainRecord::Revocation(record) => Ok(record),
        ChainRecord::Decision(_) | ChainRecord::AgentState(_) => Err(PortError::invalid(
            "a revocation row holds another kind of payload",
        )),
    }
}

fn row_to_state_record(row: &sqlx::postgres::PgRow) -> Result<AgentStateRecord, PortError> {
    match row_to_chain_record(row)? {
        ChainRecord::AgentState(record) => Ok(record),
        ChainRecord::Decision(_) | ChainRecord::Revocation(_) => Err(PortError::invalid(
            "an agent-state row holds another kind of payload",
        )),
    }
}

async fn find_state_record<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    tenant_id: &str,
    agent_id: &str,
    change_no: i64,
) -> Result<Option<AgentStateRecord>, PortError> {
    let row = sqlx::query(
        "SELECT payload, hash, sig FROM agent_decisions \
        WHERE kind = 'agent_state' AND tenant_id = $1 AND agent_id = $2 \
            AND state_change_no = $3",
    )
    .bind(tenant_id)
    .bind(agent_id)
    .bind(change_no)
    .fetch_optional(executor)
    .await
    .map_err(|e| unavailable(&e))?;
    row.as_ref().map(row_to_state_record).transpose()
}

fn same_state_record(
    stored: AgentStateRecord,
    draft: &AgentStateDraft,
) -> Result<AgentStateRecord, PortError> {
    if draft.matches(&stored) {
        Ok(stored)
    } else {
        Err(PortError::rejected(
            "this change of the agent's state is recorded with different content",
        ))
    }
}

async fn find_revocation<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    tenant_id: &str,
    source_system: &str,
    event_id: &str,
) -> Result<Option<RevocationRecord>, PortError> {
    let row = sqlx::query(
        "SELECT payload, hash, sig FROM agent_decisions \
        WHERE kind = 'mandate_revocation' AND tenant_id = $1 AND source_system = $2 \
            AND event_id = $3",
    )
    .bind(tenant_id)
    .bind(source_system)
    .bind(event_id)
    .fetch_optional(executor)
    .await
    .map_err(|e| unavailable(&e))?;
    row.as_ref().map(row_to_revocation).transpose()
}

/// The stored revocation for this event, if it is this revocation.
fn same_revocation(
    stored: RevocationRecord,
    draft: &RevocationDraft,
) -> Result<RevocationRecord, PortError> {
    if draft.matches(&stored) {
        Ok(stored)
    } else {
        Err(PortError::rejected(
            "this event's revocation is recorded with different content",
        ))
    }
}

async fn find<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    tenant_id: &str,
    agent_id: &str,
    idempotency_key: &str,
) -> Result<Option<Existing>, PortError> {
    let row = sqlx::query(
        "SELECT payload, hash, sig, binding FROM agent_decisions \
        WHERE tenant_id = $1 AND agent_id = $2 AND mode = 'commit' AND kind = 'agent_decision' \
        AND COALESCE(idempotency_key, request_id) = $3",
    )
    .bind(tenant_id)
    .bind(agent_id)
    .bind(idempotency_key)
    .fetch_optional(executor)
    .await
    .map_err(|e| unavailable(&e))?;
    let Some(row) = row else { return Ok(None) };
    let binding: serde_json::Value = row.try_get("binding").map_err(|e| unavailable(&e))?;
    let binding = serde_json::from_value(binding)
        .map_err(|e| PortError::invalid(format!("stored binding: {e}")))?;
    Ok(Some((row_to_record(&row)?, binding)))
}

impl PostgresAgentEvidenceStore {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Locks the partition head and returns it. One round trip on every
    /// commit after the first: the row is created (and locked again) only
    /// when it does not exist yet, once per tenant and partition.
    async fn lock_head(
        tx: &mut Transaction<'_, Postgres>,
        tenant_id: &str,
        partition_id: i32,
    ) -> Result<(i64, String), PortError> {
        let select = || {
            sqlx::query(
                "SELECT head_seq, head_hash FROM agent_evidence_chains \
                WHERE tenant_id = $1 AND partition_id = $2 FOR UPDATE",
            )
            .bind(tenant_id)
            .bind(partition_id)
        };
        let mut row = select()
            .fetch_optional(&mut **tx)
            .await
            .map_err(|e| unavailable(&e))?;
        if row.is_none() {
            // Concurrent first commits both insert-or-skip, then both lock
            // the one row: they still run one after the other.
            sqlx::query(
                "INSERT INTO agent_evidence_chains (tenant_id, partition_id, head_seq, head_hash) \
                VALUES ($1, $2, 0, $3) ON CONFLICT DO NOTHING",
            )
            .bind(tenant_id)
            .bind(partition_id)
            .bind(GENESIS)
            .execute(&mut **tx)
            .await
            .map_err(|e| unavailable(&e))?;
            row = Some(
                select()
                    .fetch_one(&mut **tx)
                    .await
                    .map_err(|e| unavailable(&e))?,
            );
        }
        let row = row.ok_or_else(|| PortError::unavailable("partition head missing"))?;
        Ok((
            row.try_get("head_seq").map_err(|e| unavailable(&e))?,
            row.try_get("head_hash").map_err(|e| unavailable(&e))?,
        ))
    }

    /// Reserves one contact slot; `false` when the day's cap is reached.
    async fn reserve(
        tx: &mut Transaction<'_, Postgres>,
        tenant_id: &str,
        pseudonym: &str,
        ist_date: NaiveDate,
        max_per_day: u32,
    ) -> Result<bool, PortError> {
        if max_per_day == 0 {
            return Ok(false);
        }
        let row = sqlx::query(
            "INSERT INTO contact_counters (tenant_id, subject_pseudonym, ist_date, count) \
            VALUES ($1, $2, $3, 1) \
            ON CONFLICT (tenant_id, subject_pseudonym, ist_date) \
            DO UPDATE SET count = contact_counters.count + 1 \
            WHERE contact_counters.count < $4 RETURNING count",
        )
        .bind(tenant_id)
        .bind(pseudonym)
        .bind(ist_date)
        .bind(i32::try_from(max_per_day).unwrap_or(i32::MAX))
        .fetch_optional(&mut **tx)
        .await
        .map_err(|e| unavailable(&e))?;
        Ok(row.is_some())
    }

    async fn commit_once(
        &self,
        request: &CommitRequest,
        clock: &dyn TimeSource,
        signer: &dyn EvidenceSigner,
    ) -> Result<CommitResult, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let (head_seq, head_hash) =
            Self::lock_head(&mut tx, &request.tenant_id, request.partition_id)
                .await
                .map_err(|e| sqlx::Error::Protocol(e.message))?;
        // No second request lookup here: a concurrent duplicate is stopped
        // by the unique key on (tenant, agent, mode, idempotency_key or, for
        // rows from before migration 030, request_id), which
        // aborts this transaction (and any slot it reserved); `commit`
        // then reads the stored record on a fresh connection.
        let now = clock.now();
        let (mut decision, mut reason) = finalise(request.draft.pre_commit_decision, request, now);
        if let (true, Some(contact)) = (is_allow(decision), &request.contact) {
            let reserved = Self::reserve(
                &mut tx,
                &request.tenant_id,
                &request.draft.subject_pseudonym,
                contact.ist_date,
                contact.max_per_day,
            )
            .await
            .map_err(|e| sqlx::Error::Protocol(e.message))?;
            if !reserved {
                decision = Decision::Block;
                reason = Some("contact_cap_reached");
            }
        }
        let payload = complete_payload(request, head_seq + 1, &head_hash, decision, reason, now);
        let record = seal(payload, signer).map_err(|e| sqlx::Error::Protocol(e.message))?;
        let p = &record.payload;
        // The record and the head it advances, in one statement.
        let advanced = sqlx::query(
            "WITH inserted AS ( \
                INSERT INTO agent_decisions (tenant_id, partition_id, seq, record_id, \
                    prev_hash, hash, sig, key_id, payload, agent_id, request_id, idempotency_key, binding, \
                    credential_id, returned_decision) \
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) \
                RETURNING tenant_id, partition_id, seq, hash) \
            UPDATE agent_evidence_chains AS c SET head_seq = inserted.seq, \
                head_hash = inserted.hash \
            FROM inserted \
            WHERE c.tenant_id = inserted.tenant_id AND c.partition_id = inserted.partition_id",
        )
        .bind(&p.tenant_id)
        .bind(p.partition_id)
        .bind(p.seq)
        .bind(&p.record_id)
        .bind(&p.prev_hash)
        .bind(&record.hash)
        .bind(&record.sig)
        .bind(&p.key_id)
        .bind(json(p).map_err(|e| sqlx::Error::Protocol(e.message))?)
        .bind(&p.actor.agent_id)
        .bind(&p.request_id)
        .bind(&request.idempotency_key)
        .bind(json(&request.binding).map_err(|e| sqlx::Error::Protocol(e.message))?)
        .bind(&p.credential_id)
        .bind(decision_str(p.returned_decision))
        .execute(&mut *tx)
        .await?;
        if advanced.rows_affected() != 1 {
            // The head is locked above, so this cannot happen; if it does,
            // nothing is committed.
            return Err(sqlx::Error::Protocol(
                "the partition head did not advance".into(),
            ));
        }
        tx.commit().await?;
        Ok(CommitResult::Committed(Box::new(record)))
    }

    /// One revocation record and the head it advances, in one transaction
    /// under the partition lock (the same lock order as `commit`).
    async fn append_revocation_once(
        &self,
        draft: &RevocationDraft,
        clock: &dyn TimeSource,
        signer: &dyn EvidenceSigner,
    ) -> Result<RevocationRecord, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let (head_seq, head_hash) = Self::lock_head(&mut tx, &draft.tenant_id, draft.partition_id)
            .await
            .map_err(|e| sqlx::Error::Protocol(e.message))?;
        let payload = draft.complete(head_seq + 1, &head_hash, signer.key_id(), clock.now());
        let record =
            seal_revocation(payload, signer).map_err(|e| sqlx::Error::Protocol(e.message))?;
        let p = &record.payload;
        let advanced = sqlx::query(
            "WITH inserted AS ( \
                INSERT INTO agent_decisions (tenant_id, partition_id, seq, record_id, \
                    prev_hash, hash, sig, key_id, payload, kind, source_system, event_id) \
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'mandate_revocation', $10, $11) \
                RETURNING tenant_id, partition_id, seq, hash) \
            UPDATE agent_evidence_chains AS c SET head_seq = inserted.seq, \
                head_hash = inserted.hash \
            FROM inserted \
            WHERE c.tenant_id = inserted.tenant_id AND c.partition_id = inserted.partition_id",
        )
        .bind(&p.tenant_id)
        .bind(p.partition_id)
        .bind(p.seq)
        .bind(&p.record_id)
        .bind(&p.prev_hash)
        .bind(&record.hash)
        .bind(&record.sig)
        .bind(&p.key_id)
        .bind(json(p).map_err(|e| sqlx::Error::Protocol(e.message))?)
        .bind(&p.source_system)
        .bind(&p.event_id)
        .execute(&mut *tx)
        .await?;
        if advanced.rows_affected() != 1 {
            return Err(sqlx::Error::Protocol(
                "the partition head did not advance".into(),
            ));
        }
        tx.commit().await?;
        Ok(record)
    }
}

/// A resolution from a row that has the resolution's columns (not the
/// tenant or credential, which the caller knows).
pub(crate) fn resolution_from_row(
    row: &sqlx::postgres::PgRow,
    tenant_id: &str,
    credential_id: &str,
) -> Result<ResolutionRecord, PortError> {
    let state: String = row.try_get("state").map_err(|e| unavailable(&e))?;
    let source: String = row.try_get("source").map_err(|e| unavailable(&e))?;
    Ok(ResolutionRecord {
        tenant_id: tenant_id.into(),
        credential_id: credential_id.into(),
        outcome_ref: row.try_get("outcome_ref").map_err(|e| unavailable(&e))?,
        // Never guess: an unrecognised value is a corrupt row.
        state: ResolutionState::parse(&state)
            .ok_or_else(|| PortError::invalid("stored resolution has an unknown state"))?,
        source: ResolutionSource::parse(&source)
            .ok_or_else(|| PortError::invalid("stored resolution has an unknown source"))?,
        reason: row.try_get("reason").map_err(|e| unavailable(&e))?,
        evidence_digest: row
            .try_get("evidence_digest")
            .map_err(|e| unavailable(&e))?,
        resolved_by: row.try_get("resolved_by").map_err(|e| unavailable(&e))?,
        approved_by: row.try_get("approved_by").map_err(|e| unavailable(&e))?,
        ts: row.try_get("ts").map_err(|e| unavailable(&e))?,
        key_id: row.try_get("key_id").map_err(|e| unavailable(&e))?,
        sig: row.try_get("sig").map_err(|e| unavailable(&e))?,
    })
}

impl AgentEvidenceStore for PostgresAgentEvidenceStore {
    async fn commit(
        &self,
        request: CommitRequest,
        clock: &dyn TimeSource,
        signer: &dyn EvidenceSigner,
    ) -> Result<CommitResult, PortError> {
        request.validate_idempotency()?;
        // Retries are answered without queueing on the partition lock.
        let agent = request.draft.actor.agent_id.clone();
        if let Some((record, binding)) = find(
            &self.pool,
            &request.tenant_id,
            &agent,
            &request.idempotency_key,
        )
        .await?
        {
            return Ok(classify(record, &binding, &request.binding));
        }
        match self.commit_once(&request, clock, signer).await {
            Ok(result) => Ok(result),
            // A unique key stopped this commit, and its transaction rolled
            // back (with any slot it reserved). The stored record decides
            // what that was, read on a fresh connection: a record for this
            // request means a concurrent duplicate won; none means a clash
            // on another key (`record_id`, `credential_id`), which is an
            // error and never a retry. (A duplicate may break the request
            // key and the credential key at once; which index Postgres
            // reports first does not matter here.)
            Err(err) if is_unique_violation(&err) => {
                match find(
                    &self.pool,
                    &request.tenant_id,
                    &agent,
                    &request.idempotency_key,
                )
                .await?
                {
                    Some((record, binding)) => Ok(classify(record, &binding, &request.binding)),
                    None => Err(unavailable(&err)),
                }
            }
            Err(sqlx::Error::Protocol(message)) => Err(PortError::unavailable(message)),
            Err(err) => Err(unavailable(&err)),
        }
    }

    async fn get_by_request(
        &self,
        tenant_id: &str,
        agent_id: &str,
        request_id: &str,
    ) -> Result<Option<AgentDecisionRecord>, PortError> {
        let row = sqlx::query(
            "SELECT payload, hash, sig FROM agent_decisions \
             WHERE tenant_id = $1 AND agent_id = $2 AND mode = 'commit' AND request_id = $3 \
             ORDER BY created_at ASC, partition_id ASC, seq ASC LIMIT 1",
        )
        .bind(tenant_id)
        .bind(agent_id)
        .bind(request_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| unavailable(&e))?;
        row.as_ref().map(row_to_record).transpose()
    }

    async fn record(
        &self,
        tenant_id: &str,
        record_id: &str,
    ) -> Result<Option<AgentDecisionRecord>, PortError> {
        let row = sqlx::query(
            "SELECT payload, hash, sig FROM agent_decisions \
            WHERE tenant_id = $1 AND record_id = $2 AND kind = 'agent_decision' \
                AND mode = 'commit'",
        )
        .bind(tenant_id)
        .bind(record_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| unavailable(&e))?;
        row.as_ref().map(row_to_record).transpose()
    }

    async fn record_outcome(&self, outcome: OutcomeRecord) -> Result<(), PortError> {
        let hash: Option<String> = sqlx::query_scalar(
            "SELECT hash FROM agent_decisions WHERE tenant_id = $1 AND credential_id = $2",
        )
        .bind(&outcome.tenant_id)
        .bind(&outcome.credential_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| unavailable(&e))?;
        if hash.as_deref() != Some(outcome.record_hash.as_str()) {
            return Err(PortError::rejected("no allowed record for this credential"));
        }
        sqlx::query(
            "INSERT INTO agent_outcomes (tenant_id, credential_id, record_hash, outcome, \
                reason, ts, key_id, sig) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(&outcome.tenant_id)
        .bind(&outcome.credential_id)
        .bind(&outcome.record_hash)
        .bind(outcome.outcome.as_str())
        .bind(&outcome.reason)
        .bind(outcome.ts)
        .bind(&outcome.key_id)
        .bind(&outcome.sig)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            if is_unique_violation(&e) {
                PortError::rejected("outcome already recorded")
            } else {
                unavailable(&e)
            }
        })?;
        Ok(())
    }

    async fn record_resolution(&self, resolution: ResolutionRecord) -> Result<bool, PortError> {
        check_form(&resolution)?;
        let outcome = self
            .outcome(&resolution.tenant_id, &resolution.credential_id)
            .await?;
        check_against_outcome(&resolution, outcome.as_ref())?;
        let result = sqlx::query(
            "INSERT INTO agent_outcome_resolutions (tenant_id, credential_id, outcome_ref, \
                state, source, reason, evidence_digest, resolved_by, approved_by, ts, key_id, \
                sig) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
            ON CONFLICT (tenant_id, credential_id, source, state) DO NOTHING",
        )
        .bind(&resolution.tenant_id)
        .bind(&resolution.credential_id)
        .bind(&resolution.outcome_ref)
        .bind(resolution.state.as_str())
        .bind(resolution.source.as_str())
        .bind(&resolution.reason)
        .bind(&resolution.evidence_digest)
        .bind(&resolution.resolved_by)
        .bind(&resolution.approved_by)
        .bind(resolution.ts)
        .bind(&resolution.key_id)
        .bind(&resolution.sig)
        .execute(&self.pool)
        .await
        .map_err(|e| unavailable(&e))?;
        Ok(result.rows_affected() == 1)
    }

    async fn resolutions(
        &self,
        tenant_id: &str,
        credential_id: &str,
    ) -> Result<Vec<ResolutionRecord>, PortError> {
        let rows = sqlx::query(
            "SELECT outcome_ref, state, source, reason, evidence_digest, resolved_by, \
                approved_by, ts, key_id, sig FROM agent_outcome_resolutions \
            WHERE tenant_id = $1 AND credential_id = $2 ORDER BY ts, source, state",
        )
        .bind(tenant_id)
        .bind(credential_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| unavailable(&e))?;
        rows.iter()
            .map(|row| resolution_from_row(row, tenant_id, credential_id))
            .collect()
    }

    async fn outcome(
        &self,
        tenant_id: &str,
        credential_id: &str,
    ) -> Result<Option<OutcomeRecord>, PortError> {
        let row = sqlx::query(
            "SELECT record_hash, outcome, reason, ts, key_id, sig FROM agent_outcomes \
            WHERE tenant_id = $1 AND credential_id = $2",
        )
        .bind(tenant_id)
        .bind(credential_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| unavailable(&e))?;
        let Some(row) = row else { return Ok(None) };
        let outcome: String = row.try_get("outcome").map_err(|e| unavailable(&e))?;
        Ok(Some(OutcomeRecord {
            tenant_id: tenant_id.into(),
            credential_id: credential_id.into(),
            record_hash: row.try_get("record_hash").map_err(|e| unavailable(&e))?,
            // Never guess: an unrecognised value is a corrupt row.
            outcome: Outcome::parse(&outcome)
                .ok_or_else(|| PortError::invalid("stored outcome has an unknown value"))?,
            reason: row.try_get("reason").map_err(|e| unavailable(&e))?,
            ts: row.try_get("ts").map_err(|e| unavailable(&e))?,
            key_id: row.try_get("key_id").map_err(|e| unavailable(&e))?,
            sig: row.try_get("sig").map_err(|e| unavailable(&e))?,
        }))
    }

    async fn stuck_allows(
        &self,
        tenant_id: &str,
        decided_after: DateTime<Utc>,
        decided_before: DateTime<Utc>,
        limit: u32,
    ) -> Result<Vec<AgentDecisionRecord>, PortError> {
        // The record's own time is in its payload; an allow is PASS or ALERT
        // with a credential. Anti-join on the outcomes' primary key.
        let rows = sqlx::query(
            "SELECT d.payload, d.hash, d.sig FROM agent_decisions d \
            WHERE d.tenant_id = $1 AND d.credential_id IS NOT NULL \
              AND d.returned_decision IN ('PASS', 'ALERT') \
              AND (d.payload->>'ts')::timestamptz > $2 \
              AND (d.payload->>'ts')::timestamptz < $3 \
              AND NOT EXISTS ( \
                SELECT 1 FROM agent_outcomes o \
                WHERE o.tenant_id = d.tenant_id AND o.credential_id = d.credential_id) \
            ORDER BY d.seq LIMIT $4",
        )
        .bind(tenant_id)
        .bind(decided_after)
        .bind(decided_before)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(|e| unavailable(&e))?;
        rows.iter().map(row_to_record).collect()
    }

    async fn resolution_summary(&self, tenant_id: &str) -> Result<ResolutionSummary, PortError> {
        // More unknown outcomes than this is an incident of its own; the
        // summary says it stopped counting.
        const LIMIT: i64 = 100_000;
        let outcomes = sqlx::query(
            "SELECT credential_id, ts FROM agent_outcomes \
            WHERE tenant_id = $1 AND outcome = 'unknown' ORDER BY ts, credential_id LIMIT $2",
        )
        .bind(tenant_id)
        .bind(LIMIT + 1)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| unavailable(&e))?;
        let rows = sqlx::query(
            "SELECT credential_id, state, source FROM agent_outcome_resolutions \
            WHERE tenant_id = $1",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| unavailable(&e))?;
        let mut by_credential: BTreeMap<String, Vec<(ResolutionState, ResolutionSource)>> =
            BTreeMap::new();
        for row in &rows {
            let (credential, state, source): (String, String, String) = (
                row.try_get("credential_id").map_err(|e| unavailable(&e))?,
                row.try_get("state").map_err(|e| unavailable(&e))?,
                row.try_get("source").map_err(|e| unavailable(&e))?,
            );
            let (Some(state), Some(source)) = (
                ResolutionState::parse(&state),
                ResolutionSource::parse(&source),
            ) else {
                return Err(PortError::invalid(
                    "a stored resolution has an unknown value",
                ));
            };
            by_credential
                .entry(credential)
                .or_default()
                .push((state, source));
        }
        let truncated = i64::try_from(outcomes.len()).unwrap_or(i64::MAX) > LIMIT;
        let mut counted: OutcomeRows = Vec::new();
        for row in outcomes
            .iter()
            .take(usize::try_from(LIMIT).unwrap_or(usize::MAX))
        {
            let credential: String = row.try_get("credential_id").map_err(|e| unavailable(&e))?;
            let ts: DateTime<Utc> = row.try_get("ts").map_err(|e| unavailable(&e))?;
            counted.push((ts, by_credential.remove(&credential).unwrap_or_default()));
        }
        let mut summary = summarise(counted.iter().map(|(ts, rows)| (*ts, rows.as_slice())));
        summary.truncated = truncated;
        Ok(summary)
    }

    async fn unresolved_outcomes(
        &self,
        tenant_id: &str,
        limit: u32,
    ) -> Result<Vec<UnresolvedOutcome>, PortError> {
        // The same rule as `needs_reconciling`: no confirmed state, and no
        // `ambiguous` the reconciler wrote.
        let rows = sqlx::query(
            "SELECT o.credential_id, o.record_hash, o.reason, o.ts, o.key_id, o.sig, \
                d.payload->>'action' AS action \
            FROM agent_outcomes o \
            JOIN agent_decisions d \
                ON d.tenant_id = o.tenant_id AND d.credential_id = o.credential_id \
            WHERE o.tenant_id = $1 AND o.outcome = 'unknown' AND NOT EXISTS ( \
                SELECT 1 FROM agent_outcome_resolutions r \
                WHERE r.tenant_id = o.tenant_id AND r.credential_id = o.credential_id \
                AND (r.state IN ('confirmed_delivered', 'confirmed_not_delivered') \
                    OR (r.source = 'reconciler' AND r.state = 'ambiguous'))) \
            ORDER BY o.ts, o.credential_id LIMIT $2",
        )
        .bind(tenant_id)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(|e| unavailable(&e))?;
        rows.iter()
            .map(|row| {
                let credential_id: String =
                    row.try_get("credential_id").map_err(|e| unavailable(&e))?;
                Ok(UnresolvedOutcome {
                    outcome: OutcomeRecord {
                        tenant_id: tenant_id.into(),
                        credential_id,
                        record_hash: row.try_get("record_hash").map_err(|e| unavailable(&e))?,
                        outcome: Outcome::Unknown,
                        reason: row.try_get("reason").map_err(|e| unavailable(&e))?,
                        ts: row.try_get("ts").map_err(|e| unavailable(&e))?,
                        key_id: row.try_get("key_id").map_err(|e| unavailable(&e))?,
                        sig: row.try_get("sig").map_err(|e| unavailable(&e))?,
                    },
                    action: row.try_get("action").map_err(|e| unavailable(&e))?,
                })
            })
            .collect()
    }

    async fn unknown_outcome_reviews(
        &self,
        tenant_id: &str,
        after: Option<&str>,
        limit: u32,
    ) -> Result<Vec<UnknownOutcomeReview>, PortError> {
        let rows = sqlx::query(
            "SELECT o.credential_id, o.record_hash, o.reason, o.ts, o.key_id, o.sig, \
                d.payload->>'action' AS action \
            FROM agent_outcomes o \
            JOIN agent_decisions d \
                ON d.tenant_id = o.tenant_id AND d.credential_id = o.credential_id \
            WHERE o.tenant_id = $1 AND o.outcome = 'unknown' \
                AND ($2::text IS NULL OR o.credential_id > $2) \
            ORDER BY o.credential_id LIMIT $3",
        )
        .bind(tenant_id)
        .bind(after)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(|e| unavailable(&e))?;

        let mut outcomes = Vec::with_capacity(rows.len());
        let mut credentials = Vec::with_capacity(rows.len());
        for row in &rows {
            let credential_id: String =
                row.try_get("credential_id").map_err(|e| unavailable(&e))?;
            credentials.push(credential_id.clone());
            outcomes.push((
                OutcomeRecord {
                    tenant_id: tenant_id.into(),
                    credential_id,
                    record_hash: row.try_get("record_hash").map_err(|e| unavailable(&e))?,
                    outcome: Outcome::Unknown,
                    reason: row.try_get("reason").map_err(|e| unavailable(&e))?,
                    ts: row.try_get("ts").map_err(|e| unavailable(&e))?,
                    key_id: row.try_get("key_id").map_err(|e| unavailable(&e))?,
                    sig: row.try_get("sig").map_err(|e| unavailable(&e))?,
                },
                row.try_get::<String, _>("action")
                    .map_err(|e| unavailable(&e))?,
            ));
        }
        let mut by_credential: BTreeMap<String, Vec<ResolutionRecord>> = BTreeMap::new();
        if !credentials.is_empty() {
            let resolution_rows = sqlx::query(
                "SELECT credential_id, outcome_ref, state, source, reason, evidence_digest, \
                    resolved_by, approved_by, ts, key_id, sig \
                FROM agent_outcome_resolutions WHERE tenant_id = $1 \
                    AND credential_id = ANY($2) ORDER BY ts, source, state",
            )
            .bind(tenant_id)
            .bind(&credentials)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| unavailable(&e))?;
            for row in &resolution_rows {
                let credential: String =
                    row.try_get("credential_id").map_err(|e| unavailable(&e))?;
                by_credential
                    .entry(credential.clone())
                    .or_default()
                    .push(resolution_from_row(row, tenant_id, &credential)?);
            }
        }
        Ok(outcomes
            .into_iter()
            .map(|(outcome, action)| UnknownOutcomeReview {
                resolutions: by_credential
                    .remove(&outcome.credential_id)
                    .unwrap_or_default(),
                outcome,
                action,
            })
            .collect())
    }

    async fn records(
        &self,
        tenant_id: &str,
        partition_id: i32,
    ) -> Result<Vec<ChainRecord>, PortError> {
        let rows = sqlx::query(
            "SELECT payload, hash, sig FROM agent_decisions \
            WHERE tenant_id = $1 AND partition_id = $2 ORDER BY seq",
        )
        .bind(tenant_id)
        .bind(partition_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| unavailable(&e))?;
        rows.iter().map(row_to_chain_record).collect()
    }

    async fn append_revocation(
        &self,
        draft: RevocationDraft,
        clock: &dyn TimeSource,
        signer: &dyn EvidenceSigner,
    ) -> Result<RevocationRecord, PortError> {
        if let Some(stored) = find_revocation(
            &self.pool,
            &draft.tenant_id,
            &draft.source_system,
            &draft.event_id,
        )
        .await?
        {
            return same_revocation(stored, &draft);
        }
        match self.append_revocation_once(&draft, clock, signer).await {
            Ok(record) => Ok(record),
            // Another writer (the API or the reconciler) recorded this event
            // first; its record decides.
            Err(err) if is_unique_violation(&err) => {
                let stored = find_revocation(
                    &self.pool,
                    &draft.tenant_id,
                    &draft.source_system,
                    &draft.event_id,
                )
                .await?
                .ok_or_else(|| unavailable(&err))?;
                same_revocation(stored, &draft)
            }
            Err(sqlx::Error::Protocol(message)) => Err(PortError::unavailable(message)),
            Err(err) => Err(unavailable(&err)),
        }
    }

    async fn revocation_record(
        &self,
        tenant_id: &str,
        source_system: &str,
        event_id: &str,
    ) -> Result<Option<RevocationRecord>, PortError> {
        find_revocation(&self.pool, tenant_id, source_system, event_id).await
    }

    async fn append_agent_state(
        &self,
        draft: AgentStateDraft,
        clock: &dyn TimeSource,
        signer: &dyn EvidenceSigner,
    ) -> Result<AgentStateRecord, PortError> {
        if let Some(stored) = find_state_record(
            &self.pool,
            &draft.tenant_id,
            &draft.agent_id,
            draft.change_no,
        )
        .await?
        {
            return same_state_record(stored, &draft);
        }
        match self.append_state_record_once(&draft, clock, signer).await {
            Ok(record) => Ok(record),
            // Another writer (the operator path or the reconciler) recorded
            // this change first; its record decides.
            Err(err) if err.message == STATE_RECORD_EXISTS => {
                let stored = find_state_record(
                    &self.pool,
                    &draft.tenant_id,
                    &draft.agent_id,
                    draft.change_no,
                )
                .await?
                .ok_or(err)?;
                same_state_record(stored, &draft)
            }
            Err(err) => Err(err),
        }
    }

    async fn agent_state_record(
        &self,
        tenant_id: &str,
        agent_id: &str,
        change_no: i64,
    ) -> Result<Option<AgentStateRecord>, PortError> {
        find_state_record(&self.pool, tenant_id, agent_id, change_no).await
    }

    async fn contacts_on(
        &self,
        tenant_id: &str,
        subject_pseudonym: &str,
        ist_date: NaiveDate,
    ) -> Result<u32, PortError> {
        let count: Option<i32> = sqlx::query_scalar(
            "SELECT count FROM contact_counters \
            WHERE tenant_id = $1 AND subject_pseudonym = $2 AND ist_date = $3",
        )
        .bind(tenant_id)
        .bind(subject_pseudonym)
        .bind(ist_date)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| unavailable(&e))?;
        Ok(count.map_or(0, |c| u32::try_from(c).unwrap_or(0)))
    }
}

fn row_to_checkpoint(row: &sqlx::postgres::PgRow) -> Result<Checkpoint, PortError> {
    let payload: serde_json::Value = row.try_get("payload").map_err(|e| unavailable(&e))?;
    Ok(Checkpoint {
        payload: serde_json::from_value(payload)
            .map_err(|e| PortError::invalid(format!("stored checkpoint: {e}")))?,
        hash: row.try_get("hash").map_err(|e| unavailable(&e))?,
        sig: row.try_get("sig").map_err(|e| unavailable(&e))?,
    })
}

/// Checkpoints of the agent chain (ADR-005 §13). No lock is taken: the
/// table's unique keys (one checkpoint per `seq`, one successor per
/// checkpoint) keep the stored checkpoints in one line when several
/// writers run.
impl CheckpointStore for PostgresAgentEvidenceStore {
    async fn head(&self, scope: Scope<'_>) -> Result<Option<(i64, String)>, PortError> {
        if scope.chain != CHAIN_AGENT_DECISIONS {
            return Ok(None);
        }
        let row = sqlx::query(
            "SELECT head_seq, head_hash FROM agent_evidence_chains \
            WHERE tenant_id = $1 AND partition_id = $2 AND head_seq > 0",
        )
        .bind(scope.tenant_id)
        .bind(scope.partition_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| unavailable(&e))?;
        let Some(row) = row else { return Ok(None) };
        Ok(Some((
            row.try_get("head_seq").map_err(|e| unavailable(&e))?,
            row.try_get("head_hash").map_err(|e| unavailable(&e))?,
        )))
    }

    async fn latest(&self, scope: Scope<'_>) -> Result<Option<Checkpoint>, PortError> {
        let row = sqlx::query(
            "SELECT payload, hash, sig FROM evidence_checkpoints \
            WHERE tenant_id = $1 AND partition_id = $2 AND chain = $3 \
            ORDER BY seq DESC LIMIT 1",
        )
        .bind(scope.tenant_id)
        .bind(scope.partition_id)
        .bind(scope.chain)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| unavailable(&e))?;
        row.as_ref().map(row_to_checkpoint).transpose()
    }

    async fn append(&self, checkpoint: &Checkpoint) -> Result<Appended, PortError> {
        check_storable(checkpoint)?;
        let p = &checkpoint.payload;
        let record_hash: Option<String> = sqlx::query_scalar(
            "SELECT hash FROM agent_decisions \
            WHERE tenant_id = $1 AND partition_id = $2 AND seq = $3",
        )
        .bind(&p.tenant_id)
        .bind(p.partition_id)
        .bind(p.seq)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| unavailable(&e))?;
        if record_hash.as_deref() != Some(p.head_hash.as_str()) {
            return Err(PortError::rejected(
                "no record with this seq and hash to checkpoint",
            ));
        }
        let scope = Scope {
            tenant_id: &p.tenant_id,
            partition_id: p.partition_id,
            chain: &p.chain,
        };
        let latest = self.latest(scope).await?;
        if check_follows(checkpoint, latest.as_ref())? == Appended::Superseded {
            return Ok(Appended::Superseded);
        }
        // A writer that raced past the check above loses on a unique key.
        let inserted = sqlx::query(
            "INSERT INTO evidence_checkpoints (tenant_id, partition_id, chain, seq, head_hash, \
                prev_checkpoint_hash, key_id, ts, hash, sig, payload) \
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(&p.tenant_id)
        .bind(p.partition_id)
        .bind(&p.chain)
        .bind(p.seq)
        .bind(&p.head_hash)
        .bind(&p.prev_checkpoint_hash)
        .bind(&p.key_id)
        .bind(p.ts)
        .bind(&checkpoint.hash)
        .bind(&checkpoint.sig)
        .bind(json(p)?)
        .execute(&self.pool)
        .await;
        match inserted {
            Ok(_) => Ok(Appended::Written),
            Err(e) if is_unique_violation(&e) => Ok(Appended::Superseded),
            Err(e) => Err(unavailable(&e)),
        }
    }

    async fn list(
        &self,
        scope: Scope<'_>,
        after_seq: i64,
        limit: u32,
    ) -> Result<Vec<Checkpoint>, PortError> {
        let rows = sqlx::query(
            "SELECT payload, hash, sig FROM evidence_checkpoints \
            WHERE tenant_id = $1 AND partition_id = $2 AND chain = $3 AND seq > $4 \
            ORDER BY seq LIMIT $5",
        )
        .bind(scope.tenant_id)
        .bind(scope.partition_id)
        .bind(scope.chain)
        .bind(after_seq)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(|e| unavailable(&e))?;
        rows.iter().map(row_to_checkpoint).collect()
    }
}

/// The insert lost a race: another writer recorded this change first.
const STATE_RECORD_EXISTS: &str = "this change of the agent's state is already recorded";

fn parse_state(name: &str) -> Result<AgentState, PortError> {
    // A state this build does not know is an error, never "active".
    AgentState::parse(name)
        .ok_or_else(|| PortError::invalid(format!("stored agent state {name:?}")))
}

fn parse_reason(code: &str) -> Result<ReasonCode, PortError> {
    ReasonCode::parse(code)
        .ok_or_else(|| PortError::invalid(format!("stored reason code {code:?}")))
}

fn state_row(row: &sqlx::postgres::PgRow) -> Result<StoredAgentState, PortError> {
    let get = |name: &str| -> Result<String, PortError> {
        row.try_get(name).map_err(|e| unavailable(&e))
    };
    Ok(StoredAgentState {
        tenant_id: get("tenant_id")?,
        agent_id: get("agent_id")?,
        state: parse_state(&get("state")?)?,
        change_no: row.try_get("change_no").map_err(|e| unavailable(&e))?,
        reason_code: parse_reason(&get("reason_code")?)?,
        note: get("reason")?,
        changed_by: get("changed_by")?,
        approved_by: row.try_get("approved_by").map_err(|e| unavailable(&e))?,
        change_request_id: row
            .try_get("change_request_id")
            .map_err(|e| unavailable(&e))?,
        changed_at: row.try_get("changed_at").map_err(|e| unavailable(&e))?,
    })
}

fn change_row(row: &sqlx::postgres::PgRow) -> Result<StoredAgentChange, PortError> {
    let get = |name: &str| -> Result<String, PortError> {
        row.try_get(name).map_err(|e| unavailable(&e))
    };
    Ok(StoredAgentChange {
        tenant_id: get("tenant_id")?,
        agent_id: get("agent_id")?,
        change_no: row.try_get("change_no").map_err(|e| unavailable(&e))?,
        from_state: parse_state(&get("from_state")?)?,
        to_state: parse_state(&get("to_state")?)?,
        reason_code: parse_reason(&get("reason_code")?)?,
        note: get("note")?,
        changed_by: get("changed_by")?,
        approved_by: row.try_get("approved_by").map_err(|e| unavailable(&e))?,
        change_request_id: row
            .try_get("change_request_id")
            .map_err(|e| unavailable(&e))?,
        changed_at: row.try_get("changed_at").map_err(|e| unavailable(&e))?,
    })
}

const STATE_COLUMNS: &str = "tenant_id, agent_id, state, change_no, reason_code, reason, \
     changed_by, approved_by, change_request_id, changed_at";
const CHANGE_COLUMNS: &str = "tenant_id, agent_id, change_no, from_state, to_state, reason_code, \
     note, changed_by, approved_by, change_request_id, changed_at";

impl PostgresAgentEvidenceStore {
    /// Takes the agent's lock, checks `change` against the stored state and
    /// writes the new state and the history entry, in `tx`. One change at a
    /// time per agent, whether or not it has a row yet.
    ///
    /// **Lock order:** this agent lock, then (for a recorded change) the
    /// partition head. Nothing takes them the other way round.
    async fn change_in(
        tx: &mut Transaction<'_, Postgres>,
        change: &AgentStateChange,
    ) -> Result<(StoredAgentState, StoredAgentChange), PortError> {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(format!(
                "agent_state:{}:{}",
                change.tenant_id, change.agent_id
            ))
            .execute(&mut **tx)
            .await
            .map_err(|e| unavailable(&e))?;
        let current = sqlx::query(&format!(
            "SELECT {STATE_COLUMNS} FROM agent_states WHERE tenant_id = $1 AND agent_id = $2"
        ))
        .bind(&change.tenant_id)
        .bind(&change.agent_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|e| unavailable(&e))?
        .as_ref()
        .map(state_row)
        .transpose()?;
        let (from, last_no) = current
            .as_ref()
            .map_or((AgentState::Active, 0), |row| (row.state, row.change_no));
        change.check(from)?;
        let change_no = last_no + 1;
        let history = sqlx::query(&format!(
            "INSERT INTO agent_state_changes ({CHANGE_COLUMNS}) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING {CHANGE_COLUMNS}"
        ))
        .bind(&change.tenant_id)
        .bind(&change.agent_id)
        .bind(change_no)
        .bind(from.as_str())
        .bind(change.to.as_str())
        .bind(change.reason_code.as_str())
        .bind(&change.note)
        .bind(&change.changed_by)
        .bind(&change.approved_by)
        .bind(&change.change_request_id)
        .bind(change.at)
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| unavailable(&e))?;
        let row = sqlx::query(&format!(
            "INSERT INTO agent_states ({STATE_COLUMNS}) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
             ON CONFLICT (tenant_id, agent_id) DO UPDATE SET state = EXCLUDED.state, \
             change_no = EXCLUDED.change_no, reason_code = EXCLUDED.reason_code, \
             reason = EXCLUDED.reason, changed_by = EXCLUDED.changed_by, \
             approved_by = EXCLUDED.approved_by, \
             change_request_id = EXCLUDED.change_request_id, \
             changed_at = EXCLUDED.changed_at \
             RETURNING {STATE_COLUMNS}"
        ))
        .bind(&change.tenant_id)
        .bind(&change.agent_id)
        .bind(change.to.as_str())
        .bind(change_no)
        .bind(change.reason_code.as_str())
        .bind(&change.note)
        .bind(&change.changed_by)
        .bind(&change.approved_by)
        .bind(&change.change_request_id)
        .bind(change.at)
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| unavailable(&e))?;
        Ok((state_row(&row)?, change_row(&history)?))
    }

    /// Writes `record` at the head of its partition, which `tx` holds locked,
    /// and advances the head.
    async fn insert_state_record(
        tx: &mut Transaction<'_, Postgres>,
        record: &AgentStateRecord,
    ) -> Result<(), PortError> {
        let p = &record.payload;
        let advanced = sqlx::query(
            "WITH inserted AS ( \
                INSERT INTO agent_decisions (tenant_id, partition_id, seq, record_id, \
                    prev_hash, hash, sig, key_id, payload, kind, agent_id, state_change_no) \
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'agent_state', $10, $11) \
                RETURNING tenant_id, partition_id, seq, hash) \
            UPDATE agent_evidence_chains AS c SET head_seq = inserted.seq, \
                head_hash = inserted.hash \
            FROM inserted \
            WHERE c.tenant_id = inserted.tenant_id AND c.partition_id = inserted.partition_id",
        )
        .bind(&p.tenant_id)
        .bind(p.partition_id)
        .bind(p.seq)
        .bind(&p.record_id)
        .bind(&p.prev_hash)
        .bind(&record.hash)
        .bind(&record.sig)
        .bind(&p.key_id)
        .bind(json(p)?)
        .bind(&p.agent_id)
        .bind(p.change_no)
        .execute(&mut **tx)
        .await
        .map_err(|e| {
            if is_unique_violation(&e) {
                PortError::rejected(STATE_RECORD_EXISTS)
            } else {
                unavailable(&e)
            }
        })?;
        if advanced.rows_affected() == 1 {
            Ok(())
        } else {
            Err(PortError::unavailable("the partition head did not advance"))
        }
    }

    async fn append_state_record_once(
        &self,
        draft: &AgentStateDraft,
        clock: &dyn TimeSource,
        signer: &dyn EvidenceSigner,
    ) -> Result<AgentStateRecord, PortError> {
        let mut tx = self.pool.begin().await.map_err(|e| unavailable(&e))?;
        let (head_seq, head_hash) =
            Self::lock_head(&mut tx, &draft.tenant_id, draft.partition_id).await?;
        let payload = draft.complete(head_seq + 1, &head_hash, signer.key_id(), clock.now());
        let record = seal_agent_state(payload, signer)?;
        Self::insert_state_record(&mut tx, &record).await?;
        tx.commit().await.map_err(|e| unavailable(&e))?;
        Ok(record)
    }
}

impl AgentStateStore for PostgresAgentEvidenceStore {
    async fn states(
        &self,
        tenant_id: &str,
        agent_ids: &[String],
    ) -> Result<std::collections::BTreeMap<String, AgentState>, PortError> {
        let rows = sqlx::query(&format!(
            "SELECT {STATE_COLUMNS} FROM agent_states \
             WHERE tenant_id = $1 AND agent_id = ANY($2)"
        ))
        .bind(tenant_id)
        .bind(agent_ids)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| unavailable(&e))?;
        let mut out: std::collections::BTreeMap<String, AgentState> = agent_ids
            .iter()
            .map(|id| (id.clone(), AgentState::Active))
            .collect();
        for row in &rows {
            let stored = state_row(row)?;
            out.insert(stored.agent_id, stored.state);
        }
        Ok(out)
    }

    async fn current(
        &self,
        tenant_id: &str,
        agent_id: &str,
    ) -> Result<Option<StoredAgentState>, PortError> {
        let row = sqlx::query(&format!(
            "SELECT {STATE_COLUMNS} FROM agent_states WHERE tenant_id = $1 AND agent_id = $2"
        ))
        .bind(tenant_id)
        .bind(agent_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| unavailable(&e))?;
        row.as_ref().map(state_row).transpose()
    }

    async fn set(&self, change: AgentStateChange) -> Result<StoredAgentState, PortError> {
        let mut tx = self.pool.begin().await.map_err(|e| unavailable(&e))?;
        let (state, _) = Self::change_in(&mut tx, &change).await?;
        tx.commit().await.map_err(|e| unavailable(&e))?;
        Ok(state)
    }

    async fn set_recorded(
        &self,
        change: AgentStateChange,
        recording: Recording<'_>,
    ) -> Result<(StoredAgentState, AgentStateRecord), PortError> {
        let mut tx = self.pool.begin().await.map_err(|e| unavailable(&e))?;
        let (state, history) = Self::change_in(&mut tx, &change).await?;
        let (head_seq, head_hash) =
            Self::lock_head(&mut tx, &history.tenant_id, recording.partition_id).await?;
        let draft = AgentStateDraft {
            tenant_id: history.tenant_id.clone(),
            partition_id: recording.partition_id,
            agent_id: history.agent_id.clone(),
            change_no: history.change_no,
            from_state: history.from_state,
            to_state: history.to_state,
            reason_code: history.reason_code,
            reason_digest: if history.note.is_empty() {
                None
            } else {
                (recording.reason_digest)(history.change_no)
            },
            changed_by: history.changed_by.clone(),
            approved_by: history.approved_by.clone(),
            change_request_id: history.change_request_id.clone(),
            changed_at: history.changed_at,
        };
        let payload = draft.complete(
            head_seq + 1,
            &head_hash,
            recording.signer.key_id(),
            recording.clock.now(),
        );
        let record = seal_agent_state(payload, recording.signer)?;
        Self::insert_state_record(&mut tx, &record).await?;
        // Both or neither: a failure above drops `tx`, which rolls back.
        tx.commit().await.map_err(|e| unavailable(&e))?;
        Ok((state, record))
    }

    async fn changes_after(
        &self,
        after: Option<AgentChangeCursor>,
        limit: u32,
    ) -> Result<Vec<StoredAgentChange>, PortError> {
        let limit = i64::from(limit);
        let rows = match after {
            Some(c) => {
                sqlx::query(&format!(
                    "SELECT {CHANGE_COLUMNS} FROM agent_state_changes \
                 WHERE (changed_at, tenant_id, agent_id, change_no) > ($1, $2, $3, $4) \
                 ORDER BY changed_at, tenant_id, agent_id, change_no LIMIT $5"
                ))
                .bind(c.changed_at)
                .bind(c.tenant_id)
                .bind(c.agent_id)
                .bind(c.change_no)
                .bind(limit)
                .fetch_all(&self.pool)
                .await
            }
            None => {
                sqlx::query(&format!(
                    "SELECT {CHANGE_COLUMNS} FROM agent_state_changes \
                 ORDER BY changed_at, tenant_id, agent_id, change_no LIMIT $1"
                ))
                .bind(limit)
                .fetch_all(&self.pool)
                .await
            }
        }
        .map_err(|e| unavailable(&e))?;
        rows.iter().map(change_row).collect()
    }
}

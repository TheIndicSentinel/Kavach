//! Postgres `AgentEvidenceStore` (H5a-3b, ADR-005 §6 phase 1).
//!
//! `commit` is one transaction. **Lock order: the partition head row first,
//! then the contact counter row** — any future resource must come after
//! these, or concurrent commits can deadlock.

use chrono::NaiveDate;
use kavach_domain::Decision;
use kavach_ports::agent_evidence::{
    complete_payload, finalise, is_allow, seal, AgentDecisionRecord, AgentEvidenceStore,
    CommitRequest, CommitResult, EvidenceSigner, Outcome, OutcomeRecord, RequestBinding, GENESIS,
};
use kavach_ports::chain_record::{seal_revocation, ChainRecord, RevocationDraft, RevocationRecord};
use kavach_ports::checkpoint::{
    check_follows, check_storable, Appended, Checkpoint, CheckpointStore, Scope,
    CHAIN_AGENT_DECISIONS,
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
        ChainRecord::Decision(_) => Err(PortError::invalid(
            "a revocation row holds a decision payload",
        )),
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
    request_id: &str,
) -> Result<Option<Existing>, PortError> {
    let row = sqlx::query(
        "SELECT payload, hash, sig, binding FROM agent_decisions \
        WHERE tenant_id = $1 AND agent_id = $2 AND mode = 'commit' AND request_id = $3",
    )
    .bind(tenant_id)
    .bind(agent_id)
    .bind(request_id)
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
        // by the unique key on (tenant, agent, mode, request_id), which
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
                    prev_hash, hash, sig, key_id, payload, agent_id, request_id, binding, \
                    credential_id, returned_decision) \
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) \
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

impl AgentEvidenceStore for PostgresAgentEvidenceStore {
    async fn commit(
        &self,
        request: CommitRequest,
        clock: &dyn TimeSource,
        signer: &dyn EvidenceSigner,
    ) -> Result<CommitResult, PortError> {
        // Retries are answered without queueing on the partition lock.
        let agent = request.draft.actor.agent_id.clone();
        if let Some((record, binding)) = find(
            &self.pool,
            &request.tenant_id,
            &agent,
            &request.draft.request_id,
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
                    &request.draft.request_id,
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
        Ok(find(&self.pool, tenant_id, agent_id, request_id)
            .await?
            .map(|(record, _)| record))
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

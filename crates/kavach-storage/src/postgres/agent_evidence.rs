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

    async fn lock_head(
        tx: &mut Transaction<'_, Postgres>,
        tenant_id: &str,
        partition_id: i32,
    ) -> Result<(i64, String), PortError> {
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
        let row = sqlx::query(
            "SELECT head_seq, head_hash FROM agent_evidence_chains \
            WHERE tenant_id = $1 AND partition_id = $2 FOR UPDATE",
        )
        .bind(tenant_id)
        .bind(partition_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| unavailable(&e))?;
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
        let agent = &request.draft.actor.agent_id;
        if let Some((record, binding)) = find(
            &mut *tx,
            &request.tenant_id,
            agent,
            &request.draft.request_id,
        )
        .await
        .map_err(|e| sqlx::Error::Protocol(e.message))?
        {
            return Ok(classify(record, &binding, &request.binding));
        }

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
        sqlx::query(
            "INSERT INTO agent_decisions (tenant_id, partition_id, seq, record_id, prev_hash, \
                hash, sig, key_id, payload, agent_id, request_id, binding, credential_id, \
                returned_decision) \
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
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
        sqlx::query(
            "UPDATE agent_evidence_chains SET head_seq = $3, head_hash = $4 \
            WHERE tenant_id = $1 AND partition_id = $2",
        )
        .bind(&p.tenant_id)
        .bind(p.partition_id)
        .bind(p.seq)
        .bind(&record.hash)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(CommitResult::Committed(Box::new(record)))
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
            // A concurrent commit of the same request won (another
            // partition); the unique constraint decided.
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
            "INSERT INTO agent_outcomes (tenant_id, credential_id, record_hash, outcome, ts, \
                key_id, sig) VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(&outcome.tenant_id)
        .bind(&outcome.credential_id)
        .bind(&outcome.record_hash)
        .bind(outcome.outcome.as_str())
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
            "SELECT record_hash, outcome, ts, key_id, sig FROM agent_outcomes \
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
            outcome: match outcome.as_str() {
                "delivered" => Outcome::Delivered,
                "failed" => Outcome::Failed,
                _ => Outcome::Refused,
            },
            ts: row.try_get("ts").map_err(|e| unavailable(&e))?,
            key_id: row.try_get("key_id").map_err(|e| unavailable(&e))?,
            sig: row.try_get("sig").map_err(|e| unavailable(&e))?,
        }))
    }

    async fn records(
        &self,
        tenant_id: &str,
        partition_id: i32,
    ) -> Result<Vec<AgentDecisionRecord>, PortError> {
        let rows = sqlx::query(
            "SELECT payload, hash, sig FROM agent_decisions \
            WHERE tenant_id = $1 AND partition_id = $2 ORDER BY seq",
        )
        .bind(tenant_id)
        .bind(partition_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| unavailable(&e))?;
        rows.iter().map(row_to_record).collect()
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

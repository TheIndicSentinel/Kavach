//! A read-only snapshot of one agent chain, for evidence export
//! (ADR-005 §13).
//!
//! Everything is read inside one `REPEATABLE READ, READ ONLY` transaction,
//! so records, outcomes and checkpoints agree with each other however long
//! the export takes and whatever is written meanwhile. Reads are paged by
//! key, so a large chain is never held in memory.
//!
//! The intended role is `kavach_auditor` (migration 013), which can read
//! the agent evidence tables and nothing else. [`EvidenceSnapshot::can_write`]
//! tells the caller when it was given a more powerful role.

use kavach_ports::agent_evidence::{Outcome, OutcomeRecord};
use kavach_ports::chain_record::ChainRecord;
use kavach_ports::checkpoint::{Checkpoint, CHAIN_AGENT_DECISIONS};
use kavach_ports::PortError;
use sqlx::postgres::{PgPoolOptions, PgRow};

use super::tls::{connect_options, DatabaseTls};
use sqlx::{Postgres, Row, Transaction};

fn unavailable(err: &sqlx::Error) -> PortError {
    PortError::unavailable(format!("evidence export: {err}"))
}

fn checkpoint(row: &PgRow) -> Result<Checkpoint, PortError> {
    let payload: serde_json::Value = row.try_get("payload").map_err(|e| unavailable(&e))?;
    Ok(Checkpoint {
        payload: serde_json::from_value(payload)
            .map_err(|e| PortError::invalid(format!("stored checkpoint: {e}")))?,
        hash: row.try_get("hash").map_err(|e| unavailable(&e))?,
        sig: row.try_get("sig").map_err(|e| unavailable(&e))?,
    })
}

pub struct EvidenceSnapshot {
    tx: Transaction<'static, Postgres>,
    tenant_id: String,
    partition_id: i32,
    can_write: bool,
}

impl EvidenceSnapshot {
    /// Connects (without migrating) and fixes the snapshot. Nothing read
    /// through it reflects a write made after this returns.
    pub async fn open(
        database_url: &str,
        tls: &DatabaseTls,
        tenant_id: &str,
        partition_id: i32,
    ) -> Result<Self, PortError> {
        let options = connect_options(database_url, tls)
            .map_err(|e| PortError::invalid(format!("evidence export: {e}")))?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .map_err(|e| unavailable(&e))?;
        let mut tx = pool.begin().await.map_err(|e| unavailable(&e))?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *tx)
            .await
            .map_err(|e| unavailable(&e))?;
        // The first query takes the snapshot.
        let can_write: bool = sqlx::query_scalar(
            "SELECT has_table_privilege(current_user, 'agent_decisions', 'INSERT, UPDATE, DELETE') \
                OR has_table_privilege(current_user, 'agent_outcomes', 'INSERT, UPDATE, DELETE') \
                OR has_table_privilege(current_user, 'evidence_checkpoints', \
                    'INSERT, UPDATE, DELETE')",
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| unavailable(&e))?;
        Ok(Self {
            tx,
            tenant_id: tenant_id.into(),
            partition_id,
            can_write,
        })
    }

    /// Whether the connected role could change the evidence it reads: true
    /// for anything but a read-only role such as `kavach_auditor`.
    #[must_use]
    pub fn can_write(&self) -> bool {
        self.can_write
    }

    /// The newest record (`seq`, hash); `None` while the chain has none.
    pub async fn head(&mut self) -> Result<Option<(i64, String)>, PortError> {
        let row = sqlx::query(
            "SELECT head_seq, head_hash FROM agent_evidence_chains \
            WHERE tenant_id = $1 AND partition_id = $2 AND head_seq > 0",
        )
        .bind(&self.tenant_id)
        .bind(self.partition_id)
        .fetch_optional(&mut *self.tx)
        .await
        .map_err(|e| unavailable(&e))?;
        let Some(row) = row else { return Ok(None) };
        Ok(Some((
            row.try_get("head_seq").map_err(|e| unavailable(&e))?,
            row.try_get("head_hash").map_err(|e| unavailable(&e))?,
        )))
    }

    /// Records of every kind with `seq > after_seq`, in `seq` order, at most
    /// `limit`. A kind this build does not know is an error.
    pub async fn records(
        &mut self,
        after_seq: i64,
        limit: u32,
    ) -> Result<Vec<ChainRecord>, PortError> {
        let rows = sqlx::query(
            "SELECT payload, hash, sig FROM agent_decisions \
            WHERE tenant_id = $1 AND partition_id = $2 AND seq > $3 ORDER BY seq LIMIT $4",
        )
        .bind(&self.tenant_id)
        .bind(self.partition_id)
        .bind(after_seq)
        .bind(i64::from(limit))
        .fetch_all(&mut *self.tx)
        .await
        .map_err(|e| unavailable(&e))?;
        rows.iter()
            .map(super::agent_evidence::row_to_chain_record)
            .collect()
    }

    /// Outcomes of the records with `after_seq < seq <= through_seq`, each
    /// with its record's `seq`, in that order, at most `limit`.
    pub async fn outcomes(
        &mut self,
        after_seq: i64,
        through_seq: i64,
        limit: u32,
    ) -> Result<Vec<(i64, OutcomeRecord)>, PortError> {
        let rows = sqlx::query(
            "SELECT d.seq, o.credential_id, o.record_hash, o.outcome, o.reason, o.ts, \
                o.key_id, o.sig \
            FROM agent_outcomes o \
            JOIN agent_decisions d \
                ON d.tenant_id = o.tenant_id AND d.credential_id = o.credential_id \
            WHERE o.tenant_id = $1 AND d.partition_id = $2 AND d.seq > $3 AND d.seq <= $4 \
            ORDER BY d.seq LIMIT $5",
        )
        .bind(&self.tenant_id)
        .bind(self.partition_id)
        .bind(after_seq)
        .bind(through_seq)
        .bind(i64::from(limit))
        .fetch_all(&mut *self.tx)
        .await
        .map_err(|e| unavailable(&e))?;
        rows.iter()
            .map(|row| {
                let outcome: String = row.try_get("outcome").map_err(|e| unavailable(&e))?;
                let record = OutcomeRecord {
                    tenant_id: self.tenant_id.clone(),
                    credential_id: row.try_get("credential_id").map_err(|e| unavailable(&e))?,
                    record_hash: row.try_get("record_hash").map_err(|e| unavailable(&e))?,
                    // Never guess: an unrecognised value is a corrupt row.
                    outcome: Outcome::parse(&outcome)
                        .ok_or_else(|| PortError::invalid("stored outcome has an unknown value"))?,
                    reason: row.try_get("reason").map_err(|e| unavailable(&e))?,
                    ts: row.try_get("ts").map_err(|e| unavailable(&e))?,
                    key_id: row.try_get("key_id").map_err(|e| unavailable(&e))?,
                    sig: row.try_get("sig").map_err(|e| unavailable(&e))?,
                };
                Ok((row.try_get("seq").map_err(|e| unavailable(&e))?, record))
            })
            .collect()
    }

    /// Checkpoints with `seq > after_seq`, in `seq` order, at most `limit`.
    pub async fn checkpoints(
        &mut self,
        after_seq: i64,
        limit: u32,
    ) -> Result<Vec<Checkpoint>, PortError> {
        let rows = sqlx::query(
            "SELECT payload, hash, sig FROM evidence_checkpoints \
            WHERE tenant_id = $1 AND partition_id = $2 AND chain = $3 AND seq > $4 \
            ORDER BY seq LIMIT $5",
        )
        .bind(&self.tenant_id)
        .bind(self.partition_id)
        .bind(CHAIN_AGENT_DECISIONS)
        .bind(after_seq)
        .bind(i64::from(limit))
        .fetch_all(&mut *self.tx)
        .await
        .map_err(|e| unavailable(&e))?;
        rows.iter().map(checkpoint).collect()
    }

    /// The newest checkpoint.
    pub async fn latest_checkpoint(&mut self) -> Result<Option<Checkpoint>, PortError> {
        let row = sqlx::query(
            "SELECT payload, hash, sig FROM evidence_checkpoints \
            WHERE tenant_id = $1 AND partition_id = $2 AND chain = $3 \
            ORDER BY seq DESC LIMIT 1",
        )
        .bind(&self.tenant_id)
        .bind(self.partition_id)
        .bind(CHAIN_AGENT_DECISIONS)
        .fetch_optional(&mut *self.tx)
        .await
        .map_err(|e| unavailable(&e))?;
        row.as_ref().map(checkpoint).transpose()
    }
}

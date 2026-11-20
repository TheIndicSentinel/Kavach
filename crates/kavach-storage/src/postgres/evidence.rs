use kavach_domain::{Decision, DecisionEvent, GovernanceMode, ModelOrigin, SCHEMA_VERSION};
use kavach_evaluate::EvidenceStore;
use kavach_evidence::{
    at_storage_precision, compute_event_hash, verify_event_hash, AppendDecisionEvent, EvidenceError,
};
use kavach_ports::checkpoint::{
    check_follows, check_storable, Appended, Checkpoint, CheckpointStore, Scope,
    CHAIN_DECISION_EVENTS,
};
use kavach_ports::PortError;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

#[derive(Clone)]
pub struct PostgresEvidenceStore {
    pool: PgPool,
    tenant_id: String,
}

impl PostgresEvidenceStore {
    pub fn new(pool: PgPool) -> Self {
        Self::new_for_tenant(pool, "default")
    }

    pub fn new_for_tenant(pool: PgPool, tenant_id: &str) -> Self {
        Self {
            pool,
            tenant_id: tenant_id.into(),
        }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

/// One repeatable-read, read-only view of a single decision-event partition.
/// The export CLI pages through this snapshot so writes that happen during an
/// export cannot produce a mixed chain.
pub struct DecisionEventSnapshot {
    tx: Transaction<'static, Postgres>,
    tenant_id: String,
    partition_id: i32,
    can_write: bool,
}

impl DecisionEventSnapshot {
    pub async fn open(
        database_url: &str,
        tls: &super::DatabaseTls,
        tenant_id: &str,
        partition_id: i32,
    ) -> Result<Self, EvidenceError> {
        if tenant_id.is_empty() || partition_id < 0 {
            return Err(EvidenceError::Domain(kavach_domain::DomainError::Golden(
                "decision-event export requires a tenant and non-negative partition".into(),
            )));
        }
        let options = super::tls::connect_options(database_url, tls).map_err(|err| {
            EvidenceError::Domain(kavach_domain::DomainError::Golden(format!(
                "postgres TLS: {err}"
            )))
        })?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .map_err(|err| io_err(&err))?;
        let mut tx = pool.begin().await.map_err(|err| io_err(&err))?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *tx)
            .await
            .map_err(|err| io_err(&err))?;
        let can_write: bool = sqlx::query_scalar(
            "SELECT has_table_privilege(current_user, 'decision_events', 'INSERT, UPDATE, DELETE') \
             OR has_table_privilege(current_user, 'evidence_chains', 'INSERT, UPDATE, DELETE')",
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|err| io_err(&err))?;
        Ok(Self {
            tx,
            tenant_id: tenant_id.into(),
            partition_id,
            can_write,
        })
    }

    #[must_use]
    pub const fn can_write(&self) -> bool {
        self.can_write
    }

    /// The current partition head; `None` means this partition is empty.
    pub async fn head(&mut self) -> Result<Option<(i64, String)>, EvidenceError> {
        let row = sqlx::query(
            "SELECT head_seq, head_hash FROM evidence_chains \
             WHERE tenant_id = $1 AND partition_id = $2",
        )
        .bind(&self.tenant_id)
        .bind(self.partition_id)
        .fetch_optional(&mut *self.tx)
        .await
        .map_err(|err| io_err(&err))?;
        row.map(|row| {
            Ok((
                row.try_get("head_seq").map_err(|err| io_err(&err))?,
                row.try_get("head_hash").map_err(|err| io_err(&err))?,
            ))
        })
        .transpose()
    }

    /// Read a page by sequence, excluding tenant and partition metadata from
    /// the v1 `DecisionEvent` representation.
    pub async fn events(
        &mut self,
        after_seq: i64,
        limit: u32,
    ) -> Result<Vec<(i64, DecisionEvent)>, EvidenceError> {
        let rows = sqlx::query(
            "SELECT * FROM decision_events \
             WHERE tenant_id = $1 AND partition_id = $2 AND seq > $3 \
             ORDER BY seq LIMIT $4",
        )
        .bind(&self.tenant_id)
        .bind(self.partition_id)
        .bind(after_seq)
        .bind(i64::from(limit))
        .fetch_all(&mut *self.tx)
        .await
        .map_err(|err| io_err(&err))?;
        rows.iter()
            .map(|row| {
                Ok((
                    row.try_get("seq").map_err(|err| io_err(&err))?,
                    row_to_event(row)?,
                ))
            })
            .collect()
    }

    pub async fn close(self) -> Result<(), EvidenceError> {
        self.tx.commit().await.map_err(|err| io_err(&err))
    }
}

fn checkpoint_from_row(row: &sqlx::postgres::PgRow) -> Result<Checkpoint, PortError> {
    let payload: serde_json::Value = row
        .try_get("payload")
        .map_err(|e| PortError::unavailable(e.to_string()))?;
    Ok(Checkpoint {
        payload: serde_json::from_value(payload)
            .map_err(|e| PortError::invalid(format!("stored checkpoint: {e}")))?,
        hash: row
            .try_get("hash")
            .map_err(|e| PortError::unavailable(e.to_string()))?,
        sig: row
            .try_get("sig")
            .map_err(|e| PortError::unavailable(e.to_string()))?,
    })
}

impl CheckpointStore for PostgresEvidenceStore {
    async fn head(&self, scope: Scope<'_>) -> Result<Option<(i64, String)>, PortError> {
        if scope.chain != CHAIN_DECISION_EVENTS || scope.tenant_id != self.tenant_id {
            return Ok(None);
        }
        let row = sqlx::query(
            "SELECT head_seq, head_hash FROM evidence_chains \
             WHERE tenant_id = $1 AND partition_id = $2 AND head_seq > 0",
        )
        .bind(scope.tenant_id)
        .bind(scope.partition_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| PortError::unavailable(e.to_string()))?;
        row.map(|row| {
            Ok((
                row.try_get("head_seq")
                    .map_err(|e| PortError::unavailable(e.to_string()))?,
                row.try_get("head_hash")
                    .map_err(|e| PortError::unavailable(e.to_string()))?,
            ))
        })
        .transpose()
    }

    async fn latest(&self, scope: Scope<'_>) -> Result<Option<Checkpoint>, PortError> {
        if scope.chain != CHAIN_DECISION_EVENTS || scope.tenant_id != self.tenant_id {
            return Ok(None);
        }
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
        .map_err(|e| PortError::unavailable(e.to_string()))?;
        row.as_ref().map(checkpoint_from_row).transpose()
    }

    async fn append(&self, checkpoint: &Checkpoint) -> Result<Appended, PortError> {
        check_storable(checkpoint)?;
        let payload = &checkpoint.payload;
        if payload.chain != CHAIN_DECISION_EVENTS || payload.tenant_id != self.tenant_id {
            return Err(PortError::rejected(
                "credit evidence store accepts only its tenant's decision-event checkpoints",
            ));
        }
        let record_hash: Option<String> = sqlx::query_scalar(
            "SELECT hash FROM decision_events WHERE tenant_id = $1 \
             AND partition_id = $2 AND seq = $3",
        )
        .bind(&payload.tenant_id)
        .bind(payload.partition_id)
        .bind(payload.seq)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| PortError::unavailable(e.to_string()))?;
        if record_hash.as_deref() != Some(payload.head_hash.as_str()) {
            return Err(PortError::rejected(
                "no decision event with this seq and hash to checkpoint",
            ));
        }
        let scope = Scope {
            tenant_id: &payload.tenant_id,
            partition_id: payload.partition_id,
            chain: &payload.chain,
        };
        let latest = self.latest(scope).await?;
        if check_follows(checkpoint, latest.as_ref())? == Appended::Superseded {
            return Ok(Appended::Superseded);
        }
        let inserted = sqlx::query(
            "INSERT INTO evidence_checkpoints (tenant_id, partition_id, chain, seq, head_hash, \
             prev_checkpoint_hash, key_id, ts, hash, sig, payload) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(&payload.tenant_id)
        .bind(payload.partition_id)
        .bind(&payload.chain)
        .bind(payload.seq)
        .bind(&payload.head_hash)
        .bind(&payload.prev_checkpoint_hash)
        .bind(&payload.key_id)
        .bind(payload.ts)
        .bind(&checkpoint.hash)
        .bind(&checkpoint.sig)
        .bind(serde_json::to_value(checkpoint).map_err(|e| PortError::invalid(e.to_string()))?)
        .execute(&self.pool)
        .await;
        match inserted {
            Ok(_) => Ok(Appended::Written),
            Err(sqlx::Error::Database(err)) if err.code().as_deref() == Some("23505") => {
                Ok(Appended::Superseded)
            }
            Err(err) => Err(PortError::unavailable(err.to_string())),
        }
    }

    async fn list(
        &self,
        scope: Scope<'_>,
        after_seq: i64,
        limit: u32,
    ) -> Result<Vec<Checkpoint>, PortError> {
        if scope.chain != CHAIN_DECISION_EVENTS || scope.tenant_id != self.tenant_id {
            return Ok(Vec::new());
        }
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
        .map_err(|e| PortError::unavailable(e.to_string()))?;
        rows.iter().map(checkpoint_from_row).collect()
    }
}

impl EvidenceStore for PostgresEvidenceStore {
    fn append(&mut self, input: AppendDecisionEvent) -> Result<DecisionEvent, EvidenceError> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(self.append_async(input))
        })
    }
}

impl PostgresEvidenceStore {
    async fn append_async(
        &self,
        input: AppendDecisionEvent,
    ) -> Result<DecisionEvent, EvidenceError> {
        // Fast path without the chain lock.
        if let Some(existing) = fetch_by_idempotency(
            &self.pool,
            &self.tenant_id,
            &input.model_id,
            &input.correlation_id,
        )
        .await?
        {
            kavach_evidence::check_idempotent_replay(&existing, &input)?;
            return Ok(existing);
        }

        let mut tx = self.pool.begin().await.map_err(|err| io_err(&err))?;
        sqlx::query(
            "INSERT INTO evidence_chains (tenant_id, partition_id, head_hash, head_seq) \
            VALUES ($1, 0, $2, 0) ON CONFLICT (tenant_id, partition_id) DO NOTHING",
        )
        .bind(&self.tenant_id)
        .bind(kavach_evidence::GENESIS_HASH)
        .execute(&mut *tx)
        .await
        .map_err(|err| io_err(&err))?;
        let (head_hash, head_seq): (String, i64) = sqlx::query_as(
            "SELECT head_hash, head_seq FROM evidence_chains \
            WHERE tenant_id = $1 AND partition_id = 0 FOR UPDATE",
        )
        .bind(&self.tenant_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|err| io_err(&err))?;

        // The chain lock serializes appends: a concurrent request with the same
        // key that committed while we waited is visible now, and is replayed
        // (or refused as a conflict) instead of failing on the unique key.
        if let Some(existing) = fetch_by_idempotency(
            &mut *tx,
            &self.tenant_id,
            &input.model_id,
            &input.correlation_id,
        )
        .await?
        {
            kavach_evidence::check_idempotent_replay(&existing, &input)?;
            return Ok(existing);
        }

        let event_id = Uuid::new_v4().to_string();
        let evidence_id = Uuid::new_v4().to_string();
        let mut event = DecisionEvent {
            schema_version: SCHEMA_VERSION.to_string(),
            event_id,
            evidence_id,
            prev_hash: head_hash,
            hash: String::new(),
            pack_id: input.pack_id,
            pack_version: input.pack_version,
            sector: input.sector,
            model_id: input.model_id,
            model_version: input.model_version,
            model_origin: input.model_origin,
            governance_mode: input.governance_mode,
            policy_decision: input.policy_decision,
            returned_decision: input.returned_decision,
            reason_codes: input.reason_codes,
            policy_hits: input.policy_hits,
            pii_tokens: input.pii_tokens,
            input_digest: input.input_digest,
            latency_ms: input.latency_ms,
            // Postgres keeps microseconds: hash what is stored.
            decision_time: at_storage_precision(input.decision_time),
            evaluated_at: at_storage_precision(input.evaluated_at),
            service_identity_id: input.service_identity_id,
            correlation_id: input.correlation_id,
            idempotency_key: input.idempotency_key,
        };

        event.hash = compute_event_hash(&event.prev_hash, &event).map_err(EvidenceError::Json)?;
        verify_event_hash(&event)?;

        let seq = head_seq.checked_add(1).ok_or_else(|| {
            EvidenceError::Domain(kavach_domain::DomainError::Golden(
                "evidence sequence exhausted".into(),
            ))
        })?;
        insert_event(&mut tx, &self.tenant_id, 0, seq, &event).await?;

        sqlx::query(
            "UPDATE evidence_chains SET head_hash = $1, head_seq = $2 \
            WHERE tenant_id = $3 AND partition_id = 0",
        )
        .bind(&event.hash)
        .bind(seq)
        .bind(&self.tenant_id)
        .execute(&mut *tx)
        .await
        .map_err(|err| io_err(&err))?;

        tx.commit().await.map_err(|err| io_err(&err))?;
        Ok(event)
    }
}

async fn insert_event(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    partition_id: i32,
    seq: i64,
    event: &DecisionEvent,
) -> Result<(), EvidenceError> {
    let reason_codes = serde_json::to_value(&event.reason_codes).map_err(EvidenceError::Json)?;
    let policy_hits = serde_json::to_value(&event.policy_hits).map_err(EvidenceError::Json)?;
    let pii_tokens = serde_json::to_value(&event.pii_tokens).map_err(EvidenceError::Json)?;

    sqlx::query(
        r"
        INSERT INTO decision_events (
            tenant_id, partition_id, seq, evidence_id, event_id, schema_version, prev_hash, hash,
            pack_id, pack_version, sector, model_id, model_version,
            model_origin, governance_mode, policy_decision, returned_decision,
            reason_codes, policy_hits, pii_tokens, input_digest, latency_ms,
            decision_time, evaluated_at, service_identity_id, correlation_id, idempotency_key
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9,
            $10, $11, $12, $13, $14, $15, $16,
            $17, $18, $19, $20, $21, $22,
            $23, $24, $25, $26, $27
        )
        ",
    )
    .bind(tenant_id)
    .bind(partition_id)
    .bind(seq)
    .bind(&event.evidence_id)
    .bind(&event.event_id)
    .bind(&event.schema_version)
    .bind(&event.prev_hash)
    .bind(&event.hash)
    .bind(&event.pack_id)
    .bind(&event.pack_version)
    .bind(&event.sector)
    .bind(&event.model_id)
    .bind(&event.model_version)
    .bind(model_origin_str(event.model_origin))
    .bind(governance_mode_str(event.governance_mode))
    .bind(decision_str(event.policy_decision))
    .bind(decision_str(event.returned_decision))
    .bind(reason_codes)
    .bind(policy_hits)
    .bind(pii_tokens)
    .bind(&event.input_digest)
    .bind(i64::try_from(event.latency_ms).unwrap_or(i64::MAX))
    .bind(event.decision_time)
    .bind(event.evaluated_at)
    .bind(&event.service_identity_id)
    .bind(&event.correlation_id)
    .bind(&event.idempotency_key)
    .execute(&mut **tx)
    .await
    .map_err(|err| io_err(&err))?;
    Ok(())
}

impl PostgresEvidenceStore {
    /// One decision event by its evidence id (operator reads; `kavach why`).
    pub async fn event(&self, evidence_id: &str) -> Result<Option<DecisionEvent>, EvidenceError> {
        let row =
            sqlx::query("SELECT * FROM decision_events WHERE tenant_id = $1 AND evidence_id = $2")
                .bind(&self.tenant_id)
                .bind(evidence_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|err| io_err(&err))?;
        row.as_ref().map(row_to_event).transpose()
    }
}

async fn fetch_by_idempotency<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    tenant_id: &str,
    model_id: &str,
    correlation_id: &str,
) -> Result<Option<DecisionEvent>, EvidenceError> {
    let row =
        sqlx::query("SELECT * FROM decision_events WHERE tenant_id = $1 AND model_id = $2 AND correlation_id = $3")
            .bind(tenant_id)
            .bind(model_id)
            .bind(correlation_id)
            .fetch_optional(executor)
            .await
            .map_err(|err| io_err(&err))?;

    row.as_ref().map(row_to_event).transpose()
}

fn io_err(err: &sqlx::Error) -> EvidenceError {
    EvidenceError::Domain(kavach_domain::DomainError::Golden(format!(
        "postgres io: {err}"
    )))
}

fn decision_str(decision: Decision) -> &'static str {
    match decision {
        Decision::Pass => "PASS",
        Decision::Alert => "ALERT",
        Decision::Block => "BLOCK",
        Decision::HumanReview => "HUMAN_REVIEW",
    }
}

fn parse_decision(value: &str) -> Result<Decision, EvidenceError> {
    match value {
        "PASS" => Ok(Decision::Pass),
        "ALERT" => Ok(Decision::Alert),
        "BLOCK" => Ok(Decision::Block),
        "HUMAN_REVIEW" => Ok(Decision::HumanReview),
        other => Err(EvidenceError::Domain(
            kavach_domain::DomainError::InvalidDecision(other.into()),
        )),
    }
}

fn governance_mode_str(mode: GovernanceMode) -> &'static str {
    match mode {
        GovernanceMode::Shadow => "shadow",
        GovernanceMode::Enforce => "enforce",
    }
}

fn parse_governance_mode(value: &str) -> Result<GovernanceMode, EvidenceError> {
    match value {
        "shadow" => Ok(GovernanceMode::Shadow),
        "enforce" => Ok(GovernanceMode::Enforce),
        other => Err(EvidenceError::Domain(
            kavach_domain::DomainError::InvalidGovernanceMode(other.into()),
        )),
    }
}

fn model_origin_str(origin: ModelOrigin) -> &'static str {
    match origin {
        ModelOrigin::InHouse => "in_house",
        ModelOrigin::Vendor => "vendor",
    }
}

fn parse_model_origin(value: &str) -> Result<ModelOrigin, EvidenceError> {
    match value {
        "in_house" => Ok(ModelOrigin::InHouse),
        "vendor" => Ok(ModelOrigin::Vendor),
        other => Err(EvidenceError::Domain(kavach_domain::DomainError::Golden(
            format!("invalid model_origin: {other}"),
        ))),
    }
}

fn row_to_event(row: &sqlx::postgres::PgRow) -> Result<DecisionEvent, EvidenceError> {
    let reason_codes: serde_json::Value =
        row.try_get("reason_codes").map_err(|err| io_err(&err))?;
    let policy_hits: serde_json::Value = row.try_get("policy_hits").map_err(|err| io_err(&err))?;
    let pii_tokens: serde_json::Value = row.try_get("pii_tokens").map_err(|err| io_err(&err))?;

    Ok(DecisionEvent {
        schema_version: row.try_get("schema_version").map_err(|err| io_err(&err))?,
        event_id: row.try_get("event_id").map_err(|err| io_err(&err))?,
        evidence_id: row.try_get("evidence_id").map_err(|err| io_err(&err))?,
        prev_hash: row.try_get("prev_hash").map_err(|err| io_err(&err))?,
        hash: row.try_get("hash").map_err(|err| io_err(&err))?,
        pack_id: row.try_get("pack_id").map_err(|err| io_err(&err))?,
        pack_version: row.try_get("pack_version").map_err(|err| io_err(&err))?,
        sector: row.try_get("sector").map_err(|err| io_err(&err))?,
        model_id: row.try_get("model_id").map_err(|err| io_err(&err))?,
        model_version: row.try_get("model_version").map_err(|err| io_err(&err))?,
        model_origin: parse_model_origin(row.try_get("model_origin").map_err(|err| io_err(&err))?)?,
        governance_mode: parse_governance_mode(
            row.try_get("governance_mode").map_err(|err| io_err(&err))?,
        )?,
        policy_decision: parse_decision(
            row.try_get("policy_decision").map_err(|err| io_err(&err))?,
        )?,
        returned_decision: parse_decision(
            row.try_get("returned_decision")
                .map_err(|err| io_err(&err))?,
        )?,
        reason_codes: serde_json::from_value(reason_codes).map_err(EvidenceError::Json)?,
        policy_hits: serde_json::from_value(policy_hits).map_err(EvidenceError::Json)?,
        pii_tokens: serde_json::from_value(pii_tokens).map_err(EvidenceError::Json)?,
        input_digest: row.try_get("input_digest").map_err(|err| io_err(&err))?,
        latency_ms: u64::try_from(
            row.try_get::<i64, _>("latency_ms")
                .map_err(|err| io_err(&err))?,
        )
        .unwrap_or(u64::MAX),
        decision_time: row.try_get("decision_time").map_err(|err| io_err(&err))?,
        evaluated_at: row.try_get("evaluated_at").map_err(|err| io_err(&err))?,
        service_identity_id: row
            .try_get("service_identity_id")
            .map_err(|err| io_err(&err))?,
        correlation_id: row.try_get("correlation_id").map_err(|err| io_err(&err))?,
        idempotency_key: row.try_get("idempotency_key").map_err(|err| io_err(&err))?,
    })
}

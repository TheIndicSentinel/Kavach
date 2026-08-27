use kavach_domain::{Decision, DecisionEvent, GovernanceMode, ModelOrigin, SCHEMA_VERSION};
use kavach_evaluate::EvidenceStore;
use kavach_evidence::{compute_event_hash, verify_event_hash, AppendDecisionEvent, EvidenceError};
use sqlx::{PgPool, Row};
use uuid::Uuid;

#[derive(Clone)]
pub struct PostgresEvidenceStore {
    pool: PgPool,
}

impl PostgresEvidenceStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
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
        if let Some(existing) = self
            .fetch_by_idempotency(&input.model_id, &input.correlation_id)
            .await?
        {
            return Ok(existing);
        }

        let mut tx = self.pool.begin().await.map_err(|err| io_err(&err))?;
        let head_hash: String =
            sqlx::query_scalar("SELECT head_hash FROM evidence_chain_meta WHERE id = 1 FOR UPDATE")
                .fetch_one(&mut *tx)
                .await
                .map_err(|err| io_err(&err))?;

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
            decision_time: input.decision_time,
            evaluated_at: input.evaluated_at,
            service_identity_id: input.service_identity_id,
            correlation_id: input.correlation_id,
            idempotency_key: input.idempotency_key,
        };

        event.hash = compute_event_hash(&event.prev_hash, &event).map_err(EvidenceError::Json)?;
        verify_event_hash(&event)?;

        let reason_codes =
            serde_json::to_value(&event.reason_codes).map_err(EvidenceError::Json)?;
        let policy_hits = serde_json::to_value(&event.policy_hits).map_err(EvidenceError::Json)?;
        let pii_tokens = serde_json::to_value(&event.pii_tokens).map_err(EvidenceError::Json)?;

        sqlx::query(
            r"
            INSERT INTO decision_events (
                evidence_id, event_id, schema_version, prev_hash, hash,
                pack_id, pack_version, sector, model_id, model_version,
                model_origin, governance_mode, policy_decision, returned_decision,
                reason_codes, policy_hits, pii_tokens, input_digest, latency_ms,
                decision_time, evaluated_at, service_identity_id, correlation_id, idempotency_key
            ) VALUES (
                $1, $2, $3, $4, $5,
                $6, $7, $8, $9, $10,
                $11, $12, $13, $14,
                $15, $16, $17, $18, $19,
                $20, $21, $22, $23, $24
            )
            ",
        )
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
        .execute(&mut *tx)
        .await
        .map_err(|err| io_err(&err))?;

        sqlx::query("UPDATE evidence_chain_meta SET head_hash = $1 WHERE id = 1")
            .bind(&event.hash)
            .execute(&mut *tx)
            .await
            .map_err(|err| io_err(&err))?;

        tx.commit().await.map_err(|err| io_err(&err))?;
        Ok(event)
    }

    async fn fetch_by_idempotency(
        &self,
        model_id: &str,
        correlation_id: &str,
    ) -> Result<Option<DecisionEvent>, EvidenceError> {
        let row = sqlx::query(
            "SELECT * FROM decision_events WHERE model_id = $1 AND correlation_id = $2",
        )
        .bind(model_id)
        .bind(correlation_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|err| io_err(&err))?;

        row.as_ref().map(row_to_event).transpose()
    }
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

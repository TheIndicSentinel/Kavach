-- R1b-1 (ADR-012 §7, ADR-013): the agent evidence chain holds more than one
-- kind of record. One table, so every record of a chain still takes its
-- position from the same primary key (tenant, partition, seq) and the
-- database itself refuses two records at one position.
--
-- No behaviour change: every existing row is a decision, and decisions are
-- written exactly as before. The append-only and no-truncate triggers and the
-- runtime and auditor grants are untouched (ALTER TABLE keeps them; adding a
-- column with a constant default rewrites no row, so no trigger fires).

-- The kind, as the record's signed payload states it.
ALTER TABLE agent_decisions
    ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'agent_decision';
ALTER TABLE agent_decisions
    ADD CONSTRAINT agent_records_kind_known
        CHECK (kind IN ('agent_decision', 'mandate_revocation')),
    ADD CONSTRAINT agent_records_kind_is_signed
        CHECK (kind = payload->>'kind');

-- What identifies a revocation record: the system-of-record event.
ALTER TABLE agent_decisions
    ADD COLUMN IF NOT EXISTS source_system TEXT,
    ADD COLUMN IF NOT EXISTS event_id TEXT;

-- Decision-only columns are required for decisions, absent otherwise.
ALTER TABLE agent_decisions
    ALTER COLUMN agent_id DROP NOT NULL,
    ALTER COLUMN request_id DROP NOT NULL,
    ALTER COLUMN binding DROP NOT NULL,
    ALTER COLUMN returned_decision DROP NOT NULL;
ALTER TABLE agent_decisions
    ADD CONSTRAINT agent_records_decision_fields CHECK (
        kind <> 'agent_decision' OR (
            agent_id IS NOT NULL AND request_id IS NOT NULL
            AND binding IS NOT NULL AND returned_decision IS NOT NULL
            AND source_system IS NULL AND event_id IS NULL
        )
    ),
    ADD CONSTRAINT agent_records_revocation_fields CHECK (
        kind <> 'mandate_revocation' OR (
            source_system IS NOT NULL AND event_id IS NOT NULL
            AND agent_id IS NULL AND request_id IS NULL AND binding IS NULL
            AND returned_decision IS NULL AND credential_id IS NULL
        )
    );

-- One decision per (tenant, agent, mode, request): now for decisions only.
ALTER TABLE agent_decisions
    DROP CONSTRAINT agent_decisions_tenant_id_agent_id_mode_request_id_key;
CREATE UNIQUE INDEX IF NOT EXISTS agent_decisions_one_per_request
    ON agent_decisions (tenant_id, agent_id, mode, request_id)
    WHERE kind = 'agent_decision';

-- One revocation record per system-of-record event (written once, also by
-- the reconciler).
CREATE UNIQUE INDEX IF NOT EXISTS agent_records_one_per_revocation_event
    ON agent_decisions (tenant_id, source_system, event_id)
    WHERE kind = 'mandate_revocation';

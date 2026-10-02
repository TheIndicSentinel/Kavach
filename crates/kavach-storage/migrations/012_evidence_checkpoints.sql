-- E2a: signed evidence checkpoints (ADR-005 §13).
--
-- A checkpoint states that record `seq` of a chain has hash `head_hash`.
-- The two unique keys keep the checkpoints of a chain in one line without a
-- lock: one checkpoint per seq, and one successor per checkpoint (so two
-- writers cannot both follow the same checkpoint).

CREATE TABLE IF NOT EXISTS evidence_checkpoints (
    tenant_id TEXT NOT NULL,
    partition_id INTEGER NOT NULL,
    chain TEXT NOT NULL CHECK (chain IN ('agent_decisions')),
    seq BIGINT NOT NULL CHECK (seq >= 1),
    head_hash TEXT NOT NULL,
    prev_checkpoint_hash TEXT NOT NULL,
    key_id TEXT NOT NULL,
    ts TIMESTAMPTZ NOT NULL,
    hash TEXT NOT NULL UNIQUE,
    sig TEXT NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, partition_id, chain, seq),
    UNIQUE (tenant_id, partition_id, chain, prev_checkpoint_hash)
);

-- Append-only, including against TRUNCATE (as agent_decisions, 010).
CREATE OR REPLACE TRIGGER evidence_checkpoints_append_only
    BEFORE UPDATE OR DELETE ON evidence_checkpoints
    FOR EACH ROW EXECUTE FUNCTION kavach_append_only();
CREATE OR REPLACE TRIGGER evidence_checkpoints_no_truncate
    BEFORE TRUNCATE ON evidence_checkpoints
    FOR EACH STATEMENT EXECUTE FUNCTION kavach_append_only();

-- Runtime grants, now including checkpoints (insert and read only).
CREATE OR REPLACE FUNCTION kavach_grant_runtime() RETURNS void AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kavach_runtime') THEN
        RETURN;
    END IF;
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO kavach_runtime', current_schema());
    EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA %I FROM kavach_runtime', current_schema());

    GRANT SELECT, INSERT ON admin_audit_log, decision_events, evaluate_incidents,
        evidence_tombstones, agent_decisions, agent_outcomes, evidence_checkpoints
        TO kavach_runtime;
    GRANT SELECT, UPDATE ON evidence_chain_meta, tenant_settings TO kavach_runtime;
    GRANT SELECT, INSERT, UPDATE ON batch_jobs, change_requests, mandates, model_state,
        runtime_pointers, agent_evidence_chains, contact_counters TO kavach_runtime;
    GRANT SELECT, INSERT, UPDATE, DELETE ON replay_guard TO kavach_runtime;

    EXECUTE format('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA %I TO kavach_runtime',
        current_schema());
END
$$ LANGUAGE plpgsql;

SELECT kavach_grant_runtime();

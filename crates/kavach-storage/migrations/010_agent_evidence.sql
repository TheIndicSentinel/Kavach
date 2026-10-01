-- H5a-3b: Agent Decision Records, contact counters and outcomes (ADR-005).

-- Head of each (tenant, partition) agent chain. Kept apart from the v1
-- decision_events chain until the M2 merge.
CREATE TABLE IF NOT EXISTS agent_evidence_chains (
    tenant_id TEXT NOT NULL,
    partition_id INTEGER NOT NULL,
    head_seq BIGINT NOT NULL,
    head_hash TEXT NOT NULL,
    PRIMARY KEY (tenant_id, partition_id)
);

CREATE TABLE IF NOT EXISTS agent_decisions (
    tenant_id TEXT NOT NULL,
    partition_id INTEGER NOT NULL,
    seq BIGINT NOT NULL,
    record_id TEXT NOT NULL UNIQUE,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL,
    sig TEXT NOT NULL,
    key_id TEXT NOT NULL,
    payload JSONB NOT NULL,
    agent_id TEXT NOT NULL,
    mode TEXT NOT NULL DEFAULT 'commit' CHECK (mode IN ('commit')),
    request_id TEXT NOT NULL,
    binding JSONB NOT NULL,
    credential_id TEXT UNIQUE,
    returned_decision TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, partition_id, seq),
    UNIQUE (tenant_id, agent_id, mode, request_id)
);

-- Contacts reserved per subject (pseudonym) per IST day, across agents and
-- mandates.
CREATE TABLE IF NOT EXISTS contact_counters (
    tenant_id TEXT NOT NULL,
    subject_pseudonym TEXT NOT NULL,
    ist_date DATE NOT NULL,
    count INTEGER NOT NULL CHECK (count >= 0),
    PRIMARY KEY (tenant_id, subject_pseudonym, ist_date)
);

-- What happened after an allow, once per credential (signed; off-chain).
CREATE TABLE IF NOT EXISTS agent_outcomes (
    tenant_id TEXT NOT NULL,
    credential_id TEXT NOT NULL,
    record_hash TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('delivered', 'failed', 'refused')),
    ts TIMESTAMPTZ NOT NULL,
    key_id TEXT NOT NULL,
    sig TEXT NOT NULL,
    PRIMARY KEY (tenant_id, credential_id)
);

-- Records and outcomes are append-only, including against TRUNCATE (role
-- separation is the primary control; this is defence in depth).
CREATE OR REPLACE FUNCTION kavach_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
END
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER agent_decisions_append_only
    BEFORE UPDATE OR DELETE ON agent_decisions
    FOR EACH ROW EXECUTE FUNCTION kavach_append_only();
CREATE OR REPLACE TRIGGER agent_decisions_no_truncate
    BEFORE TRUNCATE ON agent_decisions
    FOR EACH STATEMENT EXECUTE FUNCTION kavach_append_only();
CREATE OR REPLACE TRIGGER agent_outcomes_append_only
    BEFORE UPDATE OR DELETE ON agent_outcomes
    FOR EACH ROW EXECUTE FUNCTION kavach_append_only();
CREATE OR REPLACE TRIGGER agent_outcomes_no_truncate
    BEFORE TRUNCATE ON agent_outcomes
    FOR EACH STATEMENT EXECUTE FUNCTION kavach_append_only();

-- Runtime grants, now including the agent evidence tables.
CREATE OR REPLACE FUNCTION kavach_grant_runtime() RETURNS void AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kavach_runtime') THEN
        RETURN;
    END IF;
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO kavach_runtime', current_schema());
    EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA %I FROM kavach_runtime', current_schema());

    GRANT SELECT, INSERT ON admin_audit_log, decision_events, evaluate_incidents,
        evidence_tombstones, agent_decisions, agent_outcomes TO kavach_runtime;
    GRANT SELECT, UPDATE ON evidence_chain_meta, tenant_settings TO kavach_runtime;
    GRANT SELECT, INSERT, UPDATE ON batch_jobs, change_requests, mandates, model_state,
        runtime_pointers, agent_evidence_chains, contact_counters TO kavach_runtime;
    GRANT SELECT, INSERT, UPDATE, DELETE ON replay_guard TO kavach_runtime;

    EXECUTE format('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA %I TO kavach_runtime',
        current_schema());
END
$$ LANGUAGE plpgsql;

SELECT kavach_grant_runtime();

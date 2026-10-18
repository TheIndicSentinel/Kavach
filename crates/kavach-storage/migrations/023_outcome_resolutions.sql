-- ADR-017: resolutions of `unknown` outcomes. A second signed row that refers
-- to the outcome (never a rewrite of it), several per outcome, the governing
-- state computed from all of them. Append-only, like outcomes.
CREATE TABLE IF NOT EXISTS agent_outcome_resolutions (
    tenant_id TEXT NOT NULL,
    credential_id TEXT NOT NULL,
    -- hex SHA-256 of the outcome row's `sig`
    outcome_ref TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('confirmed_delivered', 'confirmed_not_delivered', 'ambiguous')),
    source TEXT NOT NULL CHECK (source IN ('provider_status', 'operator_attested', 'conflict_resolution', 'reconciler')),
    reason TEXT NOT NULL,
    evidence_digest TEXT,
    resolved_by TEXT,
    approved_by TEXT,
    ts TIMESTAMPTZ NOT NULL,
    key_id TEXT NOT NULL,
    sig TEXT NOT NULL,
    -- One row per (source, state) for an outcome: a repeat is a no-op.
    PRIMARY KEY (tenant_id, credential_id, source, state),
    FOREIGN KEY (tenant_id, credential_id) REFERENCES agent_outcomes (tenant_id, credential_id)
);

CREATE OR REPLACE TRIGGER agent_outcome_resolutions_append_only
    BEFORE UPDATE OR DELETE ON agent_outcome_resolutions
    FOR EACH ROW EXECUTE FUNCTION kavach_append_only();
CREATE OR REPLACE TRIGGER agent_outcome_resolutions_no_truncate
    BEFORE TRUNCATE ON agent_outcome_resolutions
    FOR EACH STATEMENT EXECUTE FUNCTION kavach_append_only();

-- The runtime role may read and insert; the read-only auditor role may read
-- (export reads it).
CREATE OR REPLACE FUNCTION kavach_grant_runtime() RETURNS void AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kavach_runtime') THEN
        RETURN;
    END IF;
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO kavach_runtime', current_schema());
    EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA %I FROM kavach_runtime', current_schema());

    GRANT SELECT, INSERT ON admin_audit_log, decision_events, evaluate_incidents,
        evidence_tombstones, agent_decisions, agent_outcomes, evidence_checkpoints,
        mandate_revocations, agent_state_changes, agent_outcome_resolutions
        TO kavach_runtime;
    GRANT SELECT, UPDATE ON evidence_chain_meta, tenant_settings TO kavach_runtime;
    GRANT SELECT, INSERT, UPDATE ON batch_jobs, change_requests, mandates, model_state,
        runtime_pointers, agent_evidence_chains, contact_counters, agent_states
        TO kavach_runtime;
    GRANT SELECT, INSERT, UPDATE, DELETE ON replay_guard TO kavach_runtime;

    EXECUTE format('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA %I TO kavach_runtime',
        current_schema());
END
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION kavach_grant_auditor() RETURNS void AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kavach_auditor') THEN
        RETURN;
    END IF;
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO kavach_auditor', current_schema());
    EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA %I FROM kavach_auditor', current_schema());
    EXECUTE format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA %I FROM kavach_auditor',
        current_schema());

    GRANT SELECT ON agent_decisions, agent_outcomes, evidence_checkpoints,
        agent_evidence_chains, agent_outcome_resolutions TO kavach_auditor;
END
$$ LANGUAGE plpgsql;

SELECT kavach_grant_runtime();
SELECT kavach_grant_auditor();

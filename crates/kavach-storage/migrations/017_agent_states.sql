-- K1 / ADR-013: agent risk state (active, restricted, quarantined, revoked).
--
-- One current row per (tenant, agent); an agent with no row is active. Read
-- at every authorization. The history of changes is the signed `agent_state`
-- records in the evidence chain (K1-2), not this table.
--
-- Defence in depth: the store applies the same rules in code, and the
-- database holds them too, so a runtime role that has UPDATE cannot undo a
-- revocation or let one principal approve their own change.

CREATE TABLE IF NOT EXISTS agent_states (
    tenant_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    state TEXT NOT NULL,
    reason TEXT NOT NULL,
    changed_by TEXT NOT NULL,
    approved_by TEXT,
    changed_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, agent_id),
    CONSTRAINT agent_states_state_known
        CHECK (state IN ('active', 'restricted', 'quarantined', 'revoked')),
    CONSTRAINT agent_states_reason_present
        CHECK (length(btrim(reason)) BETWEEN 1 AND 256),
    CONSTRAINT agent_states_approver_differs
        CHECK (approved_by IS NULL OR approved_by <> changed_by)
);

CREATE OR REPLACE FUNCTION kavach_agent_state_final() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'agent_states rows are never deleted' USING ERRCODE = 'P0001';
    END IF;
    IF OLD.state = 'revoked' THEN
        RAISE EXCEPTION 'a revoked agent cannot be changed' USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER agent_states_revoked_is_final
    BEFORE UPDATE OR DELETE ON agent_states
    FOR EACH ROW EXECUTE FUNCTION kavach_agent_state_final();
CREATE OR REPLACE TRIGGER agent_states_no_truncate
    BEFORE TRUNCATE ON agent_states
    FOR EACH STATEMENT EXECUTE FUNCTION kavach_append_only();

CREATE OR REPLACE FUNCTION kavach_grant_runtime() RETURNS void AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kavach_runtime') THEN
        RETURN;
    END IF;
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO kavach_runtime', current_schema());
    EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA %I FROM kavach_runtime', current_schema());

    GRANT SELECT, INSERT ON admin_audit_log, decision_events, evaluate_incidents,
        evidence_tombstones, agent_decisions, agent_outcomes, evidence_checkpoints,
        mandate_revocations
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

SELECT kavach_grant_runtime();

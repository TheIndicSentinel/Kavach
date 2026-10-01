-- H5a-3a: separate migration (owner) and runtime roles (ADR-005 §1).
--
-- The migration role owns every table. The runtime role `kavach_runtime`
-- (created by the operator; see deploy/postgres) gets only what the
-- application uses: append-only tables are INSERT/SELECT, nothing gets
-- TRUNCATE, and the runtime role can neither alter tables nor drop triggers.
-- Later migrations redefine this function to cover their tables and call it.

CREATE OR REPLACE FUNCTION kavach_grant_runtime() RETURNS void AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kavach_runtime') THEN
        RETURN;
    END IF;
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO kavach_runtime', current_schema());
    EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA %I FROM kavach_runtime', current_schema());

    -- Append-only evidence and audit.
    GRANT SELECT, INSERT ON admin_audit_log, decision_events, evaluate_incidents,
        evidence_tombstones TO kavach_runtime;
    -- Head row of the v1 chain: read and advance only.
    GRANT SELECT, UPDATE ON evidence_chain_meta, tenant_settings TO kavach_runtime;
    -- Governed state and work queues (updates guarded by triggers or the
    -- application; no deletes).
    GRANT SELECT, INSERT, UPDATE ON batch_jobs, change_requests, mandates, model_state,
        runtime_pointers TO kavach_runtime;
    -- One-time identifiers expire and are purged.
    GRANT SELECT, INSERT, UPDATE, DELETE ON replay_guard TO kavach_runtime;

    EXECUTE format('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA %I TO kavach_runtime',
        current_schema());
END
$$ LANGUAGE plpgsql;

SELECT kavach_grant_runtime();

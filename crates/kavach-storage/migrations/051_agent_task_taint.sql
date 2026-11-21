-- FR-5: monotonic, tenant-scoped task-taint projection. No content is stored.
CREATE TABLE agent_task_taint (
    tenant_id TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 128),
    mandate_id TEXT NOT NULL CHECK (length(mandate_id) BETWEEN 1 AND 128),
    first_tainted_at TIMESTAMPTZ NOT NULL,
    source TEXT NOT NULL CHECK (source IN (
        'governed_model_output', 'external_untrusted', 'user_content'
    )),
    PRIMARY KEY (tenant_id, mandate_id)
);

REVOKE ALL ON agent_task_taint FROM PUBLIC;

-- Keep the canonical grant function current so both the migration and the
-- documented post-migration role bootstrap grant only the required access.
CREATE OR REPLACE FUNCTION kavach_grant_runtime() RETURNS void AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kavach_runtime') THEN
        RETURN;
    END IF;
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO kavach_runtime', current_schema());
    EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA %I FROM kavach_runtime', current_schema());

    GRANT SELECT, INSERT ON admin_audit_log, decision_events, evaluate_incidents,
        evidence_tombstones, agent_decisions, agent_outcomes, evidence_checkpoints,
        mandate_revocations, agent_state_changes, agent_outcome_resolutions,
        human_review_releases TO kavach_runtime;
    GRANT SELECT ON evidence_chain_meta TO kavach_runtime;
    GRANT SELECT, INSERT, UPDATE ON evidence_chains, tenant_settings,
        batch_jobs, change_requests, mandates, model_state, runtime_pointers,
        agent_evidence_chains, contact_counters, agent_states, principals TO kavach_runtime;
    GRANT SELECT, INSERT ON role_bindings TO kavach_runtime;
    GRANT UPDATE (ended_at, ended_by_change_request) ON role_bindings TO kavach_runtime;
    GRANT SELECT, INSERT ON human_review_approvals TO kavach_runtime;
    GRANT UPDATE (consumed_at) ON human_review_approvals TO kavach_runtime;
    GRANT SELECT, INSERT, DELETE ON human_review_step_up_challenges,
        human_review_snapshots TO kavach_runtime;
    GRANT UPDATE (consumed_at) ON human_review_step_up_challenges TO kavach_runtime;
    GRANT SELECT, INSERT, UPDATE, DELETE ON replay_guard TO kavach_runtime;
    GRANT SELECT, INSERT ON authority_updates TO kavach_runtime;
    GRANT SELECT, INSERT, UPDATE ON consent_current TO kavach_runtime;
    GRANT SELECT, INSERT, UPDATE ON contact_preference_current TO kavach_runtime;
    GRANT SELECT ON reference_destinations TO kavach_runtime;
    GRANT SELECT, INSERT ON agent_task_taint TO kavach_runtime;

    EXECUTE format('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA %I TO kavach_runtime',
        current_schema());
END
$$ LANGUAGE plpgsql;

SELECT kavach_grant_runtime();

-- Preserve the HA active/passive write fence for this new runtime-writable
-- table. A process that lacks the current lease cannot mark taint or return
-- the corresponding model output.
CREATE TRIGGER kavach_active_write_guard
BEFORE INSERT OR UPDATE OR DELETE ON agent_task_taint
FOR EACH ROW EXECUTE FUNCTION kavach_guard_active_write();

SELECT kavach_assert_active_write_guards();

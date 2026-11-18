-- Ciphertext-only destination rows. Runtime may resolve them, but no runtime
-- write path is granted until a signed destination-update contract is approved.
CREATE TABLE reference_destinations (
    tenant_id TEXT NOT NULL,
    subject_ref TEXT NOT NULL,
    channel TEXT NOT NULL,
    version BIGINT NOT NULL CHECK (version > 0),
    format_version SMALLINT NOT NULL CHECK (format_version = 1),
    key_id TEXT NOT NULL CHECK (key_id <> '' AND length(key_id) <= 128),
    nonce BYTEA NOT NULL CHECK (octet_length(nonce) = 12),
    ciphertext BYTEA NOT NULL CHECK (octet_length(ciphertext) BETWEEN 17 AND 4112),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, subject_ref, channel),
    CHECK (tenant_id <> ''),
    CHECK (subject_ref ~ '^ref:[A-Za-z0-9_.-]{1,128}:[A-Za-z0-9_.-]{1,128}$'),
    CHECK (channel ~ '^[a-z0-9_]{1,32}$')
);

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
    GRANT SELECT, UPDATE ON evidence_chain_meta, tenant_settings TO kavach_runtime;
    GRANT SELECT, INSERT, UPDATE ON batch_jobs, change_requests, mandates, model_state,
        runtime_pointers, agent_evidence_chains, contact_counters, agent_states, principals
        TO kavach_runtime;
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

    EXECUTE format('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA %I TO kavach_runtime',
        current_schema());
END
$$ LANGUAGE plpgsql;

SELECT kavach_grant_runtime();

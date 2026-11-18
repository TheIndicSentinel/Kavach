-- Pilot consent and contact-preference persistence. Runtime reads only until
-- signed system-of-record updates are implemented. History contains validated
-- capability references and record metadata, never a destination or raw input.
CREATE TABLE authority_updates (
    tenant_id TEXT NOT NULL,
    source_system TEXT NOT NULL,
    update_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('consent', 'contact_preference')),
    consent_id TEXT,
    subject_ref TEXT,
    channel TEXT,
    payload_sha256 TEXT NOT NULL CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
    record JSONB NOT NULL CHECK (jsonb_typeof(record) = 'object'),
    occurred_at TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, source_system, update_id),
    CHECK (tenant_id <> '' AND source_system <> '' AND update_id <> ''),
    CHECK (record->>'tenant_id' IS NOT DISTINCT FROM tenant_id),
    CHECK (record->>'subject_ref' ~ '^ref:[A-Za-z0-9_.-]{1,128}:[A-Za-z0-9_.-]{1,128}$'),
    CHECK (
        (kind = 'consent' AND consent_id IS NOT NULL AND consent_id <> ''
            AND subject_ref IS NULL AND channel IS NULL
            AND record->>'consent_id' IS NOT DISTINCT FROM consent_id)
        OR (kind = 'contact_preference' AND consent_id IS NULL
            AND subject_ref IS NOT NULL AND subject_ref <> ''
            AND channel IN ('sms', 'voice', 'whatsapp')
            AND record->>'subject_ref' IS NOT DISTINCT FROM subject_ref
            AND record->>'channel' IS NOT DISTINCT FROM channel)
    )
);

CREATE OR REPLACE FUNCTION authority_updates_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'authority update history is append-only';
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER authority_updates_immutable_row
    BEFORE UPDATE OR DELETE ON authority_updates
    FOR EACH ROW EXECUTE FUNCTION authority_updates_immutable();
CREATE TRIGGER authority_updates_immutable_table
    BEFORE TRUNCATE ON authority_updates
    FOR EACH STATEMENT EXECUTE FUNCTION authority_updates_immutable();

CREATE TABLE consent_current (
    tenant_id TEXT NOT NULL,
    consent_id TEXT NOT NULL,
    record JSONB NOT NULL CHECK (jsonb_typeof(record) = 'object'),
    source_system TEXT NOT NULL,
    update_id TEXT NOT NULL,
    version BIGINT NOT NULL CHECK (version > 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, consent_id),
    FOREIGN KEY (tenant_id, source_system, update_id)
        REFERENCES authority_updates (tenant_id, source_system, update_id),
    CHECK (record->>'tenant_id' IS NOT DISTINCT FROM tenant_id),
    CHECK (record->>'consent_id' IS NOT DISTINCT FROM consent_id),
    CHECK (record->>'subject_ref' ~ '^ref:[A-Za-z0-9_.-]{1,128}:[A-Za-z0-9_.-]{1,128}$')
);

CREATE TABLE contact_preference_current (
    tenant_id TEXT NOT NULL,
    subject_ref TEXT NOT NULL,
    channel TEXT NOT NULL CHECK (channel IN ('sms', 'voice', 'whatsapp')),
    record JSONB NOT NULL CHECK (jsonb_typeof(record) = 'object'),
    source_system TEXT NOT NULL,
    update_id TEXT NOT NULL,
    version BIGINT NOT NULL CHECK (version > 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, subject_ref, channel),
    FOREIGN KEY (tenant_id, source_system, update_id)
        REFERENCES authority_updates (tenant_id, source_system, update_id),
    CHECK (record->>'tenant_id' IS NOT DISTINCT FROM tenant_id),
    CHECK (record->>'subject_ref' IS NOT DISTINCT FROM subject_ref),
    CHECK (record->>'channel' IS NOT DISTINCT FROM channel),
    CHECK (subject_ref ~ '^ref:[A-Za-z0-9_.-]{1,128}:[A-Za-z0-9_.-]{1,128}$')
);

-- Repeat the existing runtime-grant helper with read-only access to the new
-- projections, including for a runtime role created after migration.
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
    GRANT SELECT ON authority_updates, consent_current,
        contact_preference_current TO kavach_runtime;

    EXECUTE format('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA %I TO kavach_runtime',
        current_schema());
END
$$ LANGUAGE plpgsql;

SELECT kavach_grant_runtime();

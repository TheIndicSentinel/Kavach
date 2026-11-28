-- Enable signed, encrypted destination updates. History keeps scope metadata
-- and the canonical payload digest only; it never stores the destination.
ALTER TABLE authority_updates
    DROP CONSTRAINT authority_updates_kind_check;
ALTER TABLE authority_updates
    ADD CONSTRAINT authority_updates_kind_check
        CHECK (kind IN ('consent', 'contact_preference', 'reference_destination')) NOT VALID;
ALTER TABLE authority_updates
    VALIDATE CONSTRAINT authority_updates_kind_check;

ALTER TABLE authority_updates
    DROP CONSTRAINT authority_updates_check2;
ALTER TABLE authority_updates
    ADD CONSTRAINT authority_updates_change_check CHECK (
        (kind = 'consent' AND consent_id IS NOT NULL AND consent_id <> ''
            AND subject_ref IS NULL AND channel IS NULL
            AND record->>'consent_id' IS NOT DISTINCT FROM consent_id)
        OR (kind = 'contact_preference' AND consent_id IS NULL
            AND subject_ref IS NOT NULL AND subject_ref <> ''
            AND channel IN ('sms', 'voice', 'whatsapp')
            AND record->>'subject_ref' IS NOT DISTINCT FROM subject_ref
            AND record->>'channel' IS NOT DISTINCT FROM channel)
        OR (kind = 'reference_destination' AND consent_id IS NULL
            AND subject_ref IS NOT NULL AND subject_ref <> ''
            AND channel IN ('sms', 'voice', 'whatsapp')
            AND record->>'subject_ref' IS NOT DISTINCT FROM subject_ref
            AND record->>'channel' IS NOT DISTINCT FROM channel)
    ) NOT VALID;
ALTER TABLE authority_updates
    VALIDATE CONSTRAINT authority_updates_change_check;

ALTER TABLE reference_destinations
    ADD COLUMN source_system TEXT,
    ADD COLUMN update_id TEXT,
    ADD COLUMN source_occurred_at TIMESTAMPTZ;
ALTER TABLE reference_destinations
    ADD CONSTRAINT reference_destinations_source_update_fk
        FOREIGN KEY (tenant_id, source_system, update_id)
        REFERENCES authority_updates (tenant_id, source_system, update_id) NOT VALID;
ALTER TABLE reference_destinations
    VALIDATE CONSTRAINT reference_destinations_source_update_fk;
ALTER TABLE reference_destinations
    ADD CONSTRAINT reference_destinations_source_metadata_check CHECK (
        (source_system IS NULL AND update_id IS NULL AND source_occurred_at IS NULL)
        OR (source_system IS NOT NULL AND source_system <> ''
            AND update_id IS NOT NULL AND update_id <> ''
            AND source_occurred_at IS NOT NULL)
    ) NOT VALID;
ALTER TABLE reference_destinations
    VALIDATE CONSTRAINT reference_destinations_source_metadata_check;

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
    GRANT SELECT, INSERT ON reference_destinations TO kavach_runtime;
    GRANT UPDATE (version, format_version, key_id, nonce, ciphertext, update_id,
        source_occurred_at, updated_at) ON reference_destinations TO kavach_runtime;

    EXECUTE format('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA %I TO kavach_runtime',
        current_schema());
END
$$ LANGUAGE plpgsql;

SELECT kavach_grant_runtime();

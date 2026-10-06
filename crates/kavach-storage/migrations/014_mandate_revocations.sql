-- R1 / ADR-012: revocation by signed system-of-record event.
--
-- A loan's live root mandates are found by the record their issuing event
-- named; each revoking event's result is kept (append-only), so the same
-- event again is answered with the same result and its id cannot be
-- reused for other content.

CREATE INDEX IF NOT EXISTS idx_mandates_live_roots_by_record
    ON mandates (tenant_id, source_system, (mandate -> 'source' ->> 'record_ref'))
    WHERE parent_id IS NULL AND status = 'active';

CREATE TABLE IF NOT EXISTS mandate_revocations (
    tenant_id TEXT NOT NULL,
    source_system TEXT NOT NULL,
    event_id TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    event_type TEXT NOT NULL,
    record_ref TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    revoked JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, source_system, event_id)
);

CREATE OR REPLACE TRIGGER mandate_revocations_append_only
    BEFORE UPDATE OR DELETE ON mandate_revocations
    FOR EACH ROW EXECUTE FUNCTION kavach_append_only();
CREATE OR REPLACE TRIGGER mandate_revocations_no_truncate
    BEFORE TRUNCATE ON mandate_revocations
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
        runtime_pointers, agent_evidence_chains, contact_counters TO kavach_runtime;
    GRANT SELECT, INSERT, UPDATE, DELETE ON replay_guard TO kavach_runtime;

    EXECUTE format('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA %I TO kavach_runtime',
        current_schema());
END
$$ LANGUAGE plpgsql;

SELECT kavach_grant_runtime();

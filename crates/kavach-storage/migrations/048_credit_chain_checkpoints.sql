-- ADR-005 §5: v1 credit decision-event checkpoints share the signed
-- checkpoint format/table while remaining a separate hash chain.
ALTER TABLE evidence_checkpoints
    DROP CONSTRAINT evidence_checkpoints_chain_check;
ALTER TABLE evidence_checkpoints
    ADD CONSTRAINT evidence_checkpoints_chain_check
    CHECK (chain IN ('agent_decisions', 'decision_events')) NOT VALID;
ALTER TABLE evidence_checkpoints
    VALIDATE CONSTRAINT evidence_checkpoints_chain_check;

-- The credit exporter must be able to retrieve signatures to copy them
-- off-host. The role remains SELECT-only and its agent-auditor counterpart
-- is unchanged.
CREATE OR REPLACE FUNCTION kavach_grant_credit_auditor() RETURNS void AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_roles WHERE rolname = 'kavach_credit_auditor'
    ) THEN
        RETURN;
    END IF;

    EXECUTE format('GRANT USAGE ON SCHEMA %I TO kavach_credit_auditor', current_schema());
    EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA %I FROM kavach_credit_auditor',
        current_schema());
    EXECUTE format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA %I FROM kavach_credit_auditor',
        current_schema());

    GRANT SELECT ON decision_events, evidence_chains, evidence_checkpoints
        TO kavach_credit_auditor;
END
$$ LANGUAGE plpgsql;

SELECT kavach_grant_credit_auditor();

-- ADR-005 §10: a separate offline reader for credit decision-event exports.
-- Keep `kavach_auditor` limited to the agent evidence surface.
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

    GRANT SELECT ON decision_events, evidence_chains TO kavach_credit_auditor;
END
$$ LANGUAGE plpgsql;

SELECT kavach_grant_credit_auditor();

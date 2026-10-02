-- E3a: a read-only role for evidence export (ADR-005 §13).
--
-- `kavach_auditor` may read the agent evidence tables and nothing else:
-- no writes anywhere, and no access to mandates, counters, audit or
-- governance tables. The export command connects as this role, so an
-- export cannot change what it reads.
--
-- As with kavach_runtime (009), the role itself is created by the
-- operator; this only grants. If the role is created after migrations
-- ran, grant it with: SELECT kavach_grant_auditor();

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
        agent_evidence_chains TO kavach_auditor;
END
$$ LANGUAGE plpgsql;

SELECT kavach_grant_auditor();

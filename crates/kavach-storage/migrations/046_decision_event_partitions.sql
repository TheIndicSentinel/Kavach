-- ADR-005 §3: give the existing v1 decision-event chain partition/sequence
-- coordinates without changing any hashed event field or hash.
ALTER TABLE decision_events
    ADD COLUMN partition_id INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN seq BIGINT;

CREATE TEMP TABLE decision_event_sequence_backfill ON COMMIT DROP AS
WITH RECURSIVE chain_walk AS (
    SELECT de.tenant_id, de.evidence_id, de.hash, 1::BIGINT AS seq,
           ARRAY[de.hash]::TEXT[] AS seen_hashes
    FROM decision_events de
    WHERE de.prev_hash = repeat('0', 64)
    UNION ALL
    SELECT next_event.tenant_id, next_event.evidence_id, next_event.hash,
           chain_walk.seq + 1, chain_walk.seen_hashes || next_event.hash
    FROM chain_walk
    JOIN decision_events next_event
      ON next_event.tenant_id = chain_walk.tenant_id
     AND next_event.prev_hash = chain_walk.hash
    WHERE NOT next_event.hash = ANY(chain_walk.seen_hashes)
)
SELECT tenant_id, evidence_id, seq FROM chain_walk;

DO $migration$
BEGIN
    IF (SELECT count(*) FROM decision_event_sequence_backfill)
         <> (SELECT count(*) FROM decision_events)
       OR (SELECT count(DISTINCT evidence_id) FROM decision_event_sequence_backfill)
         <> (SELECT count(*) FROM decision_events) THEN
        RAISE EXCEPTION 'decision event chains are forked, cyclic, or disconnected; partition migration refused';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM evidence_chain_meta meta
        WHERE meta.id = 1
          AND meta.head_hash IS DISTINCT FROM COALESCE(
              (SELECT de.hash
               FROM decision_event_sequence_backfill numbered
               JOIN decision_events de USING (tenant_id, evidence_id)
               WHERE numbered.tenant_id = meta.tenant_id
               ORDER BY numbered.seq DESC LIMIT 1),
              repeat('0', 64))
    ) THEN
        RAISE EXCEPTION 'decision event chain head does not match its records; partition migration refused';
    END IF;

    IF EXISTS (
        SELECT 1 FROM decision_events de
        LEFT JOIN evidence_chain_meta meta ON meta.tenant_id = de.tenant_id AND meta.id = 1
        WHERE meta.tenant_id IS NULL
    ) THEN
        RAISE EXCEPTION 'decision event tenant has no chain head; partition migration refused';
    END IF;
END
$migration$;

UPDATE decision_events de
SET seq = numbered.seq
FROM decision_event_sequence_backfill numbered
WHERE numbered.tenant_id = de.tenant_id AND numbered.evidence_id = de.evidence_id;

ALTER TABLE decision_events ALTER COLUMN seq SET NOT NULL;
ALTER TABLE decision_events ADD CONSTRAINT decision_events_partition_seq_positive
    CHECK (partition_id >= 0 AND seq > 0) NOT VALID;
ALTER TABLE decision_events VALIDATE CONSTRAINT decision_events_partition_seq_positive;
ALTER TABLE decision_events ADD CONSTRAINT decision_events_tenant_partition_seq_key
    UNIQUE (tenant_id, partition_id, seq);

CREATE TABLE evidence_chains (
    tenant_id TEXT NOT NULL,
    partition_id INTEGER NOT NULL CHECK (partition_id >= 0),
    head_hash TEXT NOT NULL,
    head_seq BIGINT NOT NULL CHECK (head_seq >= 0),
    PRIMARY KEY (tenant_id, partition_id)
);

INSERT INTO evidence_chains (tenant_id, partition_id, head_hash, head_seq)
SELECT meta.tenant_id, 0, meta.head_hash, COALESCE(MAX(de.seq), 0)
FROM evidence_chain_meta meta
LEFT JOIN decision_events de
  ON de.tenant_id = meta.tenant_id AND de.partition_id = 0
WHERE meta.id = 1
GROUP BY meta.tenant_id, meta.head_hash;

-- Protect and fence the newly writable chain-head table using the existing
-- active-lease guard. The active API writer alone may advance it.
CREATE TRIGGER kavach_active_write_guard
BEFORE INSERT OR UPDATE OR DELETE ON evidence_chains
FOR EACH ROW EXECUTE FUNCTION kavach_guard_active_write();

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
        batch_jobs, change_requests,
        mandates, model_state, runtime_pointers, agent_evidence_chains,
        contact_counters, agent_states, principals TO kavach_runtime;
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
SELECT kavach_assert_active_write_guards();

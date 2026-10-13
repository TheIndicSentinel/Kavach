-- K1-2 / ADR-013 §4: every change of an agent's state is a signed record in
-- the agent evidence chain, and the changes have a history of their own.
--
-- Stopping must never wait on the evidence chain, so a tightening changes the
-- state first and its record follows (written by the reconciler if not at
-- once). The reconciler needs every change, not only the latest: A then B
-- then C must leave three records. So: an append-only history of changes,
-- each with a per-agent change number, and at most one record per change.
--
-- Constraints on existing tables are added NOT VALID and then VALIDATEd
-- (docs/MIGRATIONS.md).

-- The note is the operator's free text and is optional now (the closed
-- reason code is what the chain carries).
ALTER TABLE agent_states
    ADD COLUMN IF NOT EXISTS change_no BIGINT NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS reason_code TEXT NOT NULL DEFAULT 'other';
ALTER TABLE agent_states DROP CONSTRAINT IF EXISTS agent_states_reason_present;
ALTER TABLE agent_states
    ADD CONSTRAINT agent_states_note_short CHECK (length(reason) <= 256) NOT VALID,
    ADD CONSTRAINT agent_states_reason_code_known CHECK (reason_code IN (
        'rogue_behaviour', 'compromise_suspected', 'policy_violation',
        'customer_complaint', 'operator_request', 'reviewed', 'other')) NOT VALID,
    ADD CONSTRAINT agent_states_change_no_positive CHECK (change_no >= 1) NOT VALID;
ALTER TABLE agent_states VALIDATE CONSTRAINT agent_states_note_short;
ALTER TABLE agent_states VALIDATE CONSTRAINT agent_states_reason_code_known;
ALTER TABLE agent_states VALIDATE CONSTRAINT agent_states_change_no_positive;

CREATE TABLE IF NOT EXISTS agent_state_changes (
    tenant_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    change_no BIGINT NOT NULL,
    from_state TEXT NOT NULL,
    to_state TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    changed_by TEXT NOT NULL,
    approved_by TEXT,
    changed_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, agent_id, change_no),
    CONSTRAINT agent_state_changes_states_known CHECK (
        from_state IN ('active', 'restricted', 'quarantined', 'revoked')
        AND to_state IN ('active', 'restricted', 'quarantined', 'revoked')),
    CONSTRAINT agent_state_changes_is_a_change CHECK (from_state <> to_state),
    CONSTRAINT agent_state_changes_revoked_is_final CHECK (from_state <> 'revoked'),
    CONSTRAINT agent_state_changes_reason_code_known CHECK (reason_code IN (
        'rogue_behaviour', 'compromise_suspected', 'policy_violation',
        'customer_complaint', 'operator_request', 'reviewed', 'other')),
    CONSTRAINT agent_state_changes_note_short CHECK (length(note) <= 256),
    CONSTRAINT agent_state_changes_change_no_positive CHECK (change_no >= 1),
    CONSTRAINT agent_state_changes_approver_differs
        CHECK (approved_by IS NULL OR approved_by <> changed_by),
    -- Loosening (to a lower severity) has an approver; tightening has none.
    CONSTRAINT agent_state_changes_approval_matches_direction CHECK (
        (approved_by IS NOT NULL) = (
            (from_state = 'restricted' AND to_state = 'active')
            OR (from_state = 'quarantined' AND to_state IN ('active', 'restricted'))
        ))
);

CREATE OR REPLACE TRIGGER agent_state_changes_append_only
    BEFORE UPDATE OR DELETE ON agent_state_changes
    FOR EACH ROW EXECUTE FUNCTION kavach_append_only();
CREATE OR REPLACE TRIGGER agent_state_changes_no_truncate
    BEFORE TRUNCATE ON agent_state_changes
    FOR EACH STATEMENT EXECUTE FUNCTION kavach_append_only();

-- The reconciler pages through changes in time order.
CREATE INDEX IF NOT EXISTS agent_state_changes_by_time
    ON agent_state_changes (changed_at, tenant_id, agent_id, change_no);

-- A change that a K1-1 row stands for (the table had no surface to write
-- more than one): one history entry from `active`.
INSERT INTO agent_state_changes (tenant_id, agent_id, change_no, from_state, to_state,
        reason_code, note, changed_by, approved_by, changed_at)
    SELECT s.tenant_id, s.agent_id, s.change_no, 'active', s.state, s.reason_code, s.reason,
           s.changed_by, NULL, s.changed_at
    FROM agent_states s
    WHERE s.state <> 'active'
    ON CONFLICT DO NOTHING;

-- The chain holds a third kind of record.
ALTER TABLE agent_decisions DROP CONSTRAINT IF EXISTS agent_records_kind_known;
ALTER TABLE agent_decisions
    ADD CONSTRAINT agent_records_kind_known
        CHECK (kind IN ('agent_decision', 'mandate_revocation', 'agent_state')) NOT VALID;
ALTER TABLE agent_decisions VALIDATE CONSTRAINT agent_records_kind_known;

-- What identifies an agent-state record: the agent and its change number.
ALTER TABLE agent_decisions ADD COLUMN IF NOT EXISTS state_change_no BIGINT;
ALTER TABLE agent_decisions
    ADD CONSTRAINT agent_records_state_fields CHECK (
        kind <> 'agent_state' OR (
            agent_id IS NOT NULL AND state_change_no IS NOT NULL
            AND request_id IS NULL AND binding IS NULL AND returned_decision IS NULL
            AND credential_id IS NULL AND source_system IS NULL AND event_id IS NULL
        )) NOT VALID,
    ADD CONSTRAINT agent_records_change_no_only_for_states CHECK (
        kind = 'agent_state' OR state_change_no IS NULL) NOT VALID;
ALTER TABLE agent_decisions VALIDATE CONSTRAINT agent_records_state_fields;
ALTER TABLE agent_decisions VALIDATE CONSTRAINT agent_records_change_no_only_for_states;

-- One record per change (written once, also by the reconciler).
CREATE UNIQUE INDEX IF NOT EXISTS agent_records_one_per_state_change
    ON agent_decisions (tenant_id, agent_id, state_change_no)
    WHERE kind = 'agent_state';

CREATE OR REPLACE FUNCTION kavach_grant_runtime() RETURNS void AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kavach_runtime') THEN
        RETURN;
    END IF;
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO kavach_runtime', current_schema());
    EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA %I FROM kavach_runtime', current_schema());

    GRANT SELECT, INSERT ON admin_audit_log, decision_events, evaluate_incidents,
        evidence_tombstones, agent_decisions, agent_outcomes, evidence_checkpoints,
        mandate_revocations, agent_state_changes
        TO kavach_runtime;
    GRANT SELECT, UPDATE ON evidence_chain_meta, tenant_settings TO kavach_runtime;
    GRANT SELECT, INSERT, UPDATE ON batch_jobs, change_requests, mandates, model_state,
        runtime_pointers, agent_evidence_chains, contact_counters, agent_states
        TO kavach_runtime;
    GRANT SELECT, INSERT, UPDATE, DELETE ON replay_guard TO kavach_runtime;

    EXECUTE format('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA %I TO kavach_runtime',
        current_schema());
END
$$ LANGUAGE plpgsql;

SELECT kavach_grant_runtime();

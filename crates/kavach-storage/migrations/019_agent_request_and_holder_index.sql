-- K1-3: a reinstatement is carried out by a change request (ADR-009), and the
-- state row and its history say which, so a retried approval can tell its
-- own change from another's. And revoking an agent finds the mandates it
-- holds without scanning the table.
--
-- Nullable columns with no default: no row is rewritten, no trigger fires.

ALTER TABLE agent_states ADD COLUMN IF NOT EXISTS change_request_id TEXT;
ALTER TABLE agent_state_changes ADD COLUMN IF NOT EXISTS change_request_id TEXT;

ALTER TABLE agent_states
    ADD CONSTRAINT agent_states_change_request_id_short
        CHECK (change_request_id IS NULL OR length(change_request_id) BETWEEN 1 AND 128)
        NOT VALID;
ALTER TABLE agent_states VALIDATE CONSTRAINT agent_states_change_request_id_short;
ALTER TABLE agent_state_changes
    ADD CONSTRAINT agent_state_changes_change_request_id_short
        CHECK (change_request_id IS NULL OR length(change_request_id) BETWEEN 1 AND 128)
        NOT VALID;
ALTER TABLE agent_state_changes
    VALIDATE CONSTRAINT agent_state_changes_change_request_id_short;

CREATE INDEX IF NOT EXISTS idx_mandates_active_by_holder
    ON mandates (tenant_id, (mandate ->> 'holder'))
    WHERE status = 'active';

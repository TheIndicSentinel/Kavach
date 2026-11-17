-- PRD D17 / FR-6: durable, tenant-scoped, exact-action review decisions.
-- Approval rows are immutable except for the one transition that consumes
-- the approved record. No action details are written to the evidence chain.
CREATE TABLE IF NOT EXISTS human_review_approvals (
    tenant_id TEXT NOT NULL,
    approval_id TEXT NOT NULL,
    action_hash TEXT NOT NULL,
    rendered_action TEXT NOT NULL,
    approver TEXT NOT NULL,
    step_up_ref TEXT NOT NULL,
    decision TEXT NOT NULL,
    single_use_credential_id TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, approval_id)
);

ALTER TABLE human_review_approvals
    ADD CONSTRAINT human_review_approvals_action_hash_format
    CHECK (action_hash ~ '^sha256-action-v1:[0-9a-f]{64}$') NOT VALID;
ALTER TABLE human_review_approvals
    VALIDATE CONSTRAINT human_review_approvals_action_hash_format;

ALTER TABLE human_review_approvals
    ADD CONSTRAINT human_review_approvals_decision_known
    CHECK (decision IN ('approve', 'reject')) NOT VALID;
ALTER TABLE human_review_approvals
    VALIDATE CONSTRAINT human_review_approvals_decision_known;

ALTER TABLE human_review_approvals
    ADD CONSTRAINT human_review_approvals_credential_matches_decision
    CHECK (
        (decision = 'approve' AND single_use_credential_id IS NOT NULL
            AND single_use_credential_id <> '')
        OR (decision = 'reject' AND single_use_credential_id IS NULL)
    ) NOT VALID;
ALTER TABLE human_review_approvals
    VALIDATE CONSTRAINT human_review_approvals_credential_matches_decision;

CREATE UNIQUE INDEX IF NOT EXISTS human_review_approvals_credential_id_unique
    ON human_review_approvals (single_use_credential_id)
    WHERE single_use_credential_id IS NOT NULL;

CREATE OR REPLACE FUNCTION human_review_approvals_guard() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'human review approvals cannot be deleted';
    END IF;
    IF OLD.consumed_at IS NOT NULL OR NEW.consumed_at IS NULL
        OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.approval_id IS DISTINCT FROM OLD.approval_id
        OR NEW.action_hash IS DISTINCT FROM OLD.action_hash
        OR NEW.rendered_action IS DISTINCT FROM OLD.rendered_action
        OR NEW.approver IS DISTINCT FROM OLD.approver
        OR NEW.step_up_ref IS DISTINCT FROM OLD.step_up_ref
        OR NEW.decision IS DISTINCT FROM OLD.decision
        OR NEW.single_use_credential_id IS DISTINCT FROM OLD.single_use_credential_id
        OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
        RAISE EXCEPTION 'human review approval is immutable except for one-time consumption';
    END IF;
    RETURN NEW;
END
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER human_review_approvals_guard
    BEFORE UPDATE OR DELETE ON human_review_approvals
    FOR EACH ROW EXECUTE FUNCTION human_review_approvals_guard();

CREATE OR REPLACE FUNCTION human_review_approvals_no_truncate() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'human review approvals cannot be truncated';
END
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER human_review_approvals_no_truncate
    BEFORE TRUNCATE ON human_review_approvals
    FOR EACH STATEMENT EXECUTE FUNCTION human_review_approvals_no_truncate();

-- `consume` is a single UPDATE under the runtime role. It can only set the
-- consumption timestamp, exactly once. The approver and action details stay
-- readable to the runtime for the authorization/credential handoff.
CREATE OR REPLACE FUNCTION kavach_grant_runtime() RETURNS void AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kavach_runtime') THEN
        RETURN;
    END IF;
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO kavach_runtime', current_schema());
    EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA %I FROM kavach_runtime', current_schema());

    GRANT SELECT, INSERT ON admin_audit_log, decision_events, evaluate_incidents,
        evidence_tombstones, agent_decisions, agent_outcomes, evidence_checkpoints,
        mandate_revocations, agent_state_changes, agent_outcome_resolutions
        TO kavach_runtime;
    GRANT SELECT, UPDATE ON evidence_chain_meta, tenant_settings TO kavach_runtime;
    GRANT SELECT, INSERT, UPDATE ON batch_jobs, change_requests, mandates, model_state,
        runtime_pointers, agent_evidence_chains, contact_counters, agent_states, principals
        TO kavach_runtime;
    GRANT SELECT, INSERT ON role_bindings TO kavach_runtime;
    GRANT UPDATE (ended_at, ended_by_change_request) ON role_bindings TO kavach_runtime;
    GRANT SELECT, INSERT ON human_review_approvals TO kavach_runtime;
    GRANT UPDATE (consumed_at) ON human_review_approvals TO kavach_runtime;
    GRANT SELECT, INSERT, UPDATE, DELETE ON replay_guard TO kavach_runtime;

    EXECUTE format('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA %I TO kavach_runtime',
        current_schema());
END
$$ LANGUAGE plpgsql;

SELECT kavach_grant_runtime();

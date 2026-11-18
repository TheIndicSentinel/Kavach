-- D17 release transition (ADR-003 approved amendment, 2026-11-18): preserve
-- the original action digest/request id and give release a separate execution
-- id. The approval is consumed atomically with an append-only release row.

ALTER TABLE human_review_approvals
    ADD COLUMN review_record_id TEXT,
    ADD COLUMN execution_id TEXT;

ALTER TABLE human_review_approvals
    ADD CONSTRAINT human_review_approvals_release_ids_valid CHECK (
        (review_record_id IS NULL AND execution_id IS NULL)
        OR (review_record_id IS NOT NULL AND review_record_id <> ''
            AND length(review_record_id) <= 256
            AND ((decision = 'approve' AND execution_id ~ '^[A-Za-z0-9_-]{1,128}$')
                OR (decision = 'reject' AND execution_id IS NULL)))
    ) NOT VALID;
ALTER TABLE human_review_approvals
    VALIDATE CONSTRAINT human_review_approvals_release_ids_valid;

-- Keep the new binding fields immutable during the one permitted consumed_at
-- transition, including for owner-role maintenance paths.
CREATE OR REPLACE FUNCTION human_review_approvals_guard() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'human review approvals cannot be deleted';
    END IF;
    IF OLD.consumed_at IS NOT NULL OR NEW.consumed_at IS NULL
        OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.approval_id IS DISTINCT FROM OLD.approval_id
        OR NEW.review_record_id IS DISTINCT FROM OLD.review_record_id
        OR NEW.execution_id IS DISTINCT FROM OLD.execution_id
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

CREATE UNIQUE INDEX human_review_approvals_execution_id_unique
    ON human_review_approvals (tenant_id, execution_id)
    WHERE execution_id IS NOT NULL;

CREATE TABLE human_review_releases (
    tenant_id TEXT NOT NULL,
    execution_id TEXT NOT NULL,
    approval_id TEXT NOT NULL,
    review_record_id TEXT NOT NULL,
    action_hash TEXT NOT NULL,
    approver TEXT NOT NULL,
    released_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, execution_id),
    UNIQUE (tenant_id, approval_id),
    FOREIGN KEY (tenant_id, approval_id)
        REFERENCES human_review_approvals (tenant_id, approval_id),
    CHECK (execution_id ~ '^[A-Za-z0-9_-]{1,128}$'),
    CHECK (review_record_id <> '' AND length(review_record_id) <= 256),
    CHECK (action_hash ~ '^sha256-action-v1:[0-9a-f]{64}$'),
    CHECK (approver <> '')
);

CREATE OR REPLACE FUNCTION human_review_releases_guard() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'human review releases are append-only';
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER human_review_releases_guard
    BEFORE UPDATE OR DELETE ON human_review_releases
    FOR EACH ROW EXECUTE FUNCTION human_review_releases_guard();

CREATE OR REPLACE FUNCTION human_review_releases_no_truncate() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'human review releases cannot be truncated';
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER human_review_releases_no_truncate
    BEFORE TRUNCATE ON human_review_releases
    FOR EACH STATEMENT EXECUTE FUNCTION human_review_releases_no_truncate();

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
    GRANT SELECT, INSERT, UPDATE, DELETE ON replay_guard TO kavach_runtime;

    EXECUTE format('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA %I TO kavach_runtime',
        current_schema());
END
$$ LANGUAGE plpgsql;

SELECT kavach_grant_runtime();

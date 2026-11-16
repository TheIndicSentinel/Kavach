-- ADR-019: operator roles. Who has been seen signing in (`principals`), and
-- which role is bound to which person or IdP group (`role_bindings`), per
-- tenant. A binding is created and ended only by an approved change request
-- (or, for the first two superadmins, by the one-time bootstrap); ending one
-- sets `ended_at`, the row is never deleted, so the history stays.

-- Only what is needed to show a name next to a binding and to show that a
-- bound person has not been seen: no email, no groups, no token.
CREATE TABLE IF NOT EXISTS principals (
    tenant_id TEXT NOT NULL,
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    -- The configured principal claim's value (the audit's display id).
    display_name TEXT NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, issuer, subject)
);

CREATE TABLE IF NOT EXISTS role_bindings (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    role TEXT NOT NULL,
    -- `principal`: `subject` is the OIDC subject. `group`: `subject` is a
    -- group name from the token's groups claim.
    subject_kind TEXT NOT NULL,
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    -- NULL only for a bootstrap binding.
    granted_by_change_request TEXT,
    granted_at TIMESTAMPTZ NOT NULL,
    ended_by_change_request TEXT,
    ended_at TIMESTAMPTZ
);

-- Constraints are added NOT VALID, then validated (MIGRATIONS.md rule 4),
-- even though the table is new.
ALTER TABLE role_bindings DROP CONSTRAINT IF EXISTS role_bindings_role_known;
ALTER TABLE role_bindings
    ADD CONSTRAINT role_bindings_role_known CHECK (role IN (
        'superadmin', 'user_admin', 'policy_admin', 'approver', 'operator', 'auditor', 'viewer'
    )) NOT VALID;
ALTER TABLE role_bindings VALIDATE CONSTRAINT role_bindings_role_known;

ALTER TABLE role_bindings DROP CONSTRAINT IF EXISTS role_bindings_subject_kind_known;
ALTER TABLE role_bindings
    ADD CONSTRAINT role_bindings_subject_kind_known
    CHECK (subject_kind IN ('principal', 'group')) NOT VALID;
ALTER TABLE role_bindings VALIDATE CONSTRAINT role_bindings_subject_kind_known;

-- Never ended before it was granted, and never named as ended by a change
-- request without being ended. An end with no change request is the
-- database operator's recovery when every superadmin is gone (INSTALL.md).
ALTER TABLE role_bindings DROP CONSTRAINT IF EXISTS role_bindings_end_consistent;
ALTER TABLE role_bindings
    ADD CONSTRAINT role_bindings_end_consistent CHECK (
        (ended_at IS NULL AND ended_by_change_request IS NULL)
        OR (ended_at IS NOT NULL AND ended_at >= granted_at)
    ) NOT VALID;
ALTER TABLE role_bindings VALIDATE CONSTRAINT role_bindings_end_consistent;

ALTER TABLE role_bindings DROP CONSTRAINT IF EXISTS role_bindings_granted_by_fk;
ALTER TABLE role_bindings
    ADD CONSTRAINT role_bindings_granted_by_fk
    FOREIGN KEY (granted_by_change_request) REFERENCES change_requests (id) NOT VALID;
ALTER TABLE role_bindings VALIDATE CONSTRAINT role_bindings_granted_by_fk;

ALTER TABLE role_bindings DROP CONSTRAINT IF EXISTS role_bindings_ended_by_fk;
ALTER TABLE role_bindings
    ADD CONSTRAINT role_bindings_ended_by_fk
    FOREIGN KEY (ended_by_change_request) REFERENCES change_requests (id) NOT VALID;
ALTER TABLE role_bindings VALIDATE CONSTRAINT role_bindings_ended_by_fk;

-- One active binding per role and subject.
CREATE UNIQUE INDEX IF NOT EXISTS role_bindings_one_active
    ON role_bindings (tenant_id, role, subject_kind, issuer, subject)
    WHERE ended_at IS NULL;
-- The per-request lookup: a principal's and its groups' active bindings.
CREATE INDEX IF NOT EXISTS role_bindings_active_by_subject
    ON role_bindings (tenant_id, issuer, subject_kind, subject)
    WHERE ended_at IS NULL;

-- ADR-019 §7: set when a decision was allowed only by a superadmin policy.
-- Nullable with no default, so nothing is rewritten and the append-only
-- trigger is untouched; rows written before this migration read as NULL.
ALTER TABLE admin_audit_log ADD COLUMN IF NOT EXISTS acting_as_superadmin BOOLEAN;

-- The runtime role reads and writes principals (sign-in upserts them), and
-- reads, inserts and ends role bindings: UPDATE on the two end columns
-- only, no DELETE. The auditor role is unchanged.
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
    GRANT SELECT, INSERT, UPDATE, DELETE ON replay_guard TO kavach_runtime;

    EXECUTE format('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA %I TO kavach_runtime',
        current_schema());
END
$$ LANGUAGE plpgsql;

SELECT kavach_grant_runtime();

-- PRD D17: durable, one-use server-side OIDC step-up challenge context.
-- Raw OAuth state and nonce values are not stored; only their SHA-256 digests
-- are retained. Expired rows can be purged to bound reviewer-data retention.
CREATE TABLE IF NOT EXISTS human_review_step_up_challenges (
    challenge_id TEXT NOT NULL,
    state_hash TEXT PRIMARY KEY,
    nonce_hash TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    principal_key TEXT NOT NULL,
    action_hash TEXT NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    CONSTRAINT human_review_step_up_challenges_id_unique UNIQUE (challenge_id),
    CONSTRAINT human_review_step_up_challenges_identity_valid
        CHECK (challenge_id <> '' AND length(challenge_id) <= 128
            AND tenant_id <> '' AND principal_key <> ''),
    CONSTRAINT human_review_step_up_challenges_state_hash_format
        CHECK (state_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT human_review_step_up_challenges_nonce_hash_format
        CHECK (nonce_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT human_review_step_up_challenges_action_hash_format
        CHECK (action_hash ~ '^sha256-action-v1:[0-9a-f]{64}$'),
    CONSTRAINT human_review_step_up_challenges_lifetime_valid
        CHECK (expires_at > issued_at),
    CONSTRAINT human_review_step_up_challenges_consumed_valid
        CHECK (consumed_at IS NULL OR (consumed_at >= issued_at AND consumed_at < expires_at))
);

CREATE OR REPLACE FUNCTION human_review_step_up_challenges_guard() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.expires_at > clock_timestamp() THEN
            RAISE EXCEPTION 'live step-up challenges cannot be deleted';
        END IF;
        RETURN OLD;
    END IF;
    IF OLD.consumed_at IS NOT NULL OR NEW.consumed_at IS NULL
        OR NEW.challenge_id IS DISTINCT FROM OLD.challenge_id
        OR NEW.state_hash IS DISTINCT FROM OLD.state_hash
        OR NEW.nonce_hash IS DISTINCT FROM OLD.nonce_hash
        OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.principal_key IS DISTINCT FROM OLD.principal_key
        OR NEW.action_hash IS DISTINCT FROM OLD.action_hash
        OR NEW.issued_at IS DISTINCT FROM OLD.issued_at
        OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
        RAISE EXCEPTION 'step-up challenge is immutable except for one-time consumption';
    END IF;
    RETURN NEW;
END
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER human_review_step_up_challenges_guard
    BEFORE UPDATE OR DELETE ON human_review_step_up_challenges
    FOR EACH ROW EXECUTE FUNCTION human_review_step_up_challenges_guard();

CREATE OR REPLACE FUNCTION human_review_step_up_challenges_no_truncate() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'step-up challenge history cannot be truncated';
END
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER human_review_step_up_challenges_no_truncate
    BEFORE TRUNCATE ON human_review_step_up_challenges
    FOR EACH STATEMENT EXECUTE FUNCTION human_review_step_up_challenges_no_truncate();

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kavach_runtime') THEN
        RETURN;
    END IF;
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO kavach_runtime', current_schema());
    GRANT SELECT, INSERT ON human_review_step_up_challenges TO kavach_runtime;
    GRANT UPDATE (consumed_at) ON human_review_step_up_challenges TO kavach_runtime;
    GRANT DELETE ON human_review_step_up_challenges TO kavach_runtime;
END
$$;

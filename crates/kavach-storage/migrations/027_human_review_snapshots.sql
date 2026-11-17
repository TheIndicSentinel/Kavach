-- PRD D17: encrypted, tenant-scoped exact-action display projections.
-- Plaintext action fields must never be stored in this table.
CREATE TABLE IF NOT EXISTS human_review_snapshots (
    tenant_id TEXT NOT NULL,
    record_id TEXT NOT NULL,
    action_hash TEXT NOT NULL,
    key_id TEXT NOT NULL,
    version SMALLINT NOT NULL,
    nonce BYTEA NOT NULL,
    ciphertext BYTEA NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, record_id),
    CONSTRAINT human_review_snapshots_identity_valid
        CHECK (tenant_id <> '' AND record_id <> '' AND key_id <> '' AND length(key_id) <= 128),
    CONSTRAINT human_review_snapshots_action_hash_format
        CHECK (action_hash ~ '^sha256-action-v1:[0-9a-f]{64}$'),
    CONSTRAINT human_review_snapshots_version_supported
        CHECK (version = 1),
    CONSTRAINT human_review_snapshots_nonce_size
        CHECK (octet_length(nonce) = 12),
    CONSTRAINT human_review_snapshots_ciphertext_size
        CHECK (octet_length(ciphertext) BETWEEN 16 AND 65552)
);

CREATE INDEX IF NOT EXISTS human_review_snapshots_expiry_idx
    ON human_review_snapshots (expires_at);

CREATE OR REPLACE FUNCTION human_review_snapshots_guard() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.expires_at > clock_timestamp() THEN
            RAISE EXCEPTION 'live review snapshots cannot be deleted';
        END IF;
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'review snapshots are immutable';
END
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER human_review_snapshots_guard
    BEFORE UPDATE OR DELETE ON human_review_snapshots
    FOR EACH ROW EXECUTE FUNCTION human_review_snapshots_guard();

CREATE OR REPLACE FUNCTION human_review_snapshots_no_truncate() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'review snapshot history cannot be truncated';
END
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER human_review_snapshots_no_truncate
    BEFORE TRUNCATE ON human_review_snapshots
    FOR EACH STATEMENT EXECUTE FUNCTION human_review_snapshots_no_truncate();

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kavach_runtime') THEN
        RETURN;
    END IF;
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO kavach_runtime', current_schema());
    GRANT SELECT, INSERT, DELETE ON human_review_snapshots TO kavach_runtime;
END
$$;

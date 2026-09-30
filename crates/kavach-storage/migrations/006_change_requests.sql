-- H3a: maker-checker change requests (ADR-009).

-- Monotonic version of the governed runtime pointer; every write increments it.
-- Change requests bind to the version seen at proposal (optimistic concurrency).
ALTER TABLE runtime_pointers ADD COLUMN IF NOT EXISTS version BIGINT NOT NULL DEFAULT 1;

CREATE TABLE IF NOT EXISTS change_requests (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    kind TEXT NOT NULL,
    params JSONB NOT NULL,
    binding JSONB NOT NULL,
    change_digest TEXT NOT NULL,
    reason TEXT,
    proposer TEXT NOT NULL,
    proposer_key TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'applied', 'failed', 'rejected', 'cancelled', 'expired')),
    decided_by TEXT,
    decided_by_key TEXT,
    outcome JSONB,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    decided_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_change_requests_status_created
    ON change_requests (tenant_id, status, created_at DESC);

-- Decided requests are immutable, and no request is ever deleted.
CREATE OR REPLACE FUNCTION change_requests_guard() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'change requests cannot be deleted';
    END IF;
    IF OLD.status <> 'pending' THEN
        RAISE EXCEPTION 'change request % is already %', OLD.id, OLD.status;
    END IF;
    IF NEW.id <> OLD.id OR NEW.kind <> OLD.kind OR NEW.params <> OLD.params
        OR NEW.binding <> OLD.binding OR NEW.change_digest <> OLD.change_digest
        OR NEW.proposer_key <> OLD.proposer_key OR NEW.created_at <> OLD.created_at
        OR NEW.expires_at <> OLD.expires_at OR NEW.tenant_id <> OLD.tenant_id THEN
        RAISE EXCEPTION 'change request % fields are immutable', OLD.id;
    END IF;
    RETURN NEW;
END
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER change_requests_guard
    BEFORE UPDATE OR DELETE ON change_requests
    FOR EACH ROW EXECUTE FUNCTION change_requests_guard();

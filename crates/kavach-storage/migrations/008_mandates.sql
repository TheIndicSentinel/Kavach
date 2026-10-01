-- H5a: Postgres mandate store and replay guard (ADR-004, ADR-011).

CREATE TABLE IF NOT EXISTS mandates (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    parent_id TEXT,
    depth SMALLINT NOT NULL CHECK (depth >= 0),
    status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
    revoked_reason TEXT,
    token TEXT NOT NULL,
    mandate JSONB NOT NULL,
    source_system TEXT NOT NULL,
    source_event_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, parent_id) REFERENCES mandates (tenant_id, id),
    CHECK ((parent_id IS NULL) = (depth = 0))
);

-- One root mandate per system-of-record event: a second barrier behind the
-- replay guard (children inherit the parent's source).
CREATE UNIQUE INDEX IF NOT EXISTS idx_mandates_root_source
    ON mandates (tenant_id, source_system, source_event_id)
    WHERE parent_id IS NULL;

CREATE INDEX IF NOT EXISTS idx_mandates_parent ON mandates (tenant_id, parent_id);

CREATE TABLE IF NOT EXISTS replay_guard (
    tenant_id TEXT NOT NULL,
    key TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, key)
);

CREATE INDEX IF NOT EXISTS idx_replay_guard_expiry ON replay_guard (expires_at);

CREATE TABLE IF NOT EXISTS runtime_pointers (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    pack_path TEXT NOT NULL,
    model_path TEXT NOT NULL,
    previous_pack_path TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by TEXT NOT NULL,
    approved_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS admin_audit_log (
    id BIGSERIAL PRIMARY KEY,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    actor_principal TEXT NOT NULL,
    approver_principal TEXT NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_admin_audit_log_created_at ON admin_audit_log (created_at DESC);

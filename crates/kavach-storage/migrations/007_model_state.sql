-- H3b: governed model record (ADR-010).

-- The runtime pointer is the single authority for which model file is active;
-- its digest is pinned here next to the pack's.
ALTER TABLE runtime_pointers ADD COLUMN IF NOT EXISTS model_sha256 TEXT;

-- Mutable model fields, changed only by approved change requests. Fixed
-- fields (schema, purpose, origin, ...) come from the pinned model YAML.
CREATE TABLE IF NOT EXISTS model_state (
    tenant_id TEXT NOT NULL DEFAULT 'default',
    model_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('draft', 'production', 'retired')),
    governance_mode TEXT NOT NULL CHECK (governance_mode IN ('shadow', 'enforce')),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by TEXT NOT NULL,
    approved_by TEXT NOT NULL,
    PRIMARY KEY (tenant_id, model_id)
);

CREATE TABLE IF NOT EXISTS tenant_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    evidence_retention_days INTEGER NOT NULL DEFAULT 365,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by TEXT,
    approved_by TEXT
);

INSERT INTO tenant_settings (id, evidence_retention_days)
VALUES (1, 365)
ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS evidence_tombstones (
    evidence_id TEXT PRIMARY KEY REFERENCES decision_events (evidence_id),
    reason TEXT NOT NULL,
    actor_principal TEXT NOT NULL,
    approver_principal TEXT NOT NULL,
    tombstoned_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_evidence_tombstones_at ON evidence_tombstones (tombstoned_at DESC);

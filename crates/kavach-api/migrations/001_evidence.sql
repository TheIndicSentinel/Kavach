CREATE TABLE IF NOT EXISTS evidence_chain_meta (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    head_hash TEXT NOT NULL
);

INSERT INTO evidence_chain_meta (id, head_hash)
VALUES (1, repeat('0', 64))
ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS decision_events (
    evidence_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE,
    schema_version TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL,
    pack_id TEXT NOT NULL,
    pack_version TEXT NOT NULL,
    sector TEXT NOT NULL,
    model_id TEXT NOT NULL,
    model_version TEXT NOT NULL,
    model_origin TEXT NOT NULL,
    governance_mode TEXT NOT NULL,
    policy_decision TEXT NOT NULL,
    returned_decision TEXT NOT NULL,
    reason_codes JSONB NOT NULL DEFAULT '[]',
    policy_hits JSONB NOT NULL DEFAULT '[]',
    pii_tokens JSONB NOT NULL DEFAULT '[]',
    input_digest TEXT NOT NULL,
    latency_ms BIGINT NOT NULL,
    decision_time TIMESTAMPTZ NOT NULL,
    evaluated_at TIMESTAMPTZ NOT NULL,
    service_identity_id TEXT NOT NULL,
    correlation_id TEXT NOT NULL,
    idempotency_key TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (model_id, correlation_id)
);

CREATE TABLE IF NOT EXISTS evaluate_incidents (
    id BIGSERIAL PRIMARY KEY,
    correlation_id TEXT NOT NULL,
    model_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_decision_events_created_at ON decision_events (created_at);

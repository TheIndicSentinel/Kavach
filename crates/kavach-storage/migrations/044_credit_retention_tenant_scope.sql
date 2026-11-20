-- ADR-014 §2.3 / ADR-005 §2: retain v1 event bytes and hashes while
-- attributing rows and singleton state to the serving tenant.
ALTER TABLE decision_events
    ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';

ALTER TABLE decision_events
    DROP CONSTRAINT decision_events_model_id_correlation_id_key;
ALTER TABLE decision_events
    DROP CONSTRAINT decision_events_event_id_key;
ALTER TABLE decision_events
    ADD CONSTRAINT decision_events_tenant_model_correlation_key
        UNIQUE (tenant_id, model_id, correlation_id);
ALTER TABLE decision_events
    ADD CONSTRAINT decision_events_tenant_event_id_key UNIQUE (tenant_id, event_id);
ALTER TABLE decision_events
    ADD CONSTRAINT decision_events_tenant_evidence_id_key
        UNIQUE (tenant_id, evidence_id);

ALTER TABLE evidence_chain_meta
    ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE evidence_chain_meta DROP CONSTRAINT evidence_chain_meta_pkey;
ALTER TABLE evidence_chain_meta ADD PRIMARY KEY (tenant_id, id);

ALTER TABLE tenant_settings
    ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE tenant_settings DROP CONSTRAINT tenant_settings_pkey;
ALTER TABLE tenant_settings ADD PRIMARY KEY (tenant_id, id);

ALTER TABLE evidence_tombstones
    ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE evidence_tombstones DROP CONSTRAINT evidence_tombstones_pkey;
ALTER TABLE evidence_tombstones ADD PRIMARY KEY (tenant_id, evidence_id);
ALTER TABLE evidence_tombstones
    DROP CONSTRAINT evidence_tombstones_evidence_id_fkey;
ALTER TABLE evidence_tombstones
    ADD CONSTRAINT evidence_tombstones_tenant_evidence_fkey
        FOREIGN KEY (tenant_id, evidence_id)
        REFERENCES decision_events (tenant_id, evidence_id) NOT VALID;
ALTER TABLE evidence_tombstones
    VALIDATE CONSTRAINT evidence_tombstones_tenant_evidence_fkey;

CREATE INDEX IF NOT EXISTS idx_decision_events_tenant_evaluated
    ON decision_events (tenant_id, evaluated_at, evidence_id);
CREATE INDEX IF NOT EXISTS idx_tombstones_tenant_at
    ON evidence_tombstones (tenant_id, tombstoned_at DESC);

-- New tenant chain heads and retention settings are created lazily by their
-- scoped stores. The active-write triggers from migration 040 already guard
-- both tables.
DO $migration$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kavach_runtime') THEN
        GRANT INSERT, SELECT, UPDATE ON evidence_chain_meta TO kavach_runtime;
        GRANT INSERT, SELECT, UPDATE ON tenant_settings TO kavach_runtime;
    END IF;
END
$migration$;

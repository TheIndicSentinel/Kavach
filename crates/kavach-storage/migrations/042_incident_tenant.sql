-- ADR-014 §2.3: attribute existing incident rows to the default tenant
-- without rewriting the append-oriented history.
ALTER TABLE evaluate_incidents
    ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';

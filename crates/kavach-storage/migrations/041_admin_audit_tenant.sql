-- ADR-014 §2.3: keep existing single-tenant audit history attributable to
-- the default tenant without updating the append-only table.
ALTER TABLE admin_audit_log
    ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';

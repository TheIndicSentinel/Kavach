-- ADR-014 §2.3 / ADR-005 §2: scope the active runtime baseline by tenant.
-- The existing pointer remains attributed to default without rewriting it.
ALTER TABLE runtime_pointers
    ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';

ALTER TABLE runtime_pointers DROP CONSTRAINT runtime_pointers_pkey;
ALTER TABLE runtime_pointers ADD PRIMARY KEY (tenant_id, id);

-- ADR-014 §2.3: attribute existing batch jobs to the default tenant without
-- rewriting their job state or file metadata.
ALTER TABLE batch_jobs
    ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';

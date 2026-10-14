-- S3 (ADR-012 addendum): an audit entry that is derived from stored state
-- (a revocation's entry, rebuilt from its row) is written at most once. NULL
-- for the entries that are written once by their own request; unique
-- indexes treat NULLs as distinct, so those are unaffected.
ALTER TABLE admin_audit_log ADD COLUMN IF NOT EXISTS idempotency_key TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS admin_audit_log_idempotency_key
    ON admin_audit_log (idempotency_key);

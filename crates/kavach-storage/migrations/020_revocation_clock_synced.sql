-- S4 (ADR-012 addendum): whether the clock was synchronised when a
-- revocation was applied. Additive and nullable: NULL is a row written
-- before this column existed (unknown). Not part of the evidence record
-- format; it is what the audit entry derived from the row says.
ALTER TABLE mandate_revocations ADD COLUMN IF NOT EXISTS clock_synced boolean;

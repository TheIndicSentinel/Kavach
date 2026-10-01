-- H5b-1f (step 8a): outcomes for "allowed but never sent" (not_executed)
-- and "sent, result not known" (unknown), and a signed reason code.
-- Existing rows keep their values; their reason stays NULL (v1 signatures).
-- The table stays append-only (010's triggers are unchanged).

ALTER TABLE agent_outcomes DROP CONSTRAINT IF EXISTS agent_outcomes_outcome_check;
ALTER TABLE agent_outcomes ADD CONSTRAINT agent_outcomes_outcome_check
    CHECK (outcome IN ('delivered', 'failed', 'refused', 'not_executed', 'unknown'));

ALTER TABLE agent_outcomes ADD COLUMN IF NOT EXISTS reason TEXT;
ALTER TABLE agent_outcomes DROP CONSTRAINT IF EXISTS agent_outcomes_reason_check;
ALTER TABLE agent_outcomes ADD CONSTRAINT agent_outcomes_reason_check
    CHECK (reason IS NULL OR reason ~ '^[a-z0-9_]{1,64}$');

-- D17: retain the signed/original request_id while deduplicating an approved
-- execution under its distinct server-issued execution_id.
--
-- agent_decisions is append-only (010): no UPDATE may backfill it. Rows
-- written before this migration keep idempotency_key NULL and stay keyed by
-- request_id, as under 015; the key below is
-- COALESCE(idempotency_key, request_id), so old and new rows share one
-- uniqueness domain.
ALTER TABLE agent_decisions
    ADD COLUMN idempotency_key TEXT;

-- Binds every row written from now on. Left NOT VALID on purpose: earlier
-- decisions carry NULL and cannot be rewritten, so VALIDATE would fail.
ALTER TABLE agent_decisions
    ADD CONSTRAINT agent_decisions_idempotency_key_valid CHECK (
        (kind = 'agent_decision' AND idempotency_key IS NOT NULL
            AND idempotency_key ~ '^[A-Za-z0-9._:-]{1,128}$')
        OR (kind <> 'agent_decision' AND idempotency_key IS NULL)
    ) NOT VALID;

DROP INDEX IF EXISTS agent_decisions_one_per_request;
CREATE UNIQUE INDEX agent_decisions_one_per_idempotency_key
    ON agent_decisions (tenant_id, agent_id, mode, (COALESCE(idempotency_key, request_id)))
    WHERE kind = 'agent_decision';

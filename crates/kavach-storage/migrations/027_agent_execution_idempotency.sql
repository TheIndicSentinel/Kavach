-- D17: retain the signed/original request_id while deduplicating an approved
-- execution under its distinct server-issued execution_id.
ALTER TABLE agent_decisions
    ADD COLUMN idempotency_key TEXT;

UPDATE agent_decisions
SET idempotency_key = request_id
WHERE kind = 'agent_decision';

ALTER TABLE agent_decisions
    ADD CONSTRAINT agent_decisions_idempotency_key_valid CHECK (
        (kind = 'agent_decision' AND idempotency_key IS NOT NULL
            AND idempotency_key ~ '^[A-Za-z0-9._:-]{1,128}$')
        OR (kind <> 'agent_decision' AND idempotency_key IS NULL)
    ) NOT VALID;
ALTER TABLE agent_decisions
    VALIDATE CONSTRAINT agent_decisions_idempotency_key_valid;

DROP INDEX IF EXISTS agent_decisions_one_per_request;
CREATE UNIQUE INDEX agent_decisions_one_per_idempotency_key
    ON agent_decisions (tenant_id, agent_id, mode, idempotency_key)
    WHERE kind = 'agent_decision';

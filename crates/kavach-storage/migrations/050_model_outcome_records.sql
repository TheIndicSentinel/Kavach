-- Approved model governance evidence: persist the signed result of an
-- invocation in the same agent evidence chain. Completion text is never stored.

ALTER TABLE agent_decisions DROP CONSTRAINT IF EXISTS agent_records_kind_known;
ALTER TABLE agent_decisions
    ADD CONSTRAINT agent_records_kind_known
        CHECK (kind IN (
            'agent_decision', 'mandate_revocation', 'agent_state',
            'model_invocation', 'model_outcome'
        )) NOT VALID;
ALTER TABLE agent_decisions VALIDATE CONSTRAINT agent_records_kind_known;

ALTER TABLE agent_decisions
    ADD CONSTRAINT agent_records_model_outcome_fields CHECK (
        kind <> 'model_outcome' OR (
            agent_id IS NOT NULL
            AND request_id IS NOT NULL
            AND binding IS NOT NULL
            AND returned_decision IS NULL
            AND credential_id IS NULL
            AND source_system IS NULL
            AND event_id IS NULL
            AND state_change_no IS NULL
            AND agent_id = payload ->> 'agent_id'
            AND request_id = payload ->> 'request_id'
            AND payload ->> 'kind' = 'model_outcome'
            AND payload ->> 'invocation_record_id' = binding ->> 'invocation_record_id'
            AND payload ->> 'invocation_hash' = binding ->> 'invocation_hash'
            AND payload ->> 'status' = binding ->> 'status'
            AND payload ->> 'duration_ms' = binding ->> 'duration_ms'
            AND payload ->> 'response_digest' IS NOT DISTINCT FROM binding ->> 'response_digest'
            AND payload ->> 'status' IN ('completed', 'failed', 'unknown')
            AND (
                (payload ->> 'status' = 'completed'
                    AND payload ->> 'response_digest' ~ '^[0-9a-f]{64}$')
                OR (payload ->> 'status' IN ('failed', 'unknown')
                    AND payload -> 'response_digest' = 'null'::jsonb)
            )
            AND jsonb_typeof(payload -> 'duration_ms') = 'number'
            AND (payload ->> 'duration_ms')::numeric BETWEEN 0 AND 4294967295
            AND (payload ->> 'duration_ms')::numeric = trunc((payload ->> 'duration_ms')::numeric)
            AND payload ->> 'invocation_hash' ~ '^[0-9a-f]{64}$'
        )
    ) NOT VALID;
ALTER TABLE agent_decisions
    VALIDATE CONSTRAINT agent_records_model_outcome_fields;

CREATE UNIQUE INDEX agent_records_one_model_outcome_per_request
    ON agent_decisions (tenant_id, agent_id, request_id)
    WHERE kind = 'model_outcome';

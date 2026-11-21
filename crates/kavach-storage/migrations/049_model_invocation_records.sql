-- Approved model governance evidence: the signed model_invocation record is
-- appended to the existing agent evidence chain before inference is enabled.
-- No prompt or completion text is stored in the row.

ALTER TABLE agent_decisions DROP CONSTRAINT IF EXISTS agent_records_kind_known;
ALTER TABLE agent_decisions
    ADD CONSTRAINT agent_records_kind_known
        CHECK (kind IN (
            'agent_decision', 'mandate_revocation', 'agent_state', 'model_invocation'
        )) NOT VALID;
ALTER TABLE agent_decisions VALIDATE CONSTRAINT agent_records_kind_known;

ALTER TABLE agent_decisions
    ADD CONSTRAINT agent_records_model_invocation_fields CHECK (
        kind <> 'model_invocation' OR (
            agent_id IS NOT NULL
            AND request_id IS NOT NULL
            AND binding IS NOT NULL
            AND returned_decision IS NOT NULL
            AND credential_id IS NULL
            AND source_system IS NULL
            AND event_id IS NULL
            AND state_change_no IS NULL
            AND agent_id = payload #>> '{actor,agent_id}'
            AND request_id = payload ->> 'request_id'
            AND returned_decision = payload ->> 'returned_decision'
            AND payload ->> 'kind' = 'model_invocation'
            AND payload ->> 'action' = CASE payload ->> 'model_role'
                WHEN 'collections' THEN 'invoke_collections_model'
                WHEN 'translation' THEN 'invoke_translation_model'
                ELSE NULL
            END
            AND payload ->> 'prompt_digest' ~ '^[0-9a-f]{64}$'
            AND payload ->> 'model_digest' ~ '^sha256:[0-9a-f]{64}$'
        )
    ) NOT VALID;
ALTER TABLE agent_decisions
    VALIDATE CONSTRAINT agent_records_model_invocation_fields;

CREATE UNIQUE INDEX agent_records_one_per_model_request
    ON agent_decisions (tenant_id, agent_id, request_id)
    WHERE kind = 'model_invocation';

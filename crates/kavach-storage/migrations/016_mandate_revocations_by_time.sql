-- R1b-2 (ADR-012 §7): the evidence reconciler pages through revocations in
-- time order to find any without its evidence-chain record. `created_at` is
-- the time Kavach revoked (`revoked_at`), written by the service from
-- trusted time.
CREATE INDEX IF NOT EXISTS mandate_revocations_by_time
    ON mandate_revocations (created_at, tenant_id, source_system, event_id);

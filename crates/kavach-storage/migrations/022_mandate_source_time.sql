-- B2 (ADR-012 addendum): the time the source system says the fact occurred
-- (the issuing event's occurred_at), kept with the root mandate so a
-- revocation is scoped by when things *happened*, not when Kavach processed
-- them. Nullable: NULL is a row written before this column, scoped by `nbf`
-- as before.
ALTER TABLE mandates ADD COLUMN IF NOT EXISTS source_occurred_at TIMESTAMPTZ;

-- Issuing is refused when the record is closed (a payment recorded at or
-- after the event, or a dispute): found by record.
CREATE INDEX IF NOT EXISTS mandate_revocations_by_record
    ON mandate_revocations (tenant_id, source_system, record_ref);

-- Consent withdrawals close the consent id to future mandate issuance.
CREATE INDEX mandate_revocations_consent_withdrawal
    ON mandate_revocations (tenant_id, record_ref)
    WHERE event_type = 'consent.withdrawn';

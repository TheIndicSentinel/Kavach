-- D17 release records retain the one-use credential identity minted by the
-- reviewer approval so the authorization/broker handoff can use that exact id.
ALTER TABLE human_review_releases
    ADD COLUMN single_use_credential_id TEXT;

UPDATE human_review_releases AS release
SET single_use_credential_id = approval.single_use_credential_id
FROM human_review_approvals AS approval
WHERE release.tenant_id = approval.tenant_id
  AND release.approval_id = approval.approval_id;

ALTER TABLE human_review_releases
    ALTER COLUMN single_use_credential_id SET NOT NULL,
    ADD CONSTRAINT human_review_releases_credential_id_valid
        CHECK (single_use_credential_id ~ '^[A-Za-z0-9_-]{1,128}$')
        NOT VALID;
ALTER TABLE human_review_releases
    VALIDATE CONSTRAINT human_review_releases_credential_id_valid;

CREATE UNIQUE INDEX human_review_releases_credential_id_unique
    ON human_review_releases (single_use_credential_id);

-- Runtime inserts must correspond to an approval already consumed in this
-- same transaction. This prevents a direct table insert from fabricating a
-- release or substituting a different credential id.
CREATE OR REPLACE FUNCTION human_review_releases_insert_guard() RETURNS trigger AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM human_review_approvals AS approval
        WHERE approval.tenant_id = NEW.tenant_id
          AND approval.approval_id = NEW.approval_id
          AND approval.review_record_id = NEW.review_record_id
          AND approval.execution_id = NEW.execution_id
          AND approval.action_hash = NEW.action_hash
          AND approval.single_use_credential_id = NEW.single_use_credential_id
          AND approval.approver = NEW.approver
          AND approval.decision = 'approve'
          AND approval.consumed_at = NEW.released_at
          AND approval.expires_at > NEW.released_at
    ) THEN
        RAISE EXCEPTION 'human review release must match a consumed approval';
    END IF;
    RETURN NEW;
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER human_review_releases_insert_guard
    BEFORE INSERT ON human_review_releases
    FOR EACH ROW EXECUTE FUNCTION human_review_releases_insert_guard();

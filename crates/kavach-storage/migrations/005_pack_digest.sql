-- Pack integrity pinning: SHA-256 digests of the active and previous pack files.
ALTER TABLE runtime_pointers ADD COLUMN IF NOT EXISTS pack_sha256 TEXT;
ALTER TABLE runtime_pointers ADD COLUMN IF NOT EXISTS previous_pack_sha256 TEXT;

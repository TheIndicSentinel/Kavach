CREATE TABLE IF NOT EXISTS batch_jobs (
    job_id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    input_path TEXT NOT NULL,
    output_path TEXT,
    model_id TEXT NOT NULL,
    governance_mode TEXT NOT NULL,
    total_rows BIGINT NOT NULL DEFAULT 0,
    processed_rows BIGINT NOT NULL DEFAULT 0,
    succeeded_rows BIGINT NOT NULL DEFAULT 0,
    failed_rows BIGINT NOT NULL DEFAULT 0,
    skipped_rows BIGINT NOT NULL DEFAULT 0,
    error_summary TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_batch_jobs_created_at ON batch_jobs (created_at);

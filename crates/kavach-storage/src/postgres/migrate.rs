use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

use super::StoragePool;

pub async fn connect_pool(
    database_url: &str,
) -> Result<StoragePool, kavach_evidence::EvidenceError> {
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await
        .map_err(|err| io_err(&err))?;
    run_migrations(&pool).await?;
    Ok(StoragePool { pool })
}

/// Serializes migrations across processes (replicas starting together).
const MIGRATION_LOCK: i64 = 0x4b41_5641_4348; // "KAVACH"

async fn run_migrations(pool: &PgPool) -> Result<(), kavach_evidence::EvidenceError> {
    let mut conn = pool.acquire().await.map_err(|err| io_err(&err))?;
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(MIGRATION_LOCK)
        .execute(&mut *conn)
        .await
        .map_err(|err| io_err(&err))?;
    let result = apply_migrations(&mut conn).await;
    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(MIGRATION_LOCK)
        .execute(&mut *conn)
        .await
        .map_err(|err| io_err(&err))?;
    result
}

async fn apply_migrations(
    conn: &mut sqlx::pool::PoolConnection<sqlx::Postgres>,
) -> Result<(), kavach_evidence::EvidenceError> {
    for sql in [
        include_str!("../../migrations/001_evidence.sql"),
        include_str!("../../migrations/002_batch_jobs.sql"),
        include_str!("../../migrations/003_admin_governance.sql"),
        include_str!("../../migrations/004_retention_erasure.sql"),
        include_str!("../../migrations/005_pack_digest.sql"),
        include_str!("../../migrations/006_change_requests.sql"),
        include_str!("../../migrations/007_model_state.sql"),
    ] {
        // Whole files through the simple-query protocol: function bodies
        // contain semicolons, so statements are not split client-side.
        sqlx::raw_sql(sql)
            .execute(&mut **conn)
            .await
            .map_err(|err| io_err(&err))?;
    }
    Ok(())
}

fn io_err(err: &sqlx::Error) -> kavach_evidence::EvidenceError {
    kavach_evidence::EvidenceError::Domain(kavach_domain::DomainError::Golden(format!(
        "postgres io: {err}"
    )))
}

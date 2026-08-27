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

async fn run_migrations(pool: &PgPool) -> Result<(), kavach_evidence::EvidenceError> {
    for sql in [
        include_str!("../../migrations/001_evidence.sql"),
        include_str!("../../migrations/002_batch_jobs.sql"),
        include_str!("../../migrations/003_admin_governance.sql"),
        include_str!("../../migrations/004_retention_erasure.sql"),
    ] {
        for statement in sql.split(';').map(str::trim).filter(|s| !s.is_empty()) {
            sqlx::query(statement)
                .execute(pool)
                .await
                .map_err(|err| io_err(&err))?;
        }
    }
    Ok(())
}

fn io_err(err: &sqlx::Error) -> kavach_evidence::EvidenceError {
    kavach_evidence::EvidenceError::Domain(kavach_domain::DomainError::Golden(format!(
        "postgres io: {err}"
    )))
}

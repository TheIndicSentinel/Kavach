use sqlx::postgres::PgPoolOptions;

use super::StoragePool;

/// Connects as a single role that both migrates and runs (development; the
/// application then owns its tables).
pub async fn connect_pool(
    database_url: &str,
) -> Result<StoragePool, kavach_evidence::EvidenceError> {
    migrate(database_url).await?;
    connect_runtime(database_url).await
}

/// Connects without migrating (the runtime role, ADR-005 §1).
pub async fn connect_runtime(
    database_url: &str,
) -> Result<StoragePool, kavach_evidence::EvidenceError> {
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await
        .map_err(|err| io_err(&err))?;
    Ok(StoragePool { pool })
}

/// Applies pending migrations as the owning role. Applied migrations are
/// tracked with checksums (`_sqlx_migrations`), so each runs once and an
/// edited migration is refused; sqlx serialises concurrent runs with an
/// advisory lock.
pub async fn migrate(database_url: &str) -> Result<(), kavach_evidence::EvidenceError> {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(database_url)
        .await
        .map_err(|err| io_err(&err))?;
    let result = sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .map_err(|err| {
            kavach_evidence::EvidenceError::Domain(kavach_domain::DomainError::Golden(format!(
                "postgres migrate: {err}"
            )))
        });
    pool.close().await;
    result
}

fn io_err(err: &sqlx::Error) -> kavach_evidence::EvidenceError {
    kavach_evidence::EvidenceError::Domain(kavach_domain::DomainError::Golden(format!(
        "postgres io: {err}"
    )))
}

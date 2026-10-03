use sqlx::postgres::PgPoolOptions;

use super::tls::{connect_options, DatabaseTls};
use super::StoragePool;

/// Connects as a single role that both migrates and runs (development; the
/// application then owns its tables).
pub async fn connect_pool(
    database_url: &str,
    tls: &DatabaseTls,
) -> Result<StoragePool, kavach_evidence::EvidenceError> {
    migrate(database_url, tls).await?;
    connect_runtime(database_url, tls).await
}

/// Connections in a runtime pool unless configured otherwise.
pub const DEFAULT_POOL_SIZE: u32 = 5;

/// Connects without migrating (the runtime role, ADR-005 §1).
pub async fn connect_runtime(
    database_url: &str,
    tls: &DatabaseTls,
) -> Result<StoragePool, kavach_evidence::EvidenceError> {
    connect_runtime_sized(database_url, tls, DEFAULT_POOL_SIZE).await
}

/// [`connect_runtime`] with `pool_size` connections (at least one).
pub async fn connect_runtime_sized(
    database_url: &str,
    tls: &DatabaseTls,
    pool_size: u32,
) -> Result<StoragePool, kavach_evidence::EvidenceError> {
    let options = connect_options(database_url, tls).map_err(|err| tls_err(&err))?;
    let pool = PgPoolOptions::new()
        .max_connections(pool_size.max(1))
        .connect_with(options)
        .await
        .map_err(|err| io_err(&err))?;
    Ok(StoragePool { pool })
}

/// Applies pending migrations as the owning role. Applied migrations are
/// tracked with checksums (`_sqlx_migrations`), so each runs once and an
/// edited migration is refused; sqlx serialises concurrent runs with an
/// advisory lock.
pub async fn migrate(
    database_url: &str,
    tls: &DatabaseTls,
) -> Result<(), kavach_evidence::EvidenceError> {
    let options = connect_options(database_url, tls).map_err(|err| tls_err(&err))?;
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options)
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

fn tls_err(err: &super::tls::DatabaseTlsError) -> kavach_evidence::EvidenceError {
    kavach_evidence::EvidenceError::Domain(kavach_domain::DomainError::Golden(format!(
        "postgres tls: {err}"
    )))
}

//! Test support: an isolated Postgres schema per test (feature `test-support`).
//!
//! Tests read `KAVACH_TEST_DATABASE_URL`. Locally, a missing URL skips the
//! test with a message; under CI (`CI` set) it fails, so Postgres coverage
//! cannot silently disappear.

use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

pub const DATABASE_URL_ENV: &str = "KAVACH_TEST_DATABASE_URL";

/// Returns a database URL whose `search_path` is a fresh, empty schema, or
/// `None` (skip) when no test database is configured outside CI.
///
/// # Panics
/// When running under CI without `KAVACH_TEST_DATABASE_URL`, or when the
/// schema cannot be created.
pub async fn isolated_database_url() -> Option<String> {
    let Ok(base) = std::env::var(DATABASE_URL_ENV) else {
        assert!(
            std::env::var_os("CI").is_none(),
            "{DATABASE_URL_ENV} must be set in CI: Postgres tests may not be skipped"
        );
        eprintln!("skipping Postgres test: {DATABASE_URL_ENV} is not set");
        return None;
    };
    let schema = format!("kt_{}", Uuid::new_v4().simple());
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&base)
        .await
        .expect("connect to KAVACH_TEST_DATABASE_URL");
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&pool)
        .await
        .expect("create test schema");
    pool.close().await;
    let separator = if base.contains('?') { '&' } else { '?' };
    Some(format!(
        "{base}{separator}options=-c%20search_path%3D{schema}"
    ))
}

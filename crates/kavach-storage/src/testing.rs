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

/// Password of the `kavach_runtime` role created for tests.
pub const RUNTIME_TEST_PASSWORD: &str = "kavach-runtime-test";

/// Like [`isolated_database_url`], and also creates (once per cluster) the
/// `kavach_runtime` and `kavach_auditor` roles. Returns `(owner_url, runtime_url)`, both with the
/// fresh schema on their `search_path`; migrate with the owner URL.
///
/// # Panics
/// As [`isolated_database_url`], or when the role cannot be created.
pub async fn isolated_database_urls() -> Option<(String, String)> {
    let owner = isolated_database_url().await?;
    let base = std::env::var(DATABASE_URL_ENV).expect("checked above");
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&base)
        .await
        .expect("connect");
    // Concurrent tests may race to create the cluster-wide role.
    sqlx::query(&format!(
        "DO $$ BEGIN \
            CREATE ROLE kavach_runtime LOGIN PASSWORD '{RUNTIME_TEST_PASSWORD}'; \
         EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END $$"
    ))
    .execute(&pool)
    .await
    .expect("create kavach_runtime role");
    sqlx::query(&format!(
        "DO $$ BEGIN \
            CREATE ROLE kavach_auditor LOGIN PASSWORD '{AUDITOR_TEST_PASSWORD}'; \
         EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END $$"
    ))
    .execute(&pool)
    .await
    .expect("create kavach_auditor role");
    pool.close().await;
    let runtime = with_credentials(&owner, "kavach_runtime", RUNTIME_TEST_PASSWORD);
    Some((owner, runtime))
}

/// Password of the `kavach_auditor` role created for tests.
pub const AUDITOR_TEST_PASSWORD: &str = "kavach-auditor-test";

/// The read-only auditor's URL for a database from
/// [`isolated_database_urls`] (same schema as `owner`).
#[must_use]
pub fn auditor_url(owner: &str) -> String {
    with_credentials(owner, "kavach_auditor", AUDITOR_TEST_PASSWORD)
}

/// `postgres://user:pass@host/...` with other credentials.
fn with_credentials(url: &str, user: &str, password: &str) -> String {
    let (scheme, rest) = url.split_once("://").expect("url scheme");
    let host = rest.split_once('@').map_or(rest, |(_, host)| host);
    format!("{scheme}://{user}:{password}@{host}")
}

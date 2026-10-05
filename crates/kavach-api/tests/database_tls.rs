//! The API refuses to start with a database URL that asks for anything
//! weaker than `sslmode=verify-full`, unless it runs in a development mode
//! (T1). No database is needed: the refusal comes before any connection.

mod agent_fixture;
mod contract;

use kavach_api::{ApiConfig, AppState, DatabaseTls, EvidenceStoreKind};

use agent_fixture::*;

const URL: &str = "postgres://kavach_runtime:secret-pw@127.0.0.1:9/kavach";

fn postgres(database_url: &str, tls: DatabaseTls) -> ApiConfig {
    let store = EvidenceStoreKind::Postgres {
        database_url: database_url.into(),
    };
    let mut api = config(store, true, 50);
    api.database_tls = tls;
    api
}

async fn startup_error(api: ApiConfig) -> String {
    let err = AppState::from_config(&api).await.err().expect("refused");
    let message = format!("{err:?}");
    assert!(
        !message.contains("secret-pw"),
        "the password leaked: {message}"
    );
    message
}

#[tokio::test]
async fn startup_refuses_a_weaker_sslmode_outside_development() {
    // What the binary builds without --insecure-dev.
    let production = DatabaseTls::new(false, None);
    for weaker in ["require", "disable", "allow", "prefer", "verify-ca"] {
        let url = format!("{URL}?sslmode={weaker}");
        let message = startup_error(postgres(&url, production.clone())).await;
        assert!(message.contains(&format!("sslmode={weaker}")), "{message}");
        assert!(message.contains("verify-full"), "{message}");
    }

    // The owner's migration URL is held to the same rule.
    let mut api = postgres(URL, production.clone());
    api.migration_database_url = Some(format!("{URL}?sslmode=require"));
    let message = startup_error(api).await;
    assert!(message.contains("sslmode=require"), "{message}");

    // A CA file that is not there is refused, not skipped.
    let missing = DatabaseTls::new(false, Some("/nonexistent/kavach-db-ca.pem".into()));
    let message = startup_error(postgres(URL, missing)).await;
    assert!(message.contains("CA file"), "{message}");
}

#[tokio::test]
async fn development_accepts_a_weaker_mode_only_when_the_url_asks() {
    // With --insecure-dev and sslmode=disable the policy lets it through:
    // what fails now is the connection (nothing listens on that port).
    let development = DatabaseTls::new(true, None);
    let message = startup_error(postgres(&format!("{URL}?sslmode=disable"), development)).await;
    assert!(message.contains("postgres io"), "{message}");
    assert!(!message.contains("verify-full"), "{message}");
}

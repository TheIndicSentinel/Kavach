//! Signed runtime updates store only ciphertext and resolve under exact scope.

use chrono::{Duration, Utc};
use kavach_domain::authority::{
    AuthorityChange, AuthorityUpdateEvent, ReferenceDestinationRecord, SensitiveDestination,
};
use kavach_keys::InMemoryKeyProvider;
use kavach_mandate::jws::{self, KeySet, TYP_AUTHORITY_UPDATE};
use kavach_mandate::{AuthorityVerifier, MandateConfig, SorIssuer};
use kavach_ports::{ErrorClass, ReferenceResolver, SyncStatus, TrustedNow};
use kavach_storage::testing::isolated_database_urls;
use kavach_storage::{connect_runtime, DatabaseTls, ReferenceVaultKey, StoragePool};
use std::fs;

const TENANT: &str = "tenant-a";
const SUBJECT: &str = "ref:borrower:B-1";

fn key_file() -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "kavach-postgres-reference-key-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    fs::write(&path, format!("{}\n", "a7".repeat(32))).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    path
}

fn event(
    occurred_at: chrono::DateTime<Utc>,
    update_id: &str,
    system: &str,
    destination: &str,
) -> AuthorityUpdateEvent {
    AuthorityUpdateEvent {
        update_id: update_id.into(),
        tenant_id: TENANT.into(),
        system: system.into(),
        occurred_at,
        nonce: format!("nonce-{update_id}"),
        change: AuthorityChange::ReferenceDestination(ReferenceDestinationRecord {
            tenant_id: TENANT.into(),
            subject_ref: SUBJECT.into(),
            channel: "sms".into(),
            destination: SensitiveDestination::new(destination),
        }),
    }
}

fn trusted_now(now: chrono::DateTime<Utc>) -> TrustedNow {
    TrustedNow {
        utc: now,
        sync: SyncStatus::Synced { max_error_ms: 0 },
    }
}

#[tokio::test]
async fn signed_reference_updates_are_encrypted_atomic_and_source_pinned() {
    let Some((owner_url, runtime_url)) = isolated_database_urls().await else {
        return;
    };
    let tls = DatabaseTls::development();
    let owner = StoragePool::connect(&owner_url, &tls).await.unwrap();
    let runtime = connect_runtime(&runtime_url, &tls).await.unwrap();
    let path = key_file();
    let writer_key = ReferenceVaultKey::from_file(&path, "reference-v1").unwrap();
    let resolver_key = ReferenceVaultKey::from_file(&path, "reference-v1").unwrap();
    fs::remove_file(path).unwrap();
    let writer = runtime.reference_destination_store(writer_key);
    let resolver = runtime.reference_resolver(resolver_key);

    let mut signer = InMemoryKeyProvider::new();
    let lms_key = signer.insert_seed("lms-1", [9; 32]).unwrap();
    let crm_key = signer.insert_seed("crm-1", [10; 32]).unwrap();
    let verifier = AuthorityVerifier::new(
        TENANT,
        MandateConfig {
            issuer_id: "test".into(),
            signing_kid: "unused".into(),
            mandate_keys: KeySet::new([lms_key.clone(), crm_key.clone()]),
            sor_issuers: vec![
                SorIssuer {
                    tenant_id: TENANT.into(),
                    system: "lms".into(),
                    key: lms_key,
                },
                SorIssuer {
                    tenant_id: TENANT.into(),
                    system: "crm".into(),
                    key: crm_key,
                },
            ],
            templates: Vec::new(),
            passports: Vec::new(),
            event_freshness_seconds: 300,
            replay_window_seconds: 3600,
            max_clock_error_ms: 500,
        },
    )
    .unwrap();
    let now = Utc::now();

    let first = event(now, "destination-1", "lms", "+910000000001");
    let token = jws::sign(&signer, "lms-1", TYP_AUTHORITY_UPDATE, &first)
        .await
        .unwrap();
    let verified = verifier.verify(&token, trusted_now(now)).unwrap();
    assert!(!writer.apply(&verified).await.unwrap().replayed);
    assert!(writer.apply(&verified).await.unwrap().replayed);

    let history_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM authority_updates")
        .fetch_one(&runtime.pool)
        .await
        .unwrap();
    assert_eq!(history_count, 1);
    let history_record: serde_json::Value = sqlx::query_scalar(
        "SELECT record FROM authority_updates WHERE update_id = 'destination-1'",
    )
    .fetch_one(&runtime.pool)
    .await
    .unwrap();
    assert_eq!(history_record["tenant_id"], TENANT);
    assert_eq!(history_record["subject_ref"], SUBJECT);
    assert!(history_record.get("destination").is_none());
    let ciphertext: Vec<u8> = sqlx::query_scalar(
        "SELECT ciphertext FROM reference_destinations WHERE tenant_id = $1 AND subject_ref = $2 AND channel = 'sms'",
    )
    .bind(TENANT)
    .bind(SUBJECT)
    .fetch_one(&runtime.pool)
    .await
    .unwrap();
    assert!(!ciphertext
        .windows("+910000000001".len())
        .any(|window| window == "+910000000001".as_bytes()));
    assert_eq!(
        resolver
            .resolve(TENANT, SUBJECT, "sms")
            .await
            .unwrap()
            .expose(),
        "+910000000001"
    );
    assert_eq!(
        resolver
            .resolve("tenant-b", SUBJECT, "sms")
            .await
            .unwrap_err()
            .class,
        ErrorClass::Rejected
    );
    assert_eq!(
        resolver
            .resolve(TENANT, SUBJECT, "voice")
            .await
            .unwrap_err()
            .class,
        ErrorClass::Rejected
    );

    let conflicting_replay = event(now, "destination-1", "lms", "+910000000002");
    let token = jws::sign(&signer, "lms-1", TYP_AUTHORITY_UPDATE, &conflicting_replay)
        .await
        .unwrap();
    let conflict = verifier.verify(&token, trusted_now(now)).unwrap();
    assert_eq!(
        writer.apply(&conflict).await.unwrap_err().class,
        ErrorClass::Rejected
    );

    let stale = event(
        now - Duration::seconds(1),
        "destination-stale",
        "lms",
        "+910000000003",
    );
    let token = jws::sign(&signer, "lms-1", TYP_AUTHORITY_UPDATE, &stale)
        .await
        .unwrap();
    let stale = verifier.verify(&token, trusted_now(now)).unwrap();
    assert_eq!(
        writer.apply(&stale).await.unwrap_err().class,
        ErrorClass::Rejected
    );

    let other_source = event(
        now + Duration::seconds(1),
        "destination-crm",
        "crm",
        "+910000000004",
    );
    let token = jws::sign(&signer, "crm-1", TYP_AUTHORITY_UPDATE, &other_source)
        .await
        .unwrap();
    let other_source = verifier.verify(&token, trusted_now(now)).unwrap();
    assert_eq!(
        writer.apply(&other_source).await.unwrap_err().class,
        ErrorClass::Rejected
    );

    let newer = event(
        now + Duration::seconds(1),
        "destination-2",
        "lms",
        "+910000000005",
    );
    let token = jws::sign(&signer, "lms-1", TYP_AUTHORITY_UPDATE, &newer)
        .await
        .unwrap();
    let newer = verifier.verify(&token, trusted_now(now)).unwrap();
    assert!(!writer.apply(&newer).await.unwrap().replayed);
    assert_eq!(
        resolver
            .resolve(TENANT, SUBJECT, "sms")
            .await
            .unwrap()
            .expose(),
        "+910000000005"
    );
    let version: i64 = sqlx::query_scalar(
        "SELECT version FROM reference_destinations WHERE tenant_id = $1 AND subject_ref = $2 AND channel = 'sms'",
    )
    .bind(TENANT)
    .bind(SUBJECT)
    .fetch_one(&runtime.pool)
    .await
    .unwrap();
    assert_eq!(version, 2);

    sqlx::query("REVOKE UPDATE (version, format_version, key_id, nonce, ciphertext, update_id, source_occurred_at, updated_at) ON reference_destinations FROM kavach_runtime")
        .execute(&owner.pool)
        .await
        .unwrap();
    let atomicity_probe = event(
        now + Duration::seconds(2),
        "destination-3",
        "lms",
        "+910000000006",
    );
    let token = jws::sign(&signer, "lms-1", TYP_AUTHORITY_UPDATE, &atomicity_probe)
        .await
        .unwrap();
    let atomicity_probe = verifier.verify(&token, trusted_now(now)).unwrap();
    assert_eq!(
        writer.apply(&atomicity_probe).await.unwrap_err().class,
        ErrorClass::Unavailable
    );
    let history_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM authority_updates")
        .fetch_one(&runtime.pool)
        .await
        .unwrap();
    assert_eq!(history_count, 2);
    assert_eq!(
        resolver
            .resolve(TENANT, SUBJECT, "sms")
            .await
            .unwrap()
            .expose(),
        "+910000000005"
    );
    sqlx::query("GRANT UPDATE (version, format_version, key_id, nonce, ciphertext, update_id, source_occurred_at, updated_at) ON reference_destinations TO kavach_runtime")
        .execute(&owner.pool)
        .await
        .unwrap();
    assert!(!writer.apply(&atomicity_probe).await.unwrap().replayed);
    assert_eq!(
        resolver
            .resolve(TENANT, SUBJECT, "sms")
            .await
            .unwrap()
            .expose(),
        "+910000000006"
    );

    let select_allowed: bool = sqlx::query_scalar(
        "SELECT has_table_privilege('kavach_runtime', 'reference_destinations', 'SELECT')",
    )
    .fetch_one(&owner.pool)
    .await
    .unwrap();
    let insert_allowed: bool = sqlx::query_scalar(
        "SELECT has_table_privilege('kavach_runtime', 'reference_destinations', 'INSERT')",
    )
    .fetch_one(&owner.pool)
    .await
    .unwrap();
    let update_allowed: bool = sqlx::query_scalar(
        "SELECT has_any_column_privilege('kavach_runtime', 'reference_destinations', 'UPDATE')",
    )
    .fetch_one(&owner.pool)
    .await
    .unwrap();
    let update_source_allowed: bool = sqlx::query_scalar(
        "SELECT has_column_privilege('kavach_runtime', 'reference_destinations', 'source_system', 'UPDATE')",
    )
    .fetch_one(&owner.pool)
    .await
    .unwrap();
    let delete_allowed: bool = sqlx::query_scalar(
        "SELECT has_table_privilege('kavach_runtime', 'reference_destinations', 'DELETE')",
    )
    .fetch_one(&owner.pool)
    .await
    .unwrap();
    assert!(select_allowed && insert_allowed && update_allowed);
    assert!(!update_source_allowed && !delete_allowed);
}

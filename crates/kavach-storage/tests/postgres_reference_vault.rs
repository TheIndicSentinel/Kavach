//! Runtime reads only ciphertext and decrypts it under the exact reference scope.

use kavach_ports::{ErrorClass, ReferenceResolver};
use kavach_storage::testing::isolated_database_urls;
use kavach_storage::{connect_runtime, DatabaseTls, ReferenceVaultKey, StoragePool};
use std::fs;

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

#[tokio::test]
async fn postgres_reference_vault_is_ciphertext_only_and_runtime_read_only() {
    let Some((owner_url, runtime_url)) = isolated_database_urls().await else {
        return;
    };
    let tls = DatabaseTls::development();
    let owner = StoragePool::connect(&owner_url, &tls).await.unwrap();
    let runtime = connect_runtime(&runtime_url, &tls).await.unwrap();
    let path = key_file();
    let key = ReferenceVaultKey::from_file(&path, "reference-v1").unwrap();
    fs::remove_file(path).unwrap();

    let plaintext = "+910000000001";
    let encrypted = key
        .seal(
            "tenant-a",
            "ref:borrower:B-1",
            "sms",
            4,
            &kavach_ports::Destination::new(plaintext),
        )
        .unwrap();
    assert!(!encrypted
        .ciphertext()
        .windows(plaintext.len())
        .any(|window| window == plaintext.as_bytes()));
    sqlx::query(
        "INSERT INTO reference_destinations \
         (tenant_id, subject_ref, channel, version, format_version, key_id, nonce, ciphertext) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind("tenant-a")
    .bind("ref:borrower:B-1")
    .bind("sms")
    .bind(4_i64)
    .bind(i16::from(encrypted.format_version()))
    .bind(encrypted.key_id())
    .bind(encrypted.nonce().as_slice())
    .bind(encrypted.ciphertext())
    .execute(&owner.pool)
    .await
    .unwrap();

    let resolver = runtime.reference_resolver(key);
    assert_eq!(resolver.describe(), "Postgres encrypted reference vault");
    assert_eq!(
        resolver
            .resolve("tenant-a", "ref:borrower:B-1", "sms")
            .await
            .unwrap()
            .expose(),
        plaintext
    );
    assert_eq!(
        resolver
            .resolve("tenant-b", "ref:borrower:B-1", "sms")
            .await
            .unwrap_err()
            .class,
        ErrorClass::Rejected
    );
    assert_eq!(
        resolver
            .resolve("tenant-a", "ref:borrower:B-1", "voice")
            .await
            .unwrap_err()
            .class,
        ErrorClass::Rejected
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
        "SELECT has_table_privilege('kavach_runtime', 'reference_destinations', 'UPDATE')",
    )
    .fetch_one(&owner.pool)
    .await
    .unwrap();
    assert!(select_allowed);
    assert!(!insert_allowed);
    assert!(!update_allowed);

    sqlx::query(
        "UPDATE reference_destinations SET key_id = 'missing-key' \
         WHERE tenant_id = 'tenant-a' AND subject_ref = 'ref:borrower:B-1' AND channel = 'sms'",
    )
    .execute(&owner.pool)
    .await
    .unwrap();
    assert_eq!(
        resolver
            .resolve("tenant-a", "ref:borrower:B-1", "sms")
            .await
            .unwrap_err()
            .class,
        ErrorClass::Unavailable
    );
}

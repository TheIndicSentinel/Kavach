use kavach_keys::{validate_kid, InMemoryKeyProvider, LocalFileKeyProvider};
use kavach_ports::{ErrorClass, KeyProvider};
use kavach_ports_testkit::conformance::key_provider;

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("kavach-keys-{tag}-{}-{nanos}", std::process::id()))
}

#[tokio::test]
async fn in_memory_provider_conforms() {
    let mut provider = InMemoryKeyProvider::new();
    provider.generate("signer-1").unwrap();
    key_provider(&provider, "signer-1").await;
}

#[tokio::test]
async fn local_file_provider_conforms() {
    let dir = temp_dir("conform");
    let provider = LocalFileKeyProvider::new(&dir);
    provider.create_key("signer-1").unwrap();
    key_provider(&provider, "signer-1").await;
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn local_file_provider_refuses_duplicate_and_bad_kid() {
    let dir = temp_dir("dup");
    let provider = LocalFileKeyProvider::new(&dir);
    provider.create_key("k1").unwrap();
    assert!(provider.create_key("k1").is_err(), "must not overwrite");
    for bad in ["", "../escape", ".hidden", "a/b", "sp ace"] {
        assert_eq!(validate_kid(bad).unwrap_err().class, ErrorClass::Invalid);
    }
    let err = provider.sign("../escape", b"m").await.unwrap_err();
    assert_eq!(err.class, ErrorClass::Invalid);
    let _ = std::fs::remove_dir_all(dir);
}

#[cfg(unix)]
#[tokio::test]
async fn local_file_provider_rejects_group_readable_key() {
    use std::os::unix::fs::PermissionsExt;
    let dir = temp_dir("perm");
    let provider = LocalFileKeyProvider::new(&dir);
    provider.create_key("k1").unwrap();
    let path = dir.join("k1.ed25519");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let err = provider.sign("k1", b"m").await.unwrap_err();
    assert_eq!(err.class, ErrorClass::Rejected);
    let _ = std::fs::remove_dir_all(dir);
}

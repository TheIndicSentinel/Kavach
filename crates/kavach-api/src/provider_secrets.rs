//! Development file adapter for the ADR-015 provider-secret port.
//!
//! A deployment adapter such as OpenBao can implement the same port. The
//! local adapter accepts only one filename as a reference and requires an
//! owner-only directory and file.

use std::path::{Path, PathBuf};

use kavach_ports::{PortError, ProviderSecretFuture, ProviderSecretStore, TokenSecret};
use zeroize::Zeroizing;

#[derive(Debug, Clone)]
pub struct FileProviderSecretStore {
    root: PathBuf,
}

impl FileProviderSecretStore {
    #[must_use]
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    fn path(&self, reference: &str) -> Result<PathBuf, PortError> {
        if reference.is_empty()
            || reference == "."
            || reference == ".."
            || !reference
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Err(PortError::invalid("provider secret reference"));
        }
        Ok(self.root.join(reference))
    }
}

impl ProviderSecretStore for FileProviderSecretStore {
    fn read<'a>(&'a self, reference: &'a str) -> ProviderSecretFuture<'a> {
        let path = self.path(reference);
        Box::pin(async move {
            let path = path?;
            tokio::task::spawn_blocking(move || read_secret_file(&path))
                .await
                .map_err(|_| PortError::unavailable("provider secret lookup failed"))?
        })
    }
}

fn read_secret_file(path: &Path) -> Result<TokenSecret, PortError> {
    let root = path
        .parent()
        .ok_or_else(|| PortError::invalid("provider secret directory"))?;
    let root_meta = std::fs::symlink_metadata(root)
        .map_err(|_| PortError::unavailable("provider secret directory unavailable"))?;
    if !root_meta.is_dir() || root_meta.file_type().is_symlink() || !owner_only(&root_meta) {
        return Err(PortError::unavailable(
            "provider secret directory must be a real owner-only directory",
        ));
    }
    let meta = std::fs::symlink_metadata(path)
        .map_err(|_| PortError::unavailable("provider secret unavailable"))?;
    if !meta.is_file() || meta.file_type().is_symlink() || !owner_only(&meta) {
        return Err(PortError::unavailable(
            "provider secret must be a real owner-only file",
        ));
    }
    if meta.len() == 0 || meta.len() > 8192 {
        return Err(PortError::unavailable("provider secret has invalid size"));
    }
    let bytes =
        std::fs::read(path).map_err(|_| PortError::unavailable("provider secret unavailable"))?;
    let mut secret = Zeroizing::new(
        String::from_utf8(bytes).map_err(|_| PortError::invalid("provider secret is not UTF-8"))?,
    );
    while secret.ends_with('\n') || secret.ends_with('\r') {
        secret.pop();
    }
    if secret.is_empty() || secret.bytes().any(|b| b.is_ascii_whitespace()) {
        return Err(PortError::invalid("provider secret format"));
    }
    Ok(TokenSecret::new(secret.to_string()))
}

#[cfg(unix)]
fn owner_only(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode().trailing_zeros() >= 6
}

#[cfg(not(unix))]
fn owner_only(_metadata: &std::fs::Metadata) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn scratch() -> PathBuf {
        std::env::temp_dir().join(format!("kavach-provider-secret-{}", uuid::Uuid::new_v4()))
    }

    #[tokio::test]
    async fn reads_owner_only_secret_and_rejects_path_traversal() {
        let root = scratch();
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.join("twilio-sandbox");
        std::fs::write(&path, "secret-value\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let store = FileProviderSecretStore::new(root.clone());
        let secret = store.read("twilio-sandbox").await.unwrap();
        assert_eq!(secret.expose(), "secret-value");
        assert!(store.read("../twilio-sandbox").await.is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn refuses_group_or_world_readable_provider_secrets() {
        let root = scratch();
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.join("twilio-sandbox");
        std::fs::write(&path, "secret-value").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let store = FileProviderSecretStore::new(root.clone());
        assert!(store.read("twilio-sandbox").await.is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}

//! Development file adapter for the ADR-015 provider-secret port.
//!
//! A deployment adapter such as OpenBao can implement the same port. The
//! local adapter accepts only one filename as a reference and requires an
//! owner-only directory and file.

use std::path::{Path, PathBuf};
use std::time::Duration;

use kavach_ports::{PortError, ProviderSecretFuture, ProviderSecretStore, TokenSecret};
use reqwest::Url;
use serde::Deserialize;
use zeroize::Zeroizing;

const OPENBAO_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_OPENBAO_RESPONSE: usize = 16 * 1024;

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

/// Read-only OpenBao KV v2 provider secret adapter (ADR-015).
///
/// The OpenBao token is supplied by the deployment's authentication bootstrap;
/// provider secrets themselves are resolved by opaque reference at send time.
/// Plain HTTP is accepted only for loopback development servers.
pub struct OpenBaoKv2ProviderSecretStore {
    endpoint: Url,
    mount: String,
    token: TokenSecret,
    client: reqwest::Client,
}

impl OpenBaoKv2ProviderSecretStore {
    pub fn new(endpoint: &str, mount: &str, token: TokenSecret) -> Result<Self, PortError> {
        let mut endpoint = Url::parse(endpoint)
            .map_err(|_| PortError::invalid("OpenBao endpoint must be an absolute URL"))?;
        let loopback_http = endpoint.scheme() == "http"
            && endpoint.host_str().is_some_and(|host| {
                host.parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
            });
        if (endpoint.scheme() != "https" && !loopback_http)
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(PortError::invalid(
                "OpenBao endpoint must use HTTPS (HTTP is loopback-only)",
            ));
        }
        if !valid_component(mount) {
            return Err(PortError::invalid("OpenBao KV mount is invalid"));
        }
        if token.expose().is_empty()
            || token
                .expose()
                .bytes()
                .any(|byte| byte.is_ascii_whitespace())
        {
            return Err(PortError::invalid("OpenBao token format is invalid"));
        }
        let base_path = endpoint.path().trim_end_matches('/').to_owned();
        endpoint.set_path(&base_path);
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(OPENBAO_TIMEOUT)
            .build()
            .map_err(|_| PortError::unavailable("OpenBao client unavailable"))?;
        Ok(Self {
            endpoint,
            mount: mount.to_owned(),
            token,
            client,
        })
    }

    fn secret_url(&self, reference: &str) -> Result<Url, PortError> {
        if reference.is_empty()
            || reference.starts_with('/')
            || reference.split('/').any(|part| !valid_component(part))
        {
            return Err(PortError::invalid("OpenBao secret reference is invalid"));
        }
        let mut url = self.endpoint.clone();
        let prefix = url.path().trim_end_matches('/');
        url.set_path(&format!("{prefix}/v1/{}/data/{reference}", self.mount));
        Ok(url)
    }
}

impl ProviderSecretStore for OpenBaoKv2ProviderSecretStore {
    fn read<'a>(&'a self, reference: &'a str) -> ProviderSecretFuture<'a> {
        Box::pin(async move {
            let url = self.secret_url(reference)?;
            let response = self
                .client
                .get(url)
                .header(
                    reqwest::header::HeaderName::from_static("x-vault-token"),
                    self.token.expose(),
                )
                .send()
                .await
                .map_err(|_| PortError::unavailable("OpenBao secret lookup failed"))?;
            if !response.status().is_success() {
                return Err(PortError::unavailable("OpenBao secret lookup failed"));
            }
            if response
                .content_length()
                .is_some_and(|length| length > MAX_OPENBAO_RESPONSE as u64)
            {
                return Err(PortError::unavailable(
                    "OpenBao response exceeded size limit",
                ));
            }
            let mut response = response;
            let mut body = Zeroizing::new(Vec::new());
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_| PortError::unavailable("OpenBao secret lookup failed"))?
            {
                if body.len().saturating_add(chunk.len()) > MAX_OPENBAO_RESPONSE {
                    return Err(PortError::unavailable(
                        "OpenBao response exceeded size limit",
                    ));
                }
                body.extend_from_slice(&chunk);
            }
            let document: OpenBaoKv2Response = serde_json::from_slice(&body)
                .map_err(|_| PortError::unavailable("OpenBao response was invalid"))?;
            let mut secret = document
                .data
                .data
                .token
                .ok_or_else(|| PortError::unavailable("OpenBao secret was unavailable"))?;
            if secret.0.is_empty()
                || secret.0.len() > 8192
                || secret.0.bytes().any(|byte| byte.is_ascii_whitespace())
            {
                return Err(PortError::unavailable("OpenBao secret format is invalid"));
            }
            Ok(TokenSecret::new(secret.take()))
        })
    }
}

#[derive(Deserialize)]
struct OpenBaoKv2Response {
    data: OpenBaoKv2Data,
}

#[derive(Deserialize)]
struct OpenBaoKv2Data {
    data: OpenBaoKv2Fields,
}

struct OpenBaoKv2Fields {
    token: Option<OpenBaoSecretValue>,
}

impl<'de> Deserialize<'de> for OpenBaoKv2Fields {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct DataVisitor;

        impl<'de> serde::de::Visitor<'de> for DataVisitor {
            type Value = OpenBaoKv2Fields;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an OpenBao KV v2 data object")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: serde::de::MapAccess<'de>,
            {
                let mut token = None;
                while let Some(key) = map.next_key::<String>()? {
                    if key == "token" {
                        token = Some(map.next_value::<OpenBaoSecretValue>()?);
                    } else {
                        map.next_value::<serde::de::IgnoredAny>()?;
                    }
                }
                Ok(OpenBaoKv2Fields { token })
            }
        }

        deserializer.deserialize_map(DataVisitor)
    }
}

struct OpenBaoSecretValue(String);

impl OpenBaoSecretValue {
    fn take(&mut self) -> String {
        std::mem::take(&mut self.0)
    }
}

impl<'de> Deserialize<'de> for OpenBaoSecretValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self)
    }
}

impl Drop for OpenBaoSecretValue {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.0.zeroize();
    }
}

fn valid_component(component: &str) -> bool {
    !component.is_empty()
        && component != "."
        && component != ".."
        && component
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
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
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::os::unix::fs::PermissionsExt;

    fn scratch() -> PathBuf {
        std::env::temp_dir().join(format!("kavach-provider-secret-{}", uuid::Uuid::new_v4()))
    }

    #[tokio::test]
    async fn reads_owner_only_secret_and_rejects_path_traversal() {
        let root = scratch();
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.join("provider-token");
        std::fs::write(&path, "secret-value\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let store = FileProviderSecretStore::new(root.clone());
        let secret = store.read("provider-token").await.unwrap();
        assert_eq!(secret.expose(), "secret-value");
        assert!(store.read("../provider-token").await.is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn refuses_group_or_world_readable_provider_secrets() {
        let root = scratch();
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.join("provider-token");
        std::fs::write(&path, "secret-value").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let store = FileProviderSecretStore::new(root.clone());
        assert!(store.read("provider-token").await.is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn openbao_kv2_reads_only_the_configured_token_field() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut chunk = [0_u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut chunk).unwrap();
                assert_ne!(read, 0);
                request.extend_from_slice(&chunk[..read]);
            }
            let body = r#"{"data":{"data":{"token":"synthetic-provider-secret","metadata":42,"extra":{"hidden":true}}}}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
            String::from_utf8(request).unwrap()
        });
        let store = OpenBaoKv2ProviderSecretStore::new(
            &format!("http://{address}"),
            "secret",
            TokenSecret::new("synthetic-openbao-token"),
        )
        .unwrap();

        let secret = store.read("providers/mock-messaging").await.unwrap();
        let request = server.join().unwrap().to_ascii_lowercase();
        assert_eq!(secret.expose(), "synthetic-provider-secret");
        assert!(request.contains("get /v1/secret/data/providers/mock-messaging http/1.1"));
        assert!(request.contains("x-vault-token: synthetic-openbao-token"));
        assert!(store.read("../outside").await.is_err());
        assert!(store.read("providers//token").await.is_err());
    }

    #[test]
    fn openbao_rejects_non_loopback_http_and_unsafe_mounts() {
        assert!(OpenBaoKv2ProviderSecretStore::new(
            "http://example.invalid",
            "secret",
            TokenSecret::new("bootstrap-token")
        )
        .is_err());
        assert!(OpenBaoKv2ProviderSecretStore::new(
            "https://openbao.example",
            "../secret",
            TokenSecret::new("bootstrap-token")
        )
        .is_err());
    }
}

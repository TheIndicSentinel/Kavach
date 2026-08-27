use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct ApiConfig {
    pub pack_path: PathBuf,
    pub model_path: PathBuf,
    pub hmac_secret: Option<String>,
    pub evidence_store: EvidenceStoreKind,
    pub access_control: AccessControlKind,
    pub tls: Option<TlsConfig>,
}

#[derive(Debug, Clone)]
pub enum AccessControlKind {
    None,
    Cedar {
        policy_path: PathBuf,
        entities_path: PathBuf,
    },
}

#[derive(Debug, Clone)]
pub enum EvidenceStoreKind {
    Memory,
    Postgres { database_url: String },
}

#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub client_ca_path: Option<PathBuf>,
}

impl TlsConfig {
    pub fn from_paths(cert: PathBuf, key: PathBuf, client_ca: Option<PathBuf>) -> Self {
        Self {
            cert_path: cert,
            key_path: key,
            client_ca_path: client_ca,
        }
    }

    pub fn is_mtls(&self) -> bool {
        self.client_ca_path.is_some()
    }

    pub async fn read_server_pem(&self) -> Result<(Vec<u8>, Vec<u8>), std::io::Error> {
        let cert = tokio::fs::read(&self.cert_path).await?;
        let key = tokio::fs::read(&self.key_path).await?;
        Ok((cert, key))
    }

    pub async fn read_client_ca(&self) -> Result<Option<Vec<u8>>, std::io::Error> {
        match &self.client_ca_path {
            Some(path) => Ok(Some(tokio::fs::read(path).await?)),
            None => Ok(None),
        }
    }
}

impl ApiConfig {
    pub fn pack_path(&self) -> &Path {
        &self.pack_path
    }

    pub fn model_path(&self) -> &Path {
        &self.model_path
    }
}

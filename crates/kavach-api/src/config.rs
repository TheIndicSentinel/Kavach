use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct ApiConfig {
    pub pack_path: PathBuf,
    pub model_path: PathBuf,
    pub hmac_secret: Option<String>,
    pub evidence_store: EvidenceStoreKind,
    pub access_control: AccessControlKind,
    pub tls: Option<TlsConfig>,
    /// Expected `sha256:<hex>` (or bare hex) of the startup pack file.
    pub pack_sha256: Option<String>,
    /// Postgres mode: start even if `--pack` differs from the governed
    /// runtime pointer (audited recovery override).
    pub bootstrap_pack: bool,
    /// Postgres mode: start even if the model file differs from the pinned
    /// one; re-pins path and digest only (audited), never status or mode.
    pub bootstrap_model: bool,
    /// Trusted pack signers (JSON). When set, every pack load requires a
    /// valid detached signature (`<pack>.sig`) from one of them.
    pub pack_signers: Option<PathBuf>,
    /// OIDC/OAuth 2.0 JWT verification for API principals (ADR-008).
    pub oidc: Option<crate::oidc::OidcConfig>,
    /// Development only: accept the self-asserted `X-Kavach-Principal` header.
    pub insecure_dev: bool,
    /// mTLS principals: the client certificate SAN of this type names the
    /// principal (requires `--tls-client-ca`).
    pub mtls_principal_san: Option<crate::mtls::MtlsSanKind>,
    /// How long a change request stays approvable.
    pub change_ttl_seconds: u64,
    /// Postgres: the owner role that runs migrations. When set, the runtime
    /// connection (`database_url`) never migrates and should be the
    /// least-privilege `kavach_runtime` role (ADR-005 §1).
    pub migration_database_url: Option<String>,
}

/// Cedar access control needs an authenticated principal source (OIDC or
/// mTLS SAN) unless `--insecure-dev` explicitly allows the header. mTLS
/// principals need client-certificate verification.
pub fn validate_principal_sources(config: &ApiConfig) -> Result<(), String> {
    let mtls = config.mtls_principal_san.is_some();
    if mtls && !config.tls.as_ref().is_some_and(TlsConfig::is_mtls) {
        return Err(
            "--mtls-principal-san needs mTLS: set --tls-cert, --tls-key and --tls-client-ca".into(),
        );
    }
    match config.access_control {
        AccessControlKind::Cedar { .. }
            if config.oidc.is_none() && !mtls && !config.insecure_dev =>
        {
            Err(
                "cedar access control needs an authenticated principal source: configure OIDC \
                 (--oidc-issuer, --oidc-audience, --oidc-jwks-file or --oidc-jwks-url) or mTLS \
                 principals (--mtls-principal-san with --tls-client-ca); the X-Kavach-Principal \
                 header is accepted only with --insecure-dev"
                    .into(),
            )
        }
        _ => Ok(()),
    }
}

/// Requested access-control mode, before validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessControlMode {
    None,
    Cedar,
}

/// Validates the access-control settings. Disabling access control is only
/// allowed with an explicit development opt-in (`--insecure-dev`).
pub fn resolve_access_control(
    mode: AccessControlMode,
    insecure_dev: bool,
    cedar_policy: Option<PathBuf>,
    cedar_entities: Option<PathBuf>,
) -> Result<AccessControlKind, String> {
    match mode {
        AccessControlMode::None if !insecure_dev => Err(
            "access control disabled (--access-control none) requires --insecure-dev; \
             development use only"
                .into(),
        ),
        AccessControlMode::None => Ok(AccessControlKind::None),
        AccessControlMode::Cedar => {
            let policy_path = cedar_policy
                .ok_or("cedar access control requires --cedar-policy or KAVACH_CEDAR_POLICY")?;
            let entities_path = cedar_entities
                .ok_or("cedar access control requires --cedar-entities or KAVACH_CEDAR_ENTITIES")?;
            Ok(AccessControlKind::Cedar {
                policy_path,
                entities_path,
            })
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_requires_insecure_dev() {
        let err = resolve_access_control(AccessControlMode::None, false, None, None)
            .expect_err("none without opt-in must fail");
        assert!(err.contains("--insecure-dev"));
        assert!(matches!(
            resolve_access_control(AccessControlMode::None, true, None, None),
            Ok(AccessControlKind::None)
        ));
    }

    #[test]
    fn cedar_requires_policy_and_entities() {
        let p = Some(PathBuf::from("p.cedar"));
        let e = Some(PathBuf::from("e.json"));
        assert!(resolve_access_control(AccessControlMode::Cedar, false, None, e.clone()).is_err());
        assert!(resolve_access_control(AccessControlMode::Cedar, false, p.clone(), None).is_err());
        assert!(matches!(
            resolve_access_control(AccessControlMode::Cedar, false, p, e),
            Ok(AccessControlKind::Cedar { .. })
        ));
    }
}

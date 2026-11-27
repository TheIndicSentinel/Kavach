use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)] // independent startup switches, not a state
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
    /// How Postgres connections are secured: `verify-full` unless the URL
    /// asks for less **and** this allows it (development only).
    pub database_tls: kavach_storage::DatabaseTls,
    /// Connections in the runtime Postgres pool.
    pub database_pool_size: u32,
    /// `--require-hardening`: the start was checked against
    /// `crate::hardening`, and the development routes are not mounted.
    pub require_hardening: bool,
    /// Stable owner-managed key file for D17 review snapshots. Off until set.
    pub review_snapshot_key_file: Option<PathBuf>,
    /// Rotation id authenticated into each encrypted D17 snapshot.
    pub review_snapshot_key_id: String,
    /// Agent surfaces (`/v1/authorize`, `/v1/sor/events`; ADR-007, H5a-5).
    pub dataplane: Option<crate::dataplane::DataplaneConfig>,
    /// Operator roles (ADR-019).
    pub roles: RolesConfig,
}

/// Operator roles (ADR-019): the tenant this process serves, and the
/// one-time superadmin bootstrap.
#[derive(Debug, Clone)]
pub struct RolesConfig {
    /// `KAVACH_TENANT_ID` (ADR-014 Tier 1: one tenant per process).
    pub tenant_id: String,
    /// `--bootstrap-superadmins`: empty, or exactly two different people.
    pub bootstrap_superadmins: Vec<kavach_storage::BindingSubject>,
    /// `--access-review-stale-days`: the access review marks a person
    /// stale when they were last seen longer ago than this, or never.
    pub access_review_stale_days: u32,
}

/// The default of `--access-review-stale-days`.
pub const DEFAULT_ACCESS_REVIEW_STALE_DAYS: u32 = 90;
/// The longest `--access-review-stale-days` accepted (ten years).
pub const MAX_ACCESS_REVIEW_STALE_DAYS: u32 = 3650;
/// Default key id for the D17 review-snapshot encryption key.
pub const DEFAULT_REVIEW_SNAPSHOT_KEY_ID: &str = "review-snapshot-1";

impl Default for RolesConfig {
    fn default() -> Self {
        Self {
            tenant_id: "default".into(),
            bootstrap_superadmins: Vec::new(),
            access_review_stale_days: DEFAULT_ACCESS_REVIEW_STALE_DAYS,
        }
    }
}

/// Parses `--bootstrap-superadmins` (`<iss>#<sub>,<iss>#<sub>`). Each entry
/// must name the configured OIDC issuer (an issuer has no `#`, so the first
/// `#` separates it from the subject), and the two must be different people.
/// Anything else is a startup error.
pub fn parse_bootstrap_superadmins(
    value: &str,
    oidc_issuer: Option<&str>,
) -> Result<Vec<kavach_storage::BindingSubject>, String> {
    let usage = "--bootstrap-superadmins needs exactly two different people as \
                 '<issuer>#<subject>,<issuer>#<subject>' (ADR-019 §5)";
    let Some(issuer) = oidc_issuer else {
        return Err(format!(
            "{usage}; it needs operator OIDC (--oidc-issuer), since a superadmin is an OIDC person"
        ));
    };
    let subjects = value
        .split(',')
        .map(|entry| {
            let entry = entry.trim();
            let (iss, sub) = entry
                .split_once('#')
                .filter(|(iss, sub)| !iss.is_empty() && !sub.is_empty())
                .ok_or_else(|| usage.to_string())?;
            if iss != issuer {
                return Err(format!(
                    "{usage}; an entry names issuer {iss:?}, not the configured --oidc-issuer"
                ));
            }
            Ok(kavach_storage::BindingSubject {
                kind: kavach_storage::SubjectKind::Principal,
                issuer: iss.to_string(),
                value: sub.to_string(),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    if subjects.len() != 2 || subjects[0] == subjects[1] {
        return Err(usage.into());
    }
    Ok(subjects)
}

/// The shortest `--hmac-secret` accepted, in bytes: the output size of
/// HMAC-SHA256, below which the key is the weakest part of the signature.
pub const MIN_HMAC_SECRET_BYTES: usize = 32;

/// Refuses an HMAC secret (`--hmac-secret`) shorter than
/// [`MIN_HMAC_SECRET_BYTES`], when one is set. Checked when the configuration is loaded, so a short secret stops the
/// start instead of weakening request signing quietly. The message never
/// contains the secret.
pub fn validate_hmac_secret(secret: Option<&str>) -> Result<(), String> {
    match secret {
        Some(secret) if secret.len() < MIN_HMAC_SECRET_BYTES => Err(format!(
            "--hmac-secret is {} bytes; it must be at least {MIN_HMAC_SECRET_BYTES} (generate one \
             with `openssl rand -hex 32`)",
            secret.len()
        )),
        _ => Ok(()),
    }
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
    fn a_short_hmac_secret_is_refused_at_load() {
        assert!(
            validate_hmac_secret(None).is_ok(),
            "no secret: no HMAC layer"
        );
        for short in ["", "s", "test-secret", &"x".repeat(31)] {
            let err = validate_hmac_secret(Some(short)).expect_err(short);
            assert!(err.contains("at least 32"), "{err}");
            // The message names the length, never the secret.
            assert!(short.len() < 4 || !err.contains(short), "{err}");
        }
        for long in [&"x".repeat(32), &"y".repeat(4096)] {
            assert!(validate_hmac_secret(Some(long)).is_ok());
        }
        // Bytes, not characters: 16 two-byte characters are 32 bytes.
        assert!(validate_hmac_secret(Some(&"é".repeat(16))).is_ok());
        assert!(validate_hmac_secret(Some(&"é".repeat(15))).is_err());
    }

    #[test]
    fn the_bootstrap_setting_takes_two_different_oidc_people() {
        let iss = "https://idp.example/realms/k";
        let ok = parse_bootstrap_superadmins(&format!("{iss}#alice, {iss}#bob#2"), Some(iss))
            .expect("two people");
        assert_eq!(ok[0].value, "alice");
        assert_eq!(ok[1].value, "bob#2", "a subject may contain '#'");
        for bad in [
            format!("{iss}#alice"),
            format!("{iss}#alice,{iss}#alice"),
            format!("{iss}#a,{iss}#b,{iss}#c"),
            format!("{iss}#alice,https://other.example#bob"),
            format!("{iss}#alice,bob"),
            format!("{iss}#alice,{iss}#"),
            String::new(),
        ] {
            assert!(
                parse_bootstrap_superadmins(&bad, Some(iss)).is_err(),
                "{bad}"
            );
        }
        let err =
            parse_bootstrap_superadmins(&format!("{iss}#a,{iss}#b"), None).expect_err("no OIDC");
        assert!(err.contains("--oidc-issuer"), "{err}");
    }

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

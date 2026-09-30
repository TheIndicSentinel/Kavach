use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, ValueEnum};
use kavach_api::{
    grpc_server_tls_config, resolve_access_control, router, serve_http, validate_principal_sources,
    AccessControlKind, AccessControlMode, ApiConfig, AppState, EvaluateServiceServer,
    EvidenceStoreKind, GrpcEvaluateService, JwksSource, MtlsSanKind, OidcConfig, TlsConfig,
    DEFAULT_CHANGE_TTL_HOURS,
};
use tonic::transport::Server;

#[derive(Copy, Clone, Debug, ValueEnum)]
enum EvidenceStoreArg {
    Memory,
    Postgres,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum AccessControlArg {
    None,
    Cedar,
}

/// OIDC / OAuth 2.0 JWT access tokens for API principals (ADR-008).
#[derive(clap::Args)]
#[allow(clippy::struct_field_names)] // field names become the `--oidc-*` flags
struct OidcArgs {
    /// Expected token issuer (`iss`), e.g. https://idp.bank.example/realms/kavach
    #[arg(long, env = "KAVACH_OIDC_ISSUER")]
    oidc_issuer: Option<String>,

    /// Expected audience (`aud`) for Kavach API tokens.
    #[arg(long, env = "KAVACH_OIDC_AUDIENCE")]
    oidc_audience: Option<String>,

    /// JWKS file with the issuer's signing keys (offline deployments).
    #[arg(long, env = "KAVACH_OIDC_JWKS_FILE", conflicts_with = "oidc_jwks_url")]
    oidc_jwks_file: Option<PathBuf>,

    /// HTTPS JWKS URL at the bank's identity provider (fetched at startup and refreshed).
    #[arg(long, env = "KAVACH_OIDC_JWKS_URL")]
    oidc_jwks_url: Option<String>,

    /// Claim holding the principal id.
    #[arg(long, env = "KAVACH_OIDC_PRINCIPAL_CLAIM", default_value = "sub")]
    oidc_principal_claim: String,

    /// Claim holding the principal's groups (array of strings).
    #[arg(long, env = "KAVACH_OIDC_GROUPS_CLAIM", default_value = "groups")]
    oidc_groups_claim: String,

    /// Allowed clock skew for `exp`/`nbf`.
    #[arg(long, env = "KAVACH_OIDC_LEEWAY_SECONDS", default_value_t = 60)]
    oidc_leeway_seconds: u64,
}

impl OidcArgs {
    fn into_config(self) -> Result<Option<OidcConfig>, String> {
        let jwks = match (self.oidc_jwks_file, self.oidc_jwks_url) {
            (Some(path), None) => Some(JwksSource::File(path)),
            (None, Some(url)) => Some(JwksSource::Url(url)),
            _ => None,
        };
        match (self.oidc_issuer, self.oidc_audience, jwks) {
            (None, None, None) => Ok(None),
            (Some(issuer), Some(audience), Some(jwks)) => Ok(Some(OidcConfig {
                issuer,
                audience,
                jwks,
                principal_claim: self.oidc_principal_claim,
                groups_claim: self.oidc_groups_claim,
                leeway_seconds: self.oidc_leeway_seconds,
            })),
            _ => Err("OIDC needs --oidc-issuer, --oidc-audience and one of \
                      --oidc-jwks-file / --oidc-jwks-url"
                .into()),
        }
    }
}

#[derive(Parser)]
#[command(name = "kavach-api", about = "Kavach sync evaluate HTTP + gRPC API")]
struct Cli {
    #[arg(long, default_value = "0.0.0.0:8080")]
    listen: SocketAddr,

    #[arg(long, default_value = "0.0.0.0:50051")]
    grpc_listen: SocketAddr,

    #[arg(long, env = "KAVACH_PACK_PATH")]
    pack: PathBuf,

    #[arg(long, env = "KAVACH_MODEL_PATH")]
    model: PathBuf,

    /// Expected SHA-256 of the pack file (`sha256:<hex>` or bare hex). Startup fails on mismatch.
    #[arg(long, env = "KAVACH_PACK_SHA256")]
    pack_sha256: Option<String>,

    /// When set, `/v1/evaluate` requires an HMAC v2 signature
    /// (`X-Kavach-Timestamp`, `X-Kavach-Nonce`, `X-Kavach-Signature`; ADR-008).
    #[arg(long, env = "KAVACH_HMAC_SECRET")]
    hmac_secret: Option<String>,

    #[command(flatten)]
    oidc: OidcArgs,

    #[arg(long, value_enum, default_value = "memory")]
    evidence_store: EvidenceStoreArg,

    #[arg(long, env = "KAVACH_DATABASE_URL")]
    database_url: Option<String>,

    /// Access control for API principals. Defaults to Cedar (secure by default).
    #[arg(
        long,
        value_enum,
        default_value = "cedar",
        env = "KAVACH_ACCESS_CONTROL"
    )]
    access_control: AccessControlArg,

    /// Postgres mode only: start even if `--pack` differs from the governed
    /// runtime pointer. Audited; for recovery, not routine use.
    #[arg(long, env = "KAVACH_BOOTSTRAP_PACK")]
    bootstrap_pack: bool,

    /// Postgres recovery: start with a model file that differs from the pinned
    /// one. Re-pins path and digest only (audited); status and mode stay governed.
    #[arg(long, env = "KAVACH_BOOTSTRAP_MODEL")]
    bootstrap_model: bool,

    /// Trusted pack signers file (JSON). When set, every pack load (startup,
    /// activate, rollback, model update) requires a valid `<pack>.sig`.
    #[arg(long, env = "KAVACH_PACK_SIGNERS")]
    pack_signers: Option<PathBuf>,

    /// Required to run with `--access-control none`. Development only: every request is allowed.
    #[arg(long, env = "KAVACH_INSECURE_DEV")]
    insecure_dev: bool,

    /// Cedar policy file (required when --access-control cedar).
    #[arg(long, env = "KAVACH_CEDAR_POLICY")]
    cedar_policy: Option<PathBuf>,

    /// Cedar entities JSON (required when --access-control cedar).
    #[arg(long, env = "KAVACH_CEDAR_ENTITIES")]
    cedar_entities: Option<PathBuf>,

    #[arg(long, env = "KAVACH_TLS_CERT")]
    tls_cert: Option<PathBuf>,

    #[arg(long, env = "KAVACH_TLS_KEY")]
    tls_key: Option<PathBuf>,

    /// When set with cert/key, require client certificate (mTLS).
    #[arg(long, env = "KAVACH_TLS_CLIENT_CA")]
    tls_client_ca: Option<PathBuf>,

    /// Use the client certificate's single SAN of this type (uri, e.g. a
    /// SPIFFE id, or dns) as the principal. Requires --tls-client-ca.
    #[arg(long, env = "KAVACH_MTLS_PRINCIPAL_SAN", value_enum)]
    mtls_principal_san: Option<MtlsSanKind>,

    /// Hours a change request stays approvable (1-168).
    #[arg(
        long,
        env = "KAVACH_CHANGE_REQUEST_TTL_HOURS",
        default_value_t = DEFAULT_CHANGE_TTL_HOURS,
        value_parser = clap::value_parser!(u64).range(1..=168)
    )]
    change_request_ttl_hours: u64,
}

impl Cli {
    fn into_config(self) -> Result<ApiConfig, String> {
        let evidence_store = match self.evidence_store {
            EvidenceStoreArg::Memory => EvidenceStoreKind::Memory,
            EvidenceStoreArg::Postgres => {
                let database_url = self.database_url.ok_or(
                    "postgres evidence store requires --database-url or KAVACH_DATABASE_URL",
                )?;
                EvidenceStoreKind::Postgres { database_url }
            }
        };

        let mode = match self.access_control {
            AccessControlArg::None => AccessControlMode::None,
            AccessControlArg::Cedar => AccessControlMode::Cedar,
        };
        let access_control = resolve_access_control(
            mode,
            self.insecure_dev,
            self.cedar_policy,
            self.cedar_entities,
        )?;
        let oidc = self.oidc.into_config()?;

        let tls = match (self.tls_cert, self.tls_key) {
            (Some(cert_path), Some(key_path)) => Some(TlsConfig::from_paths(
                cert_path,
                key_path,
                self.tls_client_ca,
            )),
            (None, None) => None,
            _ => {
                return Err("TLS requires both --tls-cert and --tls-key".into());
            }
        };

        let config = ApiConfig {
            pack_path: self.pack,
            model_path: self.model,
            hmac_secret: self.hmac_secret,
            evidence_store,
            access_control,
            tls,
            pack_sha256: self.pack_sha256,
            bootstrap_pack: self.bootstrap_pack,
            bootstrap_model: self.bootstrap_model,
            pack_signers: self.pack_signers,
            oidc,
            insecure_dev: self.insecure_dev,
            mtls_principal_san: self.mtls_principal_san,
            change_ttl_seconds: self.change_request_ttl_hours * 3600,
        };
        validate_principal_sources(&config)?;
        Ok(config)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cli = Cli::parse();
    let http_listen = cli.listen;
    let grpc_listen = cli.grpc_listen;
    let config = cli
        .into_config()
        .map_err(|msg| std::io::Error::new(std::io::ErrorKind::InvalidInput, msg))?;
    let state = Arc::new(AppState::from_config(&config).await?);
    let pack_sha256 = state.runtime().pack_sha256.unwrap_or_else(|| "none".into());
    let http_app = router(state.clone());
    let grpc_service = EvaluateServiceServer::new(GrpcEvaluateService::new(state));

    let tls_mode = if config.tls.as_ref().is_some_and(TlsConfig::is_mtls) {
        "mTLS"
    } else if config.tls.is_some() {
        "TLS"
    } else {
        "plain"
    };

    let insecure = matches!(config.access_control, AccessControlKind::None);
    let principal_sources = [
        (config.oidc.is_some(), "oidc-jwt"),
        (config.mtls_principal_san.is_some(), "mtls-san"),
        (config.insecure_dev, "insecure-header"),
    ]
    .iter()
    .filter(|(on, _)| *on)
    .map(|(_, name)| *name)
    .collect::<Vec<_>>()
    .join("+");
    let principal_sources = if principal_sources.is_empty() {
        "none".to_string()
    } else {
        principal_sources
    };
    if config.insecure_dev && !insecure {
        eprintln!(
            "WARNING: kavach-api: --insecure-dev accepts the self-asserted X-Kavach-Principal \
             header. Anyone who can reach this port can claim any principal. Development only."
        );
    }
    if insecure {
        eprintln!(
            "WARNING: kavach-api running with --insecure-dev: access control is DISABLED and \
             every request is allowed. Never use this outside local development."
        );
    }
    eprintln!(
        "kavach-api listening http={} grpc={} transport={} evidence={:?} access_control={:?} \
         principal_sources={principal_sources} insecure_dev={} pack_sha256={}",
        http_listen,
        grpc_listen,
        tls_mode,
        config.evidence_store,
        config.access_control,
        insecure,
        pack_sha256
    );

    let tls_ref = config.tls.as_ref();
    tokio::try_join!(
        async move {
            serve_http(http_app, http_listen, tls_ref).await?;
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        },
        async move {
            let mut builder = Server::builder();
            if let Some(server_tls) = grpc_server_tls_config(tls_ref).await? {
                builder = builder.tls_config(server_tls)?;
            }
            builder.add_service(grpc_service).serve(grpc_listen).await?;
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        }
    )?;

    Ok(())
}

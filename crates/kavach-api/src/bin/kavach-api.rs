use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, ValueEnum};
use kavach_api::{
    grpc_server_tls_config, resolve_access_control, router, serve_http, AccessControlKind,
    AccessControlMode, ApiConfig, AppState, EvaluateServiceServer, EvidenceStoreKind,
    GrpcEvaluateService, TlsConfig,
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

    /// When set, requires `X-Kavach-Signature: sha256=<hex>` over the raw HTTP request body.
    #[arg(long, env = "KAVACH_HMAC_SECRET")]
    hmac_secret: Option<String>,

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

        Ok(ApiConfig {
            pack_path: self.pack,
            model_path: self.model,
            hmac_secret: self.hmac_secret,
            evidence_store,
            access_control,
            tls,
            pack_sha256: self.pack_sha256,
        })
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
    if insecure {
        eprintln!(
            "WARNING: kavach-api running with --insecure-dev: access control is DISABLED and \
             every request is allowed. Never use this outside local development."
        );
    }
    eprintln!(
        "kavach-api listening http={} grpc={} transport={} evidence={:?} access_control={:?} \
         insecure_dev={} pack_sha256={}",
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

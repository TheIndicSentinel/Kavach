use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use kavach_api::{router, AppState, EvaluateServiceServer, GrpcEvaluateService};
use tonic::transport::Server;

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

    /// When set, requires `X-Kavach-Signature: sha256=<hex>` over the raw HTTP request body.
    #[arg(long, env = "KAVACH_HMAC_SECRET")]
    hmac_secret: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let state = Arc::new(AppState::from_paths(
        &cli.pack,
        &cli.model,
        cli.hmac_secret,
    )?);

    let http_app = router(state.clone());
    let http_listener = tokio::net::TcpListener::bind(cli.listen).await?;
    let grpc_service = EvaluateServiceServer::new(GrpcEvaluateService::new(state));

    eprintln!(
        "kavach-api listening http={} grpc={}",
        cli.listen, cli.grpc_listen
    );

    tokio::try_join!(
        async move {
            axum::serve(http_listener, http_app).await?;
            Ok::<(), Box<dyn std::error::Error>>(())
        },
        async move {
            Server::builder()
                .add_service(grpc_service)
                .serve(cli.grpc_listen)
                .await?;
            Ok::<(), Box<dyn std::error::Error>>(())
        }
    )?;

    Ok(())
}

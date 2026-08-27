use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use kavach_api::{router, AppState};

#[derive(Parser)]
#[command(name = "kavach-api", about = "Kavach sync evaluate HTTP API")]
struct Cli {
    #[arg(long, default_value = "0.0.0.0:8080")]
    listen: SocketAddr,

    #[arg(long, env = "KAVACH_PACK_PATH")]
    pack: PathBuf,

    #[arg(long, env = "KAVACH_MODEL_PATH")]
    model: PathBuf,

    /// When set, requires `X-Kavach-Signature: sha256=<hex>` over the raw request body.
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
    let app = router(state);

    let listener = tokio::net::TcpListener::bind(cli.listen).await?;
    eprintln!("kavach-api listening on {}", cli.listen);
    axum::serve(listener, app).await?;
    Ok(())
}

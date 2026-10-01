//! PROTOCOL FIXTURE: a mock messaging provider that accepts only Kavach
//! credentials. Not a real provider; never deploy it as one.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Parser, Subcommand};
use kavach_credential::DecryptionKey;
use kavach_jws::KeySet;
use kavach_mock_provider::{inspect_router, router, MockProvider, ProviderConfig};
use kavach_ports::{KeyAlgorithm, PublicKey};
use serde::Deserialize;

#[derive(Parser)]
#[command(
    name = "kavach-mock-provider",
    about = "PROTOCOL FIXTURE: mock messaging provider for Kavach credentials"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate this provider's X25519 encryption key (owner-only file) and
    /// print its entry for Kavach's `--providers` file.
    Keygen {
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        kid: String,
        #[arg(long, default_value = "mock-messaging")]
        audience: String,
    },
    /// Serve the provider API and the inspection listener.
    Serve {
        #[arg(long, env = "MOCK_PROVIDER_LISTEN", default_value = "127.0.0.1:8095")]
        listen: SocketAddr,
        /// Delivered messages (synthetic destinations): loopback or the
        /// backend network only.
        #[arg(
            long,
            env = "MOCK_PROVIDER_INSPECT_LISTEN",
            default_value = "127.0.0.1:8099"
        )]
        inspect_listen: SocketAddr,
        #[arg(long, env = "MOCK_PROVIDER_AUDIENCE", default_value = "mock-messaging")]
        audience: String,
        /// Hex X25519 private key file (from `keygen`).
        #[arg(long, env = "MOCK_PROVIDER_ENCRYPTION_KEY")]
        encryption_key: PathBuf,
        #[arg(long, env = "MOCK_PROVIDER_ENCRYPTION_KID")]
        encryption_kid: String,
        /// JSON `{"keys": [{"kid", "public_key"}]}`: trusted credential
        /// signing keys (hex Ed25519).
        #[arg(long, env = "MOCK_PROVIDER_CREDENTIAL_KEYS")]
        credential_keys: PathBuf,
        #[arg(long, default_value_t = 2)]
        leeway_seconds: i64,
        #[arg(long, default_value_t = 30)]
        hang_seconds: u64,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeysFile {
    keys: Vec<KeyEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyEntry {
    kid: String,
    public_key: String,
}

fn hex32(text: &str, what: &str) -> Result<[u8; 32], String> {
    hex::decode(text.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| format!("{what} must be 32 bytes hex"))
}

fn write_owner_only(path: &Path, contents: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(contents.as_bytes())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    kavach_telemetry::init(kavach_telemetry::LogFormat::Text)?;
    match Cli::parse().command {
        Command::Keygen { out, kid, audience } => {
            let mut secret = [0u8; 32];
            getrandom::fill(&mut secret).map_err(|e| format!("os rng: {e}"))?;
            write_owner_only(&out, &hex::encode(secret))?;
            let public = DecryptionKey::from_bytes(kid.clone(), secret)
                .recipient()
                .public;
            println!(
                "{}",
                serde_json::json!({ "audience": audience, "kid": kid, "x25519_public_key": hex::encode(public) })
            );
        }
        Command::Serve {
            listen,
            inspect_listen,
            audience,
            encryption_key,
            encryption_kid,
            credential_keys,
            leeway_seconds,
            hang_seconds,
        } => {
            let secret = hex32(&std::fs::read_to_string(&encryption_key)?, "encryption key")?;
            let file: KeysFile = serde_json::from_str(&std::fs::read_to_string(&credential_keys)?)?;
            let keys = file
                .keys
                .into_iter()
                .map(|k| {
                    Ok(PublicKey {
                        bytes: hex32(&k.public_key, &format!("credential key {}", k.kid))?,
                        kid: k.kid,
                        algorithm: KeyAlgorithm::Ed25519,
                    })
                })
                .collect::<Result<Vec<_>, String>>()?;
            if keys.is_empty() {
                return Err("no trusted credential keys".into());
            }
            let mut config = ProviderConfig::new(
                audience.clone(),
                DecryptionKey::from_bytes(encryption_kid, secret),
                KeySet::new(keys),
            );
            config.leeway_seconds = leeway_seconds;
            config.hang = Duration::from_secs(hang_seconds);
            let provider = MockProvider::with_system_clock(config);
            tracing::warn!(
                "PROTOCOL FIXTURE (not a real provider). audience {audience}; API on {listen}; \
                 inbox on {inspect_listen}"
            );
            let api = tokio::net::TcpListener::bind(listen).await?;
            let inspect = tokio::net::TcpListener::bind(inspect_listen).await?;
            tokio::try_join!(
                axum::serve(api, router(provider.clone())),
                axum::serve(inspect, inspect_router(provider)),
            )?;
        }
    }
    Ok(())
}

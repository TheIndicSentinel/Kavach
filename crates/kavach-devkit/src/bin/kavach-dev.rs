//! DEVELOPMENT ONLY: generate a Kavach dev bundle and drive a dev stack.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "kavach-dev",
    about = "DEVELOPMENT ONLY: Kavach dev bundle and dev-stack helpers"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Write a complete dev bundle (dev- keys, signed registry, dev CA,
    /// fixtures, tokens). The directory should be new or empty.
    Generate {
        #[arg(long)]
        out: PathBuf,
        /// Where <out>/kavach is mounted for kavach-api (paths in kavach.env).
        #[arg(long, default_value = "/etc/kavach")]
        kavach_mount: String,
        /// The provider base URL the gateway forwards to (https only).
        #[arg(long, default_value = "https://mock-provider:8443")]
        provider_endpoint: String,
        /// DNS names and IPs for the provider's TLS certificate.
        #[arg(long = "provider-host", default_values_t = ["mock-provider".to_string()])]
        provider_hosts: Vec<String>,
        #[arg(long, default_value_t = 24)]
        token_hours: i64,
    },
    /// Sign a system-of-record event with the bundle's dev SoR key and post
    /// it to Kavach's SoR listener; prints the response (the mandate id).
    SorEvent {
        #[arg(long)]
        bundle: PathBuf,
        /// e.g. http://172.30.20.10:8090/v1/sor/events
        #[arg(long)]
        url: String,
        #[arg(long)]
        event_id: String,
        #[arg(long, default_value = kavach_devkit::SUBJECT)]
        subject_ref: String,
        #[arg(long, default_value = "collections-agent")]
        agent: String,
    },
    /// The test agent's checks, run from inside the agent network: only the
    /// agent listener is reachable, the agent holds no key material, and
    /// the gateway is the only way to act. Exit status = result.
    ProbeIsolation {
        #[arg(long)]
        agent_url: String,
        /// The agent listener's host:port (must be reachable).
        #[arg(long)]
        agent_listener: String,
        /// host:port that must be unreachable (repeat).
        #[arg(long = "must-fail")]
        must_fail: Vec<String>,
        /// Names that must not be reachable (repeat).
        #[arg(long = "must-not-resolve")]
        must_not_resolve: Vec<String>,
        #[arg(long)]
        token_file: PathBuf,
        #[arg(long)]
        mandate_file: PathBuf,
        /// Directories readable by the agent, scanned for key material.
        #[arg(long = "scan-dir")]
        scan_dirs: Vec<PathBuf>,
        /// Fail unless a reminder is delivered (the scheduled midday run).
        #[arg(long, env = "REQUIRE_DELIVERY")]
        require_delivery: bool,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().command {
        Command::Generate {
            out,
            kavach_mount,
            provider_endpoint,
            provider_hosts,
            token_hours,
        } => {
            let summary = kavach_devkit::generate(&kavach_devkit::Options {
                out,
                kavach_mount,
                provider_endpoint,
                provider_hosts,
                token_hours,
            })
            .await?;
            println!(
                "DEVELOPMENT bundle written to {} (tool registry {}; agents: {})",
                summary.out.display(),
                summary.registry_sha256,
                summary.agents.join(", ")
            );
        }
        Command::SorEvent {
            bundle,
            url,
            event_id,
            subject_ref,
            agent,
        } => {
            let event = kavach_devkit::sor_event(
                &bundle,
                &event_id,
                &subject_ref,
                &agent,
                chrono::Utc::now(),
            )
            .await?;
            let response = reqwest::Client::new()
                .post(&url)
                .json(&serde_json::json!({ "event": event }))
                .send()
                .await?;
            let status = response.status();
            let body = response.text().await?;
            println!("{body}");
            if !status.is_success() {
                return Err(format!("SoR listener answered {status}").into());
            }
        }
        Command::ProbeIsolation {
            agent_url,
            agent_listener,
            must_fail,
            must_not_resolve,
            token_file,
            mandate_file,
            scan_dirs,
            require_delivery,
        } => {
            let ok = kavach_devkit::probe::run(&kavach_devkit::probe::ProbeOptions {
                agent_url,
                agent_listener,
                must_fail,
                must_not_resolve,
                token_file,
                mandate_file,
                scan_dirs,
                require_delivery,
            })
            .await?;
            if !ok {
                std::process::exit(1);
            }
        }
    }
    Ok(())
}

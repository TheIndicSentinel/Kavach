//! DEVELOPMENT ONLY: generate a Kavach dev bundle and drive a dev stack.

use std::path::{Path, PathBuf};

use chrono::Utc;
use clap::{Parser, Subcommand};
use kavach_domain::authority::{AuthorityChange, AuthorityUpdateEvent};
use kavach_domain::mandate::{ConsentRecord, ContactPreferenceRecord};
use kavach_keys::LocalFileKeyProvider;

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
        /// DNS names and IPs for Postgres's TLS certificate.
        #[arg(long = "database-host", default_values_t = ["postgres".to_string()])]
        database_hosts: Vec<String>,
        #[arg(long, default_value_t = 24)]
        token_hours: i64,
        /// The `iss` of the minted tokens and KAVACH_OIDC_ISSUER; a test
        /// IdP's origin when its tokens and the bundle's must both verify.
        #[arg(long, default_value = kavach_devkit::ISSUER)]
        issuer: String,
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
        /// Send this revoking event (loan.paid or loan.disputed) for the
        /// borrower's loan instead of an assignment: it revokes every
        /// mandate issued for that loan.
        #[arg(long)]
        revoke: Option<String>,
    },
    /// Sign and post this bundle's synthetic consent and contact preferences
    /// to the development stack's persistent authority-update route.
    SeedAuthority {
        #[arg(long)]
        bundle: PathBuf,
        /// e.g. http://127.0.0.1:8090/v1/sor/authority-updates
        #[arg(long)]
        url: String,
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
            database_hosts,
            token_hours,
            issuer,
        } => {
            let summary = kavach_devkit::generate(&kavach_devkit::Options {
                out,
                kavach_mount,
                provider_endpoint,
                provider_hosts,
                database_hosts,
                token_hours,
                issuer,
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
            revoke,
        } => {
            let now = chrono::Utc::now();
            let event = match revoke {
                Some(event_type) => {
                    kavach_devkit::revoking_event(
                        &bundle,
                        &event_id,
                        &subject_ref,
                        &event_type,
                        now,
                    )
                    .await?
                }
                None => {
                    kavach_devkit::sor_event(&bundle, &event_id, &subject_ref, &agent, now).await?
                }
            };
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
        Command::SeedAuthority { bundle, url } => {
            seed_authority_updates(&bundle, &url).await?;
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

async fn seed_authority_updates(
    bundle: &Path,
    url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let kavach = bundle.join("kavach");
    let consents: Vec<ConsentRecord> =
        serde_json::from_slice(&std::fs::read(kavach.join("consents.json"))?)?;
    let preferences: Vec<ContactPreferenceRecord> =
        serde_json::from_slice(&std::fs::read(kavach.join("contact-preferences.json"))?)?;
    if !consents.iter().any(|record| record.active) || preferences.is_empty() {
        return Err("the development bundle needs active consent and explicit preferences".into());
    }

    let keys = LocalFileKeyProvider::new(bundle.join("sor"));
    let client = reqwest::Client::new();
    let mut posted = 0usize;
    for (kind, changes) in [
        (
            "consent",
            consents
                .into_iter()
                .filter(|record| record.active)
                .map(AuthorityChange::Consent)
                .collect::<Vec<_>>(),
        ),
        (
            "preference",
            preferences
                .into_iter()
                .map(AuthorityChange::ContactPreference)
                .collect::<Vec<_>>(),
        ),
    ] {
        for (index, change) in changes.into_iter().enumerate() {
            let now = Utc::now();
            let suffix = now.timestamp_micros();
            let update_id = format!("demo-{kind}-{index}-{suffix}");
            let event = AuthorityUpdateEvent {
                update_id: update_id.clone(),
                tenant_id: "default".into(),
                system: "lms".into(),
                occurred_at: now,
                nonce: update_id,
                change,
            };
            let token = kavach_mandate::jws::sign(
                &keys,
                kavach_devkit::SOR_KID,
                kavach_mandate::jws::TYP_AUTHORITY_UPDATE,
                &event,
            )
            .await?;
            let response = client
                .post(url)
                .json(&serde_json::json!({ "event": token }))
                .send()
                .await?;
            let status = response.status();
            let body = response.text().await?;
            if !status.is_success() {
                return Err(format!("SoR {kind} update answered {status}: {body}").into());
            }
            posted += 1;
        }
    }
    println!("seeded {posted} synthetic consent and preference authority updates");
    Ok(())
}

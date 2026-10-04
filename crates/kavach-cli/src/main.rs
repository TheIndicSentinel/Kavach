//! `kavach`: the developer command line.
//!
//! Conventions (clig.dev): `noun verb` commands, `--help` everywhere, human
//! output on stdout and errors on stderr, `--json` on every command (one
//! versioned document), stable exit codes (0 ok, 1 failed or blocked,
//! 2 warnings, 64 usage), colour only on a terminal and never with
//! `NO_COLOR`, no prompts. Nothing is sent anywhere: no telemetry.

mod authorize;
mod dev;
mod doctor;
mod init;
mod output;
mod project;

use std::path::PathBuf;

use clap::{CommandFactory, Parser, Subcommand};
use output::{CliError, Ui, EXIT_INTERNAL, EXIT_OK, EXIT_USAGE};

#[derive(Parser)]
#[command(
    name = "kavach",
    version,
    about = "Authorization and runtime control for AI agents: the developer command line",
    long_about = "Authorization and runtime control for AI agents: the developer command line.\n\n\
                  Start with `kavach init`, check with `kavach doctor`, try decisions offline with\n\
                  `kavach authorize`, run with `kavach dev up`.\n\
                  Everything here is for development: loopback only, dev- keys, no telemetry.",
    propagate_version = true
)]
struct Cli {
    /// Print one JSON document (schema kavach.cli/v1) instead of text.
    #[arg(long, global = true)]
    json: bool,
    /// The project directory (default: this one, or the nearest parent
    /// with a kavach.toml).
    #[arg(
        long,
        short = 'C',
        global = true,
        value_name = "DIR",
        default_value = "."
    )]
    project: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a dev project: dev- keys, a signed tool registry, synthetic
    /// references, kavach.toml, and a .gitignore entry for the keys.
    Init {
        /// Where to create it (default: the project directory).
        dir: Option<PathBuf>,
    },
    /// Check this machine and project, and say what to fix.
    Doctor,
    /// Run Kavach locally.
    #[command(subcommand)]
    Dev(DevCommand),
    /// What the gateway would decide for a tool call: offline, in this
    /// process, nothing recorded. Exit 0 if allowed, 1 if not.
    #[command(
        after_help = "Examples:\n  kavach authorize send_reminder\n  kavach authorize send_reminder --at 20:30\n  kavach authorize send_reminder --contacts-today 3\n  kavach authorize propose_plan --param waiver_bps=2500\n  kavach authorize send_reminder --param subject_ref=ref:borrower:9876543210"
    )]
    Authorize {
        /// The tool, as the registry names it (send_reminder, place_call,
        /// read_fields, propose_plan).
        tool: String,
        /// A tool parameter (repeatable). Required ones left out get a
        /// default, which the output lists.
        #[arg(long = "param", short = 'p', value_name = "NAME=VALUE", value_parser = authorize::parse_param)]
        params: Vec<(String, String)>,
        /// The calling agent.
        #[arg(long, default_value = authorize::DEFAULT_AGENT)]
        agent: String,
        /// The borrower the what-if mandate covers (and the default
        /// subject_ref).
        #[arg(long, default_value = authorize::DEFAULT_SUBJECT)]
        subject: String,
        /// The agent the what-if mandate assigns the borrower to.
        #[arg(long, value_name = "AGENT", default_value = authorize::DEFAULT_AGENT)]
        mandate_for: String,
        /// Decide at this time today (HH:MM, IST) instead of now.
        #[arg(long, value_name = "HH:MM", value_parser = dev::parse_hhmm)]
        at: Option<String>,
        /// Contacts already made with the borrower today.
        #[arg(long, value_name = "N", default_value_t = 0)]
        contacts_today: u32,
    },
}

#[derive(Subcommand)]
enum DevCommand {
    /// Start Kavach and a mock provider in this process, on loopback only.
    Up {
        /// Start the clock at this time today (HH:MM, IST): contact is
        /// allowed 08:00–19:00 IST, so demos outside those hours need it.
        #[arg(long, value_name = "HH:MM", value_parser = dev::parse_hhmm)]
        at: Option<String>,
        /// Start, print where everything is, and exit (for scripts and CI).
        #[arg(long, hide = true)]
        exit_when_ready: bool,
    },
}

fn main() {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            use clap::error::ErrorKind;
            let code = match e.kind() {
                ErrorKind::DisplayHelp
                | ErrorKind::DisplayVersion
                | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => EXIT_OK,
                _ => EXIT_USAGE,
            };
            let _ = e.print();
            std::process::exit(code);
        }
    };
    let ui = Ui::new(cli.json);
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => {
            let mut error = CliError::new("cannot start", e);
            error.code = EXIT_INTERNAL;
            std::process::exit(ui.error("kavach", &error));
        }
    };
    let (name, result) = runtime.block_on(async {
        match &cli.command {
            Command::Init { dir } => (
                "init",
                init::run(&ui, dir.as_ref().unwrap_or(&cli.project)).await,
            ),
            Command::Doctor => ("doctor", doctor::run(&ui, &cli.project).await),
            Command::Authorize {
                tool,
                params,
                agent,
                subject,
                mandate_for,
                at,
                contacts_today,
            } => (
                "authorize",
                authorize::run(
                    &ui,
                    &cli.project,
                    &authorize::Ask {
                        tool,
                        agent,
                        subject,
                        mandate_for,
                        params,
                        at: at.as_deref(),
                        contacts_today: *contacts_today,
                    },
                )
                .await,
            ),
            Command::Dev(DevCommand::Up {
                at,
                exit_when_ready,
            }) => (
                "dev up",
                dev::up(&ui, &cli.project, at.as_deref(), *exit_when_ready).await,
            ),
        }
    });
    let code = match result {
        Ok(code) => code,
        Err(e) => ui.error(name, &e),
    };
    std::process::exit(code);
}

/// The command tree, for tests that check help and conventions.
#[allow(dead_code)]
fn command() -> clap::Command {
    Cli::command()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_command_tree_is_well_formed() {
        Cli::command().debug_assert();
        assert_eq!(EXIT_INTERNAL, 70);
    }
}

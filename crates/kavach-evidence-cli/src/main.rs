use std::path::PathBuf;
use std::process;

use clap::{Parser, Subcommand};
use kavach_evidence::verify_export_file;

#[derive(Parser)]
#[command(name = "kavach-evidence", about = "Kavach evidence chain tools")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// The chain to read and the database to read it from.
#[cfg(feature = "export")]
#[derive(clap::Args)]
struct TargetArgs {
    /// Postgres URL of the read-only `kavach_auditor` role. Prefer the
    /// environment variable: a URL on the command line is visible to other
    /// users of the machine.
    #[arg(long, env = "KAVACH_AUDITOR_DATABASE_URL", hide_env_values = true)]
    database_url: String,
    #[arg(long, default_value = "default")]
    tenant: String,
    #[arg(long, default_value_t = 0)]
    partition: i32,
    /// Accept a database role that could change the evidence. Development
    /// stacks only.
    #[arg(long)]
    allow_write_role: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Verify an exported evidence file (NDJSON or JSON array).
    Verify {
        /// Path to export file.
        #[arg(short, long)]
        file: PathBuf,
    },
    /// Export the agent evidence chain as a bundle (docs/EVIDENCE_BUNDLE.md).
    #[cfg(feature = "export")]
    Export {
        #[command(flatten)]
        target: TargetArgs,
        /// Directory to create. It must not exist.
        #[arg(long)]
        out: PathBuf,
        /// Export only the records after the checkpoint at this record.
        #[arg(long)]
        after_checkpoint: Option<i64>,
        /// Directory holding the export key (`<key-id>.ed25519`, owner-only).
        #[arg(long, requires = "key_id", conflicts_with = "unsigned")]
        key_dir: Option<PathBuf>,
        /// The export key: an id starting with `export-`. It belongs to
        /// whoever exports and is never a key of the API.
        #[arg(long, requires = "key_dir")]
        key_id: Option<String>,
        /// Write the bundle without a signature. Nothing then vouches for
        /// the set of outcomes, and the verifier says so.
        #[arg(long)]
        unsigned: bool,
    },
    /// Print stored checkpoints as JSON lines, to copy off-host.
    #[cfg(feature = "export")]
    Checkpoints {
        #[command(flatten)]
        target: TargetArgs,
        /// Only the newest checkpoint.
        #[arg(long, conflicts_with = "after")]
        latest: bool,
        /// Checkpoints of records after this one (0: all).
        #[arg(long)]
        after: Option<i64>,
    },
}

#[cfg(feature = "export")]
mod database {
    use std::path::Path;

    use kavach_evidence_cli::postgres::{run_checkpoints, run_export, Signing, Target, Which};

    use super::TargetArgs;

    fn target(args: TargetArgs) -> Target {
        Target {
            database_url: args.database_url,
            tenant_id: args.tenant,
            partition_id: args.partition,
            allow_write_role: args.allow_write_role,
        }
    }

    fn runtime() -> Result<tokio::runtime::Runtime, String> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("runtime: {e}"))
    }

    pub fn export(
        args: TargetArgs,
        out: &Path,
        after_checkpoint: Option<i64>,
        signing: &Signing,
    ) -> Result<(), String> {
        let summary = runtime()?
            .block_on(run_export(&target(args), after_checkpoint, out, signing))
            .map_err(|e| e.to_string())?;
        let p = &summary.manifest.payload;
        println!(
            "OK: exported {} record(s) (after {} through {}), {} outcome(s), {} checkpoint(s) to {}",
            p.files.records.count,
            p.segment.after_seq,
            p.segment.last_seq,
            p.files.outcomes.count,
            p.files.checkpoints.count,
            out.display()
        );
        println!("manifest hash: {}", summary.manifest.hash);
        match &p.key_id {
            Some(key_id) => println!("signed with: {key_id}"),
            None => eprintln!(
                "WARNING: the bundle is UNSIGNED: nothing vouches for the set of outcomes"
            ),
        }
        match summary.last_checkpoint {
            None => eprintln!("WARNING: no checkpoint covers these records"),
            Some(seq) if summary.uncovered_records > 0 => eprintln!(
                "NOTE: {} record(s) are newer than the last checkpoint (record {seq})",
                summary.uncovered_records
            ),
            Some(_) => {}
        }
        Ok(())
    }

    pub fn checkpoints(args: TargetArgs, which: Which) -> Result<(), String> {
        let checkpoints = runtime()?
            .block_on(run_checkpoints(&target(args), which))
            .map_err(|e| e.to_string())?;
        for checkpoint in &checkpoints {
            println!(
                "{}",
                serde_json::to_string(checkpoint).map_err(|e| e.to_string())?
            );
        }
        if checkpoints.is_empty() {
            eprintln!("NOTE: no checkpoints");
        }
        Ok(())
    }
}

fn run(command: Commands) -> Result<(), String> {
    match command {
        Commands::Verify { file } => {
            let report = verify_export_file(&file).map_err(|e| e.to_string())?;
            println!(
                "OK: verified {} event(s); head_hash={}",
                report.events_checked, report.head_hash
            );
            Ok(())
        }
        #[cfg(feature = "export")]
        Commands::Export {
            target,
            out,
            after_checkpoint,
            key_dir,
            key_id,
            unsigned,
        } => {
            use kavach_evidence_cli::postgres::Signing;
            let signing =
                match (key_dir, key_id, unsigned) {
                    (Some(key_dir), Some(key_id), false) => Signing::Key { key_dir, key_id },
                    (None, None, true) => Signing::Unsigned,
                    _ => return Err(
                        "sign the bundle with --key-dir and --key-id (an export- key), or pass \
                         --unsigned to write it without a signature"
                            .into(),
                    ),
                };
            database::export(target, &out, after_checkpoint, &signing)
        }
        #[cfg(feature = "export")]
        Commands::Checkpoints {
            target,
            latest,
            after,
        } => {
            use kavach_evidence_cli::postgres::Which;
            let which = match (latest, after) {
                (true, _) => Which::Latest,
                (false, Some(seq)) => Which::After(seq),
                (false, None) => return Err("pass --latest or --after <seq>".into()),
            };
            database::checkpoints(target, which)
        }
    }
}

fn main() {
    if let Err(err) = run(Cli::parse().command) {
        eprintln!("FAIL: {err}");
        process::exit(1);
    }
}

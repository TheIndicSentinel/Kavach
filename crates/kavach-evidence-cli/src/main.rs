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

#[derive(Subcommand)]
enum Commands {
    /// Verify an exported evidence file (NDJSON or JSON array).
    Verify {
        /// Path to export file.
        #[arg(short, long)]
        file: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Verify { file } => match verify_export_file(&file) {
            Ok(report) => {
                println!(
                    "OK: verified {} event(s); head_hash={}",
                    report.events_checked, report.head_hash
                );
            }
            Err(err) => {
                eprintln!("FAIL: {err}");
                process::exit(1);
            }
        },
    }
}

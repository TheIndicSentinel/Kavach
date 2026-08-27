use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use kavach_batch::{run_batch, BatchConfig};
use kavach_evaluate::VecIncidentRecorder;
use kavach_evidence::MemoryChain;

#[derive(Parser)]
#[command(name = "kavach-batch", about = "Kavach NDJSON batch evaluate worker")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Process an NDJSON file of EvaluateRequest rows.
    Run {
        #[arg(long)]
        input: PathBuf,

        #[arg(long)]
        output: PathBuf,

        #[arg(long, env = "KAVACH_PACK_PATH")]
        pack: PathBuf,

        #[arg(long, env = "KAVACH_MODEL_PATH")]
        model: PathBuf,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Command::Run {
            input,
            output,
            pack,
            model,
        } => {
            let input_file = File::open(input)?;
            let output_file = File::create(output)?;
            let mut writer = BufWriter::new(output_file);
            let report = run_batch(
                input_file,
                &mut writer,
                &BatchConfig {
                    pack_path: pack,
                    model_path: model,
                    ..BatchConfig::default()
                },
                MemoryChain::new(),
                VecIncidentRecorder::default(),
            )?;
            writer.flush()?;
            eprintln!(
                "kavach-batch job={} total={} succeeded={} failed={} skipped={}",
                report.job_id, report.total_rows, report.succeeded, report.failed, report.skipped
            );
            if report.failed > 0 {
                std::process::exit(1);
            }
        }
    }
    Ok(())
}

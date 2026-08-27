use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use kavach_batch::{
    run_batch, run_disparity_report, run_inclusion_report, BatchConfig, BatchRunContext,
    FairnessConfig, FairnessReport,
};
use kavach_evaluate::VecIncidentRecorder;
use kavach_evidence::MemoryChain;
use kavach_storage::{EvidenceBackend, IncidentBackend, NoopBatchJobStore, StoragePool};

#[derive(Copy, Clone, Debug, ValueEnum)]
enum EvidenceStoreArg {
    Memory,
    Postgres,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum FairnessReportKind {
    Disparity,
    Inclusion,
}

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

        #[arg(long, value_enum, default_value = "memory")]
        evidence_store: EvidenceStoreArg,

        #[arg(long, env = "KAVACH_DATABASE_URL")]
        database_url: Option<String>,
    },
    /// Generate a fairness batch report from paired NDJSON request/result files.
    Fairness {
        #[arg(long)]
        requests: PathBuf,

        #[arg(long)]
        results: PathBuf,

        #[arg(long)]
        output: PathBuf,

        #[arg(long, value_enum)]
        report: FairnessReportKind,

        #[arg(long, default_value = "input.customer_segment")]
        attribute: String,

        #[arg(long, default_value = "input.informal_sector")]
        inclusion_field: String,

        #[arg(long, default_value_t = 30)]
        min_sample_size: usize,

        #[arg(long, default_value_t = 0.10)]
        disparity_threshold: f64,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Command::Run {
            input,
            output,
            pack,
            model,
            evidence_store,
            database_url,
        } => {
            let input_path = input.display().to_string();
            let output_path = output.display().to_string();
            let input_file = File::open(&input)?;
            let output_file = File::create(&output)?;
            let mut writer = BufWriter::new(output_file);

            let context = BatchRunContext {
                input_path,
                output_path,
            };
            let config = BatchConfig {
                pack_path: pack,
                model_path: model,
                ..BatchConfig::default()
            };

            let report = match evidence_store {
                EvidenceStoreArg::Memory => {
                    let mut job_store = NoopBatchJobStore;
                    run_batch(
                        input_file,
                        &mut writer,
                        &config,
                        &context,
                        MemoryChain::new(),
                        VecIncidentRecorder::default(),
                        &mut job_store,
                    )?
                }
                EvidenceStoreArg::Postgres => {
                    let database_url = database_url.ok_or(
                        "postgres evidence store requires --database-url or KAVACH_DATABASE_URL",
                    )?;
                    let pool = StoragePool::connect(&database_url).await?;
                    let mut job_store = pool.batch_job_store();
                    run_batch(
                        input_file,
                        &mut writer,
                        &config,
                        &context,
                        EvidenceBackend::Postgres(pool.evidence_store()),
                        IncidentBackend::Postgres(pool.incident_store()),
                        &mut job_store,
                    )?
                }
            };

            writer.flush()?;
            eprintln!(
                "kavach-batch job={} total={} succeeded={} failed={} skipped={}",
                report.job_id, report.total_rows, report.succeeded, report.failed, report.skipped
            );
            if report.failed > 0 {
                std::process::exit(1);
            }
        }
        Command::Fairness {
            requests,
            results,
            output,
            report,
            attribute,
            inclusion_field,
            min_sample_size,
            disparity_threshold,
        } => {
            let config = FairnessConfig {
                attribute,
                inclusion_field,
                min_sample_size,
                disparity_threshold,
            };
            let fairness_report = match report {
                FairnessReportKind::Disparity => {
                    let disparity = run_disparity_report(&requests, &results, &config)?;
                    FairnessReport::Disparity(disparity)
                }
                FairnessReportKind::Inclusion => {
                    let inclusion = run_inclusion_report(&requests, &results, &config)?;
                    FairnessReport::Inclusion(inclusion)
                }
            };
            let output_file = File::create(&output)?;
            serde_json::to_writer_pretty(BufWriter::new(output_file), &fairness_report)?;
            eprintln!(
                "kavach-batch fairness report={:?} output={}",
                report,
                output.display()
            );
        }
    }
    Ok(())
}

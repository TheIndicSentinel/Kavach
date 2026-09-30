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

        /// Expected SHA-256 of the pack file (`sha256:<hex>` or bare hex). Fails on mismatch.
        #[arg(long, env = "KAVACH_PACK_SHA256")]
        pack_sha256: Option<String>,

        /// Trusted pack signers file (JSON). When set, the pack must carry a
        /// valid `<pack>.sig` from one of them.
        #[arg(long, env = "KAVACH_PACK_SIGNERS")]
        pack_signers: Option<PathBuf>,

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
            pack_sha256,
            pack_signers,
            model,
            evidence_store,
            database_url,
        } => {
            verify_signature_if_configured(&pack, pack_signers.as_deref())?;
            let input_file = File::open(&input)?;
            let mut writer = BufWriter::new(File::create(&output)?);
            let context = BatchRunContext {
                input_path: input.display().to_string(),
                output_path: output.display().to_string(),
            };
            let config = BatchConfig {
                pack_path: pack,
                model_path: model,
                pack_sha256,
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
                    check_governed_pack(&pool, &config.pack_path).await?;
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
            write_fairness_report(&requests, &results, &output, report, &config)?;
        }
    }
    Ok(())
}

fn write_fairness_report(
    requests: &std::path::Path,
    results: &std::path::Path,
    output: &std::path::Path,
    report: FairnessReportKind,
    config: &FairnessConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let fairness_report = match report {
        FairnessReportKind::Disparity => {
            FairnessReport::Disparity(run_disparity_report(requests, results, config)?)
        }
        FairnessReportKind::Inclusion => {
            FairnessReport::Inclusion(run_inclusion_report(requests, results, config)?)
        }
    };
    serde_json::to_writer_pretty(BufWriter::new(File::create(output)?), &fairness_report)?;
    eprintln!(
        "kavach-batch fairness report={:?} output={}",
        report,
        output.display()
    );
    Ok(())
}

/// Postgres mode: batch must evaluate the pack the API governs. Batch never
/// records governance state, so any mismatch is refused (no bootstrap).
async fn check_governed_pack(
    pool: &StoragePool,
    pack_path: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let digest = kavach_policy::pack_digest(&std::fs::read(pack_path)?);
    let pointers = pool.admin_store().get_runtime_pointers().await?;
    kavach_storage::check_startup_pack(pointers.as_ref(), pack_path, Some(&digest))?;
    Ok(())
}

/// When trusted signers are configured, the pack must carry a valid
/// `<pack>.sig` before any rows are evaluated.
fn verify_signature_if_configured(
    pack: &std::path::Path,
    signers: Option<&std::path::Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(signers) = signers else {
        return Ok(());
    };
    let trusted = kavach_keys::TrustedSigners::from_file(signers)?;
    let digest = kavach_policy::pack_digest(&std::fs::read(pack)?);
    kavach_keys::verify_pack_file(pack, &digest, &trusted)?;
    Ok(())
}

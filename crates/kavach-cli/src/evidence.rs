//! `kavach evidence export` and `kavach evidence verify`: the agent evidence
//! chain as a bundle (docs/EVIDENCE_BUNDLE.md), written and checked with the
//! same code as `kavach-evidence`.
//!
//! - Export reads the project's Postgres (`[database]` in kavach.toml): the
//!   memory store keeps nothing to export. It signs with the auditor's
//!   export key (`.kavach/auditor/dev-export-1`), never a key of the stack.
//!   A dev project's database role can write, which a production export
//!   refuses; this says so.
//! - Verify takes trusted keys from the project's auditor directory (or
//!   `--keys`), never from the bundle, and reports what is **not**
//!   protected before what verified. Dev keys are accepted only when the
//!   trusted keys are themselves dev keys.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use chrono::Utc;
use kavach_evidence_cli::export::{ExportRequest, Snapshot, DEFAULT_PAGE};
use kavach_evidence_cli::postgres::{export_key, run_export, Signing, Target};
use kavach_evidence_cli::verify::{load_trusted_keys, verify_dir, Verdict, VerifyRequest};
use kavach_ports::agent_evidence::{is_dev_key, AgentEvidenceStore};
use kavach_ports::bundle::Exporter;
use kavach_ports::checkpoint::{CheckpointStore, Scope, CHAIN_AGENT_DECISIONS};
use serde_json::json;

use crate::output::{CliError, Status, Style, Ui};
use crate::project::Project;

/// The dev stack's one chain.
const PARTITION: i32 = 0;

pub async fn export(
    ui: &Ui,
    dir: &Path,
    out: &Path,
    after: Option<i64>,
    unsigned: bool,
) -> Result<i32, CliError> {
    let project = Project::find(dir)?;
    let Some(database) = &project.file.database else {
        return Err(CliError::new(
            "there is nothing to export",
            "this project keeps its evidence in memory, which is lost when `kavach dev up` stops",
        )
        .fix("set [database] in kavach.toml, restart `kavach dev up`, then export"));
    };
    let target = Target {
        database_url: database.url.clone(),
        tenant_id: kavach_devkit::TENANT.into(),
        partition_id: PARTITION,
        // A dev project uses one role for everything; a production export
        // runs as the read-only kavach_auditor role and refuses this.
        allow_write_role: true,
        tls: kavach_api::DatabaseTls::development(),
    };
    let signing = if unsigned {
        Signing::Unsigned
    } else {
        Signing::Key {
            key_dir: project.bundle().join("auditor"),
            key_id: kavach_devkit::EXPORT_KID.into(),
        }
    };
    let summary = run_export(&target, after, out, &signing)
        .await
        .map_err(|e| {
            CliError::new(format!("cannot export to {}", out.display()), e)
                .fix("check that `kavach dev up` has run with this database, and that the directory does not exist")
        })?;
    let p = &summary.manifest.payload;
    let data = json!({
        "bundle": out.display().to_string(),
        "records": p.files.records.count,
        "outcomes": p.files.outcomes.count,
        "checkpoints": p.files.checkpoints.count,
        "after_seq": p.segment.after_seq,
        "last_seq": p.segment.last_seq,
        "manifest_hash": summary.manifest.hash,
        "signed_with": p.key_id,
        "last_checkpoint": summary.last_checkpoint,
        "uncovered_records": summary.uncovered_records,
        "development": true,
    });
    let mut human = format!(
        "{} {} records (after {} through {}), {} outcomes, {} checkpoints → {}\n",
        ui.paint(Style::Ok, "exported"),
        p.files.records.count,
        p.segment.after_seq,
        p.segment.last_seq,
        p.files.outcomes.count,
        p.files.checkpoints.count,
        out.display()
    );
    match &p.key_id {
        Some(key) => {
            let _ = writeln!(human, "signed with the auditor's export key {key}");
        }
        None => human.push_str("UNSIGNED (--unsigned): nothing vouches for the set of outcomes\n"),
    }
    match summary.last_checkpoint {
        None => human.push_str("no checkpoint covers these records yet\n"),
        Some(seq) if summary.uncovered_records > 0 => {
            let _ = writeln!(
                human,
                "{} records are newer than the last checkpoint (record {seq})",
                summary.uncovered_records
            );
        }
        Some(_) => {}
    }
    let _ = write!(
        human,
        "development: read with a role that can write; production exports as kavach_auditor\n\
         Next: kavach evidence verify {}",
        out.display()
    );
    let status = if p.key_id.is_none() || summary.uncovered_records > 0 {
        Status::Warnings
    } else {
        Status::Ok
    };
    Ok(ui.finish("evidence export", status, &data, &human))
}

/// `kavach dev up --export-on-exit`: the running stack's chain as a bundle,
/// written as it stops (Ctrl-C or SIGTERM; a killed stack writes nothing).
/// A checkpoint covers every record first. Signed with the auditor's dev
/// export key, so it verifies only as a development bundle.
pub async fn export_on_exit(
    project: &Project,
    state: &kavach_api::AppState,
    out: &Path,
) -> Result<String, CliError> {
    let fail = |e: &dyn std::fmt::Display| {
        CliError::new(
            format!("the evidence could not be exported to {}", out.display()),
            e,
        )
    };
    let dataplane = state
        .dataplane()
        .ok_or_else(|| fail(&"the stack has no agent surfaces"))?;
    let checkpoint = dataplane
        .checkpointer()
        .checkpoint_now(std::time::Instant::now())
        .await;
    let store = dataplane.core().store();
    let tenant = kavach_devkit::TENANT;
    let records = store
        .records(tenant, PARTITION)
        .await
        .map_err(|e| fail(&e.message))?;
    let mut outcomes = Vec::new();
    for record in &records {
        if let Some(credential) = &record.payload.credential_id {
            if let Some(outcome) = store
                .outcome(tenant, credential)
                .await
                .map_err(|e| fail(&e.message))?
            {
                outcomes.push((record.payload.seq, outcome));
            }
        }
    }
    let scope = Scope {
        tenant_id: tenant,
        partition_id: PARTITION,
        chain: CHAIN_AGENT_DECISIONS,
    };
    let mut checkpoints = Vec::new();
    loop {
        let after = checkpoints
            .last()
            .map_or(0, |c: &kavach_ports::checkpoint::Checkpoint| c.payload.seq);
        let page = store
            .list(scope, after, DEFAULT_PAGE)
            .await
            .map_err(|e| fail(&e.message))?;
        if page.is_empty() {
            break;
        }
        checkpoints.extend(page);
    }
    let signer = export_key(&Signing::Key {
        key_dir: project.bundle().join("auditor"),
        key_id: kavach_devkit::EXPORT_KID.into(),
    })
    .map_err(|e| fail(&e))?;
    let summary = kavach_evidence_cli::export::export(
        &mut Snapshot::new(records, outcomes, checkpoints),
        ExportRequest {
            scope,
            after_checkpoint: None,
            out,
            signer: signer.as_deref(),
            exported_at: Utc::now(),
            exporter: Exporter {
                tool: "kavach dev up".into(),
                version: env!("CARGO_PKG_VERSION").into(),
            },
            page: DEFAULT_PAGE,
        },
    )
    .await
    .map_err(|e| fail(&e))?;
    let p = &summary.manifest.payload;
    let mut line = format!(
        "evidence exported to {}: {} records, {} outcomes, {} checkpoints, signed with {} (a development bundle)",
        out.display(),
        p.files.records.count,
        p.files.outcomes.count,
        p.files.checkpoints.count,
        kavach_devkit::EXPORT_KID,
    );
    if summary.uncovered_records > 0 {
        let _ = write!(
            line,
            "; {} records not covered by a checkpoint ({:?})",
            summary.uncovered_records, checkpoint.tick
        );
    }
    Ok(line)
}

pub fn verify(
    ui: Ui,
    dir: &Path,
    bundle: &Path,
    keys: Option<&Path>,
    checkpoint: Option<&Path>,
    allow_warnings: bool,
) -> Result<i32, CliError> {
    let keys: PathBuf = match keys {
        Some(k) => k.to_path_buf(),
        None => Project::find(dir)
            .map_err(|e| e.fix("pass --keys <trusted-keys.json>, or run inside a Kavach project"))?
            .bundle()
            .join("auditor/trusted-keys.json"),
    };
    let trusted = load_trusted_keys(&keys, bundle)
        .map_err(|e| CliError::new("cannot load the trusted keys", e))?;
    // Dev keys only when the trust file is a dev one: a production trust
    // file never lets a dev-signed bundle through.
    let dev = trusted.keys.keys().any(|k| is_dev_key(k));
    let verdict = Verdict {
        result: verify_dir(&VerifyRequest {
            bundle,
            keys: &keys,
            expect_checkpoint: checkpoint,
            dev,
            now: Utc::now(),
        }),
        allow_warnings,
        bundle: bundle.to_path_buf(),
    };
    let status = match verdict.exit_code() {
        0 => Status::Ok,
        2 => Status::Warnings,
        _ => Status::Failed,
    };
    let mut data = verdict.json();
    data["development"] = json!(dev);
    let mut human = verdict.text();
    if dev {
        human.push_str("development: verified against dev keys, which production refuses\n");
    }
    Ok(ui.finish("evidence verify", status, &data, human.trim_end()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_memory_project_has_nothing_to_export() {
        let dir = std::env::temp_dir().join(format!("kavach-evidence-{}", uuid::Uuid::new_v4()));
        crate::init::run(&Ui::new(true), &dir).await.unwrap();
        let error = export(&Ui::new(true), &dir, &dir.join("out"), None, false)
            .await
            .unwrap_err();
        assert!(error.what.contains("nothing to export"), "{}", error.what);
        assert!(error.fix.unwrap().contains("[database]"));
        assert!(!dir.join("out").exists());
        std::fs::remove_dir_all(dir).unwrap();
    }
}

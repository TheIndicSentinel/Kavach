//! The `export` and `checkpoints` commands against Postgres (feature
//! `export`): one read-only snapshot, read as a role that cannot write.

use std::path::{Path, PathBuf};

use chrono::Utc;
use kavach_keys::Ed25519EvidenceSigner;
use kavach_ports::agent_evidence::{EvidenceSigner, OutcomeRecord};
use kavach_ports::bundle::{is_export_key, Exporter, EXPORT_KEY_PREFIX};
use kavach_ports::chain_record::ChainRecord;
use kavach_ports::checkpoint::{Checkpoint, Scope, CHAIN_AGENT_DECISIONS};
use kavach_ports::PortError;
use kavach_storage::EvidenceSnapshot;

use crate::export::{
    export, ExportError, ExportRequest, ExportSource, ExportSummary, DEFAULT_PAGE,
};

impl ExportSource for EvidenceSnapshot {
    async fn head(&mut self) -> Result<Option<(i64, String)>, PortError> {
        EvidenceSnapshot::head(self).await
    }
    async fn records(&mut self, after_seq: i64, limit: u32) -> Result<Vec<ChainRecord>, PortError> {
        EvidenceSnapshot::records(self, after_seq, limit).await
    }
    async fn outcomes(
        &mut self,
        after_seq: i64,
        through_seq: i64,
        limit: u32,
    ) -> Result<Vec<(i64, OutcomeRecord)>, PortError> {
        EvidenceSnapshot::outcomes(self, after_seq, through_seq, limit).await
    }
    async fn checkpoints(
        &mut self,
        after_seq: i64,
        limit: u32,
    ) -> Result<Vec<Checkpoint>, PortError> {
        EvidenceSnapshot::checkpoints(self, after_seq, limit).await
    }
}

/// Which chain to read, and as whom.
#[derive(Debug, Clone)]
pub struct Target {
    pub database_url: String,
    pub tenant_id: String,
    pub partition_id: i32,
    /// Accept a role that could change the evidence (development only).
    pub allow_write_role: bool,
    /// How the connection is secured: `verify-full` unless the URL asks
    /// for less and this allows it.
    pub tls: kavach_storage::DatabaseTls,
}

/// How the bundle is signed.
#[derive(Debug, Clone)]
pub enum Signing {
    /// With the export key `<key_dir>/<key_id>.ed25519`.
    Key { key_dir: PathBuf, key_id: String },
    /// With the export key `key_id` held in an HSM (its label), through the
    /// HSM's PKCS#11 module. The key must have been generated in the HSM.
    Hsm {
        module: PathBuf,
        token_label: String,
        /// Owner-only file holding the token's user PIN.
        pin_file: PathBuf,
        key_id: String,
    },
    /// Not at all: asked for explicitly, and reported by the verifier.
    Unsigned,
}

#[derive(Debug, thiserror::Error)]
pub enum CommandError {
    #[error(transparent)]
    Export(#[from] ExportError),
    #[error("{}", .0.message)]
    Database(PortError),
    #[error(
        "the database role can change the evidence it reads; export as the read-only \
         kavach_auditor role (or pass --allow-write-role on a development stack)"
    )]
    WriteRole,
    #[error("export key: {0}")]
    Key(String),
}

async fn open(target: &Target) -> Result<EvidenceSnapshot, CommandError> {
    let snapshot = EvidenceSnapshot::open(
        &target.database_url,
        &target.tls,
        &target.tenant_id,
        target.partition_id,
    )
    .await
    .map_err(CommandError::Database)?;
    if snapshot.can_write() && !target.allow_write_role {
        return Err(CommandError::WriteRole);
    }
    Ok(snapshot)
}

fn require_export_key(key_id: &str) -> Result<(), CommandError> {
    if is_export_key(key_id) {
        Ok(())
    } else {
        Err(CommandError::Key(format!(
            "{key_id} is not an export key: its id must start with {EXPORT_KEY_PREFIX}"
        )))
    }
}

/// The signer for `signing`: only an export key (`export-…`) signs a
/// bundle; `None` for an unsigned one.
pub fn export_key(signing: &Signing) -> Result<Option<Box<dyn EvidenceSigner>>, CommandError> {
    match signing {
        Signing::Unsigned => Ok(None),
        Signing::Key { key_dir, key_id } => {
            // Before the key file is touched: only an export key signs a bundle.
            require_export_key(key_id)?;
            Ed25519EvidenceSigner::from_key_dir(key_dir, key_id)
                .map(|s| Some(Box::new(s) as Box<dyn EvidenceSigner>))
                .map_err(|e| CommandError::Key(e.message))
        }
        Signing::Hsm {
            module,
            token_label,
            pin_file,
            key_id,
        } => {
            // Before the HSM is touched, as for a key file.
            require_export_key(key_id)?;
            let pin = kavach_keys_pkcs11::read_pin_file(pin_file)
                .map_err(|e| CommandError::Key(e.message))?;
            let provider =
                kavach_keys_pkcs11::Pkcs11KeyProvider::open(kavach_keys_pkcs11::Pkcs11Config {
                    module: module.clone(),
                    token_label: token_label.clone(),
                    pin,
                    key_ids: vec![key_id.clone()],
                    max_sessions: 1,
                    // The export key is the exporter's own: no development
                    // relaxation.
                    require_hsm_generated: true,
                })
                .map_err(|e| CommandError::Key(e.message))?;
            provider
                .evidence_signer(key_id)
                .map(|s| Some(Box::new(s) as Box<dyn EvidenceSigner>))
                .map_err(|e| CommandError::Key(e.message))
        }
    }
}

/// `kavach-evidence export`: writes the bundle to `out`.
pub async fn run_export(
    target: &Target,
    after_checkpoint: Option<i64>,
    out: &Path,
    signing: &Signing,
) -> Result<ExportSummary, CommandError> {
    // The key first: a wrong key should not cost a database round trip.
    let signer = export_key(signing)?;
    let mut snapshot = open(target).await?;
    let request = ExportRequest {
        scope: Scope {
            tenant_id: &target.tenant_id,
            partition_id: target.partition_id,
            chain: CHAIN_AGENT_DECISIONS,
        },
        after_checkpoint,
        out,
        signer: signer.as_deref(),
        exported_at: Utc::now(),
        exporter: Exporter {
            tool: "kavach-evidence".into(),
            version: env!("CARGO_PKG_VERSION").into(),
        },
        page: DEFAULT_PAGE,
    };
    Ok(export(&mut snapshot, request).await?)
}

/// Which checkpoints `kavach-evidence checkpoints` prints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Which {
    Latest,
    /// Those with `seq` greater than this.
    After(i64),
}

/// `kavach-evidence checkpoints`: the checkpoints to copy off-host.
pub async fn run_checkpoints(
    target: &Target,
    which: Which,
) -> Result<Vec<Checkpoint>, CommandError> {
    let mut snapshot = open(target).await?;
    match which {
        Which::Latest => Ok(snapshot
            .latest_checkpoint()
            .await
            .map_err(CommandError::Database)?
            .into_iter()
            .collect()),
        Which::After(seq) => {
            let mut all = Vec::new();
            let mut after = seq;
            loop {
                let page = snapshot
                    .checkpoints(after, DEFAULT_PAGE)
                    .await
                    .map_err(CommandError::Database)?;
                let Some(newest) = page.last() else {
                    return Ok(all);
                };
                after = newest.payload.seq;
                all.extend(page);
            }
        }
    }
}

//! Writes an evidence bundle (format v1, `docs/EVIDENCE_BUNDLE.md`).
//!
//! The bundle is built in `<out>.partial` and renamed to `<out>` only when
//! it is complete, so a directory at `<out>` is always a whole bundle. The
//! writer refuses to overwrite anything, and creates the directory and its
//! files owner-only.
//!
//! It checks what it is given as it goes (the right chain, records in
//! order and linked, checkpoints in order), so a bug in an exporter cannot
//! produce a bundle that looks whole. It does not verify signatures: that
//! is the verifier's job, with keys the operator supplies.

use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use kavach_ports::agent_evidence::{
    AgentDecisionRecord, EvidenceSigner, OutcomeRecord, SegmentStart,
};
use kavach_ports::bundle::{
    seal_manifest, Exporter, FileEntry, Files, Manifest, ManifestDraft, Segment, CHECKPOINTS_FILE,
    MANIFEST_FILE, OUTCOMES_FILE, RECORDS_FILE,
};
use kavach_ports::checkpoint::{Checkpoint, Scope};
use kavach_ports::PortError;
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    #[error("{0} already exists; a bundle is never written over anything")]
    Exists(PathBuf),
    #[error("{what}: {source}")]
    Io {
        what: String,
        #[source]
        source: std::io::Error,
    },
    /// What the exporter handed over is not one segment of one chain.
    #[error("not a consistent bundle: {0}")]
    Inconsistent(String),
    #[error("manifest: {0}")]
    Manifest(#[from] PortError),
}

fn io(what: impl Into<String>) -> impl FnOnce(std::io::Error) -> BundleError {
    let what = what.into();
    move |source| BundleError::Io { what, source }
}

fn inconsistent<T>(reason: impl Into<String>) -> Result<T, BundleError> {
    Err(BundleError::Inconsistent(reason.into()))
}

/// One JSON-lines file: its bytes are hashed as they are written.
struct Sink {
    file: BufWriter<File>,
    hasher: Sha256,
    count: u64,
    name: &'static str,
}

impl Sink {
    fn create(dir: &Path, name: &'static str) -> Result<Self, BundleError> {
        Ok(Self {
            file: BufWriter::new(create_owner_only(&dir.join(name))?),
            hasher: Sha256::new(),
            count: 0,
            name,
        })
    }

    fn line<T: Serialize>(&mut self, value: &T) -> Result<(), BundleError> {
        let mut line = serde_json::to_vec(value)
            .map_err(|e| BundleError::Inconsistent(format!("{}: {e}", self.name)))?;
        line.push(b'\n');
        self.hasher.update(&line);
        self.file.write_all(&line).map_err(io(self.name))?;
        self.count += 1;
        Ok(())
    }

    fn finish(self) -> Result<FileEntry, BundleError> {
        let file = self.file.into_inner().map_err(|e| BundleError::Io {
            what: self.name.into(),
            source: e.into_error(),
        })?;
        file.sync_all().map_err(io(self.name))?;
        Ok(FileEntry {
            sha256: format!("{:x}", self.hasher.finalize()),
            count: self.count,
        })
    }
}

fn create_owner_only(path: &Path) -> Result<File, BundleError> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).map_err(io(path.display().to_string()))
}

fn create_dir_owner_only(path: &Path) -> Result<(), BundleError> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path).map_err(|source| {
        if source.kind() == std::io::ErrorKind::AlreadyExists {
            BundleError::Exists(path.to_path_buf())
        } else {
            io(path.display().to_string())(source)
        }
    })
}

fn partial_path(out: &Path) -> PathBuf {
    let mut name = out.file_name().unwrap_or_default().to_os_string();
    name.push(".partial");
    out.with_file_name(name)
}

/// The directory a bundle is built in: removed on drop unless the bundle
/// was moved into place, so an unfinished bundle leaves nothing behind.
struct Partial {
    path: PathBuf,
    moved: bool,
}

impl Drop for Partial {
    fn drop(&mut self) {
        if !self.moved {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

pub struct BundleWriter {
    out: PathBuf,
    partial: Partial,
    tenant_id: String,
    partition_id: i32,
    chain: String,
    after_seq: i64,
    after_hash: String,
    last_seq: i64,
    head_hash: String,
    last_checkpoint_seq: i64,
    outcomes_begun: bool,
    records: Sink,
    outcomes: Sink,
    checkpoints: Sink,
}

impl BundleWriter {
    /// Starts a bundle of the records of `scope` that follow `start`.
    /// `out` must not exist (nor `<out>.partial`, a leftover of an
    /// interrupted export, which is never removed for the caller).
    pub fn create(
        out: &Path,
        scope: Scope<'_>,
        start: SegmentStart<'_>,
    ) -> Result<Self, BundleError> {
        if out.file_name().is_none() {
            return inconsistent("the output path must name a directory");
        }
        if out.symlink_metadata().is_ok() {
            return Err(BundleError::Exists(out.to_path_buf()));
        }
        let path = partial_path(out);
        create_dir_owner_only(&path)?;
        let partial = Partial { path, moved: false };
        let records = Sink::create(&partial.path, RECORDS_FILE)?;
        let outcomes = Sink::create(&partial.path, OUTCOMES_FILE)?;
        let checkpoints = Sink::create(&partial.path, CHECKPOINTS_FILE)?;
        Ok(Self {
            out: out.to_path_buf(),
            partial,
            tenant_id: scope.tenant_id.into(),
            partition_id: scope.partition_id,
            chain: scope.chain.into(),
            after_seq: start.seq,
            after_hash: start.hash.into(),
            last_seq: start.seq,
            head_hash: start.hash.into(),
            last_checkpoint_seq: 0,
            outcomes_begun: false,
            records,
            outcomes,
            checkpoints,
        })
    }

    /// The next record of the segment: the right chain, the next `seq`,
    /// linked to the record before it. All records come before any outcome.
    pub fn record(&mut self, record: &AgentDecisionRecord) -> Result<(), BundleError> {
        let p = &record.payload;
        if self.outcomes_begun {
            return inconsistent("records must all be written before outcomes");
        }
        if p.tenant_id != self.tenant_id || p.partition_id != self.partition_id {
            return inconsistent(format!("record {} is of another chain", p.seq));
        }
        if p.seq != self.last_seq + 1 {
            return inconsistent(format!(
                "record {} does not follow record {}",
                p.seq, self.last_seq
            ));
        }
        if p.prev_hash != self.head_hash {
            return inconsistent(format!(
                "record {} does not link to the record before it",
                p.seq
            ));
        }
        self.records.line(record)?;
        self.last_seq = p.seq;
        self.head_hash.clone_from(&record.hash);
        Ok(())
    }

    /// An outcome of a record of this tenant.
    pub fn outcome(&mut self, outcome: &OutcomeRecord) -> Result<(), BundleError> {
        if outcome.tenant_id != self.tenant_id {
            return inconsistent("an outcome of another tenant");
        }
        self.outcomes_begun = true;
        self.outcomes.line(outcome)
    }

    /// The next checkpoint, in `seq` order.
    pub fn checkpoint(&mut self, checkpoint: &Checkpoint) -> Result<(), BundleError> {
        let p = &checkpoint.payload;
        if p.tenant_id != self.tenant_id
            || p.partition_id != self.partition_id
            || p.chain != self.chain
        {
            return inconsistent(format!("checkpoint {} is of another chain", p.seq));
        }
        if p.seq <= self.last_checkpoint_seq {
            return inconsistent(format!(
                "checkpoint {} does not advance past checkpoint {}",
                p.seq, self.last_checkpoint_seq
            ));
        }
        self.checkpoints.line(checkpoint)?;
        self.last_checkpoint_seq = p.seq;
        Ok(())
    }

    /// Writes the manifest and moves the bundle into place.
    ///
    /// `signer` is the export key; `None` writes an unsigned bundle, which
    /// the verifier reports as such.
    pub fn finish(
        self,
        exported_at: DateTime<Utc>,
        exporter: Exporter,
        signer: Option<&dyn EvidenceSigner>,
    ) -> Result<Manifest, BundleError> {
        let mut partial = self.partial;
        let files = Files {
            records: self.records.finish()?,
            outcomes: self.outcomes.finish()?,
            checkpoints: self.checkpoints.finish()?,
        };

        let manifest = seal_manifest(
            ManifestDraft {
                scope: Scope {
                    tenant_id: &self.tenant_id,
                    partition_id: self.partition_id,
                    chain: &self.chain,
                },
                segment: Segment {
                    after_seq: self.after_seq,
                    after_hash: self.after_hash.clone(),
                    last_seq: self.last_seq,
                    head_hash: self.head_hash.clone(),
                },
                files,
                exported_at,
                exporter,
            },
            signer,
        )?;
        let mut text = serde_json::to_vec_pretty(&manifest)
            .map_err(|e| BundleError::Inconsistent(format!("manifest: {e}")))?;
        text.push(b'\n');
        let mut file = create_owner_only(&partial.path.join(MANIFEST_FILE))?;
        file.write_all(&text).map_err(io(MANIFEST_FILE))?;
        file.sync_all().map_err(io(MANIFEST_FILE))?;

        fs::rename(&partial.path, &self.out).map_err(io(self.out.display().to_string()))?;
        partial.moved = true;
        Ok(manifest)
    }
}

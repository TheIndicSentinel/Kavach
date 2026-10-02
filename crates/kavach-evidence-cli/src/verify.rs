//! `kavach-evidence verify-bundle`: checks a bundle directory offline, with
//! keys the operator supplies (the steps of `docs/EVIDENCE_BUNDLE.md`).
//!
//! No database and no network. The files are read as streams (twice: once
//! for their digests, once for what they say), so memory use does not grow
//! with the size of the chain.
//!
//! The verifier fails closed. A bundle that verifies but is not fully
//! protected (unsigned, records no checkpoint covers, no kept checkpoint to
//! compare with, allows with no outcome) is a **warning**, and a warning is
//! a non-zero exit unless the caller explicitly allows warnings.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use kavach_ports::agent_evidence::DevKeys;
use kavach_ports::bundle::{
    FileEntry, Manifest, ManifestSignature, CHECKPOINTS_FILE, MANIFEST_FILE, OUTCOMES_FILE,
    RECORDS_FILE,
};
use kavach_ports::bundle_verify::{verify_bundle, BundleFailure, BundleReport, VerifyOptions};
use kavach_ports::checkpoint::Checkpoint;
use kavach_ports::{KeyAlgorithm, PublicKey};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Exit status: verified, nothing to report.
pub const EXIT_VERIFIED: i32 = 0;
/// Exit status: the bundle does not verify, or could not be read.
pub const EXIT_FAILED: i32 = 1;
/// Exit status: it verifies, but something is not protected (and warnings
/// were not allowed).
pub const EXIT_WARNINGS: i32 = 2;

/// Longest line accepted in a bundle file or a manifest (a record is about
/// a kilobyte). A longer one is refused, not read into memory.
const MAX_LINE: u64 = 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("{what}: {source}")]
    Io {
        what: String,
        #[source]
        source: std::io::Error,
    },
    /// The directory is not laid out as a bundle.
    #[error("not a bundle: {0}")]
    Layout(String),
    #[error("trusted keys: {0}")]
    Keys(String),
    #[error("kept checkpoint: {0}")]
    Kept(String),
    #[error("{file} does not match the manifest ({what}): the file was changed after export")]
    FileMismatch { file: &'static str, what: String },
    #[error(transparent)]
    Bundle(#[from] BundleFailure),
}

fn io(what: impl Into<String>) -> impl FnOnce(std::io::Error) -> VerifyError {
    let what = what.into();
    move |source| VerifyError::Io { what, source }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeysFile {
    #[serde(default)]
    #[allow(dead_code)]
    description: Option<String>,
    keys: Vec<KeyEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyEntry {
    kid: String,
    alg: String,
    public_key: String,
}

/// Reads the operator's trusted keys. A keys file inside the bundle is
/// refused: keys are never taken from what is being verified.
pub fn load_keys(path: &Path, bundle: &Path) -> Result<BTreeMap<String, PublicKey>, VerifyError> {
    let canonical = |p: &Path| fs::canonicalize(p).map_err(io(p.display().to_string()));
    if canonical(path)?.starts_with(canonical(bundle)?) {
        return Err(VerifyError::Keys(
            "the keys file is inside the bundle; trusted keys must come from the operator, \
             never from the bundle"
                .into(),
        ));
    }
    let text = fs::read_to_string(path).map_err(io(path.display().to_string()))?;
    let file: KeysFile =
        serde_json::from_str(&text).map_err(|e| VerifyError::Keys(e.to_string()))?;
    let mut keys = BTreeMap::new();
    for entry in file.keys {
        if entry.alg != "Ed25519" {
            return Err(VerifyError::Keys(format!(
                "{}: unsupported algorithm {}",
                entry.kid, entry.alg
            )));
        }
        let bytes: [u8; 32] = hex::decode(&entry.public_key)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| {
                VerifyError::Keys(format!(
                    "{}: public_key must be 64 hex characters",
                    entry.kid
                ))
            })?;
        let key = PublicKey {
            kid: entry.kid.clone(),
            algorithm: KeyAlgorithm::Ed25519,
            bytes,
        };
        if keys.insert(entry.kid.clone(), key).is_some() {
            return Err(VerifyError::Keys(format!("{} is listed twice", entry.kid)));
        }
    }
    if keys.is_empty() {
        return Err(VerifyError::Keys("the file lists no keys".into()));
    }
    Ok(keys)
}

/// Reads a kept checkpoint: one JSON object, or the last line of a file of
/// them (as `kavach-evidence checkpoints --latest >> file` builds up).
pub fn load_kept(path: &Path) -> Result<Checkpoint, VerifyError> {
    let text = fs::read_to_string(path).map_err(io(path.display().to_string()))?;
    let last = text
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .ok_or_else(|| VerifyError::Kept("the file is empty".into()))?;
    // A whole-file object (pretty-printed) or the last line of JSON lines.
    serde_json::from_str(text.trim())
        .or_else(|_| serde_json::from_str(last))
        .map_err(|e| VerifyError::Kept(e.to_string()))
}

/// One line, at most [`MAX_LINE`] bytes, without its line feed.
fn read_line(reader: &mut impl BufRead, buffer: &mut Vec<u8>) -> Result<bool, String> {
    buffer.clear();
    let read = reader
        .by_ref()
        .take(MAX_LINE + 1)
        .read_until(b'\n', buffer)
        .map_err(|e| e.to_string())?;
    if read == 0 {
        return Ok(false);
    }
    if buffer.last() == Some(&b'\n') {
        buffer.pop();
    } else if read as u64 > MAX_LINE {
        return Err("the line is longer than a megabyte".into());
    } else {
        return Err("the last line does not end with a line feed".into());
    }
    Ok(true)
}

/// The lines of a bundle file, parsed one at a time.
struct JsonLines<T> {
    reader: BufReader<File>,
    buffer: Vec<u8>,
    failed: bool,
    _item: std::marker::PhantomData<T>,
}

impl<T> JsonLines<T> {
    fn open(path: &Path) -> Result<Self, VerifyError> {
        Ok(Self {
            reader: BufReader::new(File::open(path).map_err(io(path.display().to_string()))?),
            buffer: Vec::new(),
            failed: false,
            _item: std::marker::PhantomData,
        })
    }
}

impl<T: DeserializeOwned> Iterator for JsonLines<T> {
    type Item = Result<T, String>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        let item = match read_line(&mut self.reader, &mut self.buffer) {
            Ok(false) => return None,
            Ok(true) => serde_json::from_slice(&self.buffer).map_err(|e| e.to_string()),
            Err(reason) => Err(reason),
        };
        self.failed = item.is_err();
        Some(item)
    }
}

/// SHA-256 and line count of a file, read in chunks.
fn digest(path: &Path) -> Result<FileEntry, VerifyError> {
    let mut file = File::open(path).map_err(io(path.display().to_string()))?;
    let mut hasher = Sha256::new();
    let mut count = 0u64;
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut chunk)
            .map_err(io(path.display().to_string()))?;
        if read == 0 {
            break;
        }
        hasher.update(&chunk[..read]);
        // Line feeds in this chunk: one fewer than the pieces they split it into.
        count += chunk[..read].split(|b| *b == b'\n').count() as u64 - 1;
    }
    Ok(FileEntry {
        sha256: format!("{:x}", hasher.finalize()),
        count,
    })
}

/// The directory holds exactly the four files of a bundle, as plain files.
fn check_layout(dir: &Path) -> Result<(), VerifyError> {
    let expected = [MANIFEST_FILE, RECORDS_FILE, OUTCOMES_FILE, CHECKPOINTS_FILE];
    let mut found = Vec::new();
    for entry in fs::read_dir(dir).map_err(io(dir.display().to_string()))? {
        let entry = entry.map_err(io(dir.display().to_string()))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !expected.contains(&name.as_str()) {
            return Err(VerifyError::Layout(format!(
                "unexpected entry {name}; a bundle holds exactly {}",
                expected.join(", ")
            )));
        }
        // No symbolic links: the files verified are the files in the bundle.
        let kind = entry.file_type().map_err(io(name.clone()))?;
        if !kind.is_file() {
            return Err(VerifyError::Layout(format!("{name} is not a plain file")));
        }
        found.push(name);
    }
    for name in expected {
        if !found.iter().any(|f| f == name) {
            return Err(VerifyError::Layout(format!("{name} is missing")));
        }
    }
    Ok(())
}

fn read_manifest(dir: &Path) -> Result<Manifest, VerifyError> {
    let path = dir.join(MANIFEST_FILE);
    let size = fs::metadata(&path)
        .map_err(io(path.display().to_string()))?
        .len();
    if size > MAX_LINE {
        return Err(VerifyError::Layout(format!("{MANIFEST_FILE} is too large")));
    }
    let bytes = fs::read(&path).map_err(io(path.display().to_string()))?;
    serde_json::from_slice(&bytes).map_err(|e| VerifyError::Layout(format!("{MANIFEST_FILE}: {e}")))
}

/// What to verify and against what.
pub struct VerifyRequest<'a> {
    pub bundle: &'a Path,
    /// The operator's trusted keys file (never inside the bundle).
    pub keys: &'a Path,
    /// A checkpoint kept out of band, to compare the chain with.
    pub expect_checkpoint: Option<&'a Path>,
    /// Accept `dev-` keys: a development stack is being verified.
    pub dev: bool,
    /// The reference time for "this allow's credential has expired".
    pub now: DateTime<Utc>,
}

/// Verifies the bundle. `Ok` means it verifies; read
/// [`BundleReport::not_protected`] before calling it protected.
pub fn verify_dir(request: &VerifyRequest<'_>) -> Result<BundleReport, VerifyError> {
    let dir = request.bundle;
    check_layout(dir)?;
    let keys = load_keys(request.keys, dir)?;
    let kept = request.expect_checkpoint.map(load_kept).transpose()?;
    let manifest = read_manifest(dir)?;

    // First what the files are, then what they say.
    let files = &manifest.payload.files;
    for (file, expected) in [
        (RECORDS_FILE, &files.records),
        (OUTCOMES_FILE, &files.outcomes),
        (CHECKPOINTS_FILE, &files.checkpoints),
    ] {
        let actual = digest(&dir.join(file))?;
        let what = if actual.sha256 != expected.sha256 {
            "digest"
        } else if actual.count != expected.count {
            "line count"
        } else {
            continue;
        };
        return Err(VerifyError::FileMismatch {
            file,
            what: what.into(),
        });
    }

    let options = VerifyOptions {
        keys: &keys,
        dev_keys: if request.dev {
            DevKeys::Accept
        } else {
            DevKeys::Refuse
        },
        now: request.now,
        kept: kept.as_ref(),
    };
    Ok(verify_bundle(
        &manifest,
        JsonLines::open(&dir.join(RECORDS_FILE))?,
        JsonLines::open(&dir.join(OUTCOMES_FILE))?,
        JsonLines::open(&dir.join(CHECKPOINTS_FILE))?,
        &options,
    )?)
}

/// The outcome of a verification, ready to print and to exit with.
pub struct Verdict {
    pub result: Result<BundleReport, VerifyError>,
    pub allow_warnings: bool,
    pub bundle: PathBuf,
}

impl Verdict {
    /// `0` verified with nothing to report (or warnings that were
    /// explicitly allowed), `2` verified with warnings, `1` failed.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        match &self.result {
            Err(_) => EXIT_FAILED,
            Ok(report) if report.not_protected().is_empty() || self.allow_warnings => EXIT_VERIFIED,
            Ok(_) => EXIT_WARNINGS,
        }
    }

    fn result_word(&self) -> &'static str {
        match (&self.result, self.exit_code()) {
            (Err(_), _) => "failed",
            (Ok(report), _) if !report.not_protected().is_empty() => "warnings",
            _ => "verified",
        }
    }

    /// The report for people. What is **not** protected comes first.
    #[must_use]
    pub fn text(&self) -> String {
        let mut out = String::new();
        let mut line = |text: String| {
            out.push_str(&text);
            out.push('\n');
        };
        let report = match &self.result {
            Err(err) => {
                line(format!("FAIL: {err}"));
                line(format!(
                    "RESULT: FAILED — {} does not verify (exit {EXIT_FAILED})",
                    self.bundle.display()
                ));
                return out;
            }
            Ok(report) => report,
        };
        let findings = report.not_protected();
        if !findings.is_empty() {
            line(format!("NOT PROTECTED ({}):", findings.len()));
            for finding in &findings {
                line(format!("  - {}", finding.detail));
            }
        }
        line("VERIFIED:".into());
        line(match &report.signature {
            ManifestSignature::Signed { key_id } => format!("  manifest: signed with {key_id}"),
            ManifestSignature::Unsigned => "  manifest: UNSIGNED".into(),
        });
        line(format!(
            "  records: {} (after {} through {}), head {}",
            report.records, report.after_seq, report.last_seq, report.head_hash
        ));
        line(format!("  outcomes: {}", report.outcomes));
        line(match report.last_checkpoint {
            Some(seq) => format!(
                "  checkpoints: {} (the last covers record {seq})",
                report.checkpoints
            ),
            None => format!("  checkpoints: {}", report.checkpoints),
        });
        line(match report.kept_checkpoint {
            Some(seq) => format!("  kept checkpoint: matches at record {seq}"),
            None => "  kept checkpoint: none supplied".into(),
        });
        line(match (findings.is_empty(), self.allow_warnings) {
            (true, _) => format!("RESULT: VERIFIED (exit {EXIT_VERIFIED})"),
            (false, true) => format!(
                "RESULT: VERIFIED WITH {} WARNING(S), allowed by --allow-warnings (exit \
                 {EXIT_VERIFIED})",
                findings.len()
            ),
            (false, false) => format!(
                "RESULT: WARNINGS — the bundle verifies but is not fully protected (exit \
                 {EXIT_WARNINGS}; --allow-warnings accepts this)"
            ),
        });
        out
    }

    /// The same report for programs.
    #[must_use]
    pub fn json(&self) -> serde_json::Value {
        use serde_json::json;
        let (failure, not_protected, verified) = match &self.result {
            Err(err) => (json!(err.to_string()), json!([]), json!(null)),
            Ok(report) => (
                json!(null),
                report
                    .not_protected()
                    .iter()
                    .map(|f| json!({ "kind": f.kind, "detail": f.detail }))
                    .collect(),
                json!({
                    "signed_with": match &report.signature {
                        ManifestSignature::Signed { key_id } => json!(key_id),
                        ManifestSignature::Unsigned => json!(null),
                    },
                    "after_seq": report.after_seq,
                    "last_seq": report.last_seq,
                    "head_hash": report.head_hash,
                    "records": report.records,
                    "outcomes": report.outcomes,
                    "checkpoints": report.checkpoints,
                    "last_checkpoint": report.last_checkpoint,
                    "uncovered_records": report.uncovered_records,
                    "kept_checkpoint": report.kept_checkpoint,
                    "outcome_missing": report.outcome_missing.count,
                    "outcome_unknown": report.outcome_unknown.count,
                }),
            ),
        };
        json!({
            "result": self.result_word(),
            "exit_code": self.exit_code(),
            "warnings_allowed": self.allow_warnings,
            "failure": failure,
            "not_protected": not_protected,
            "verified": verified,
        })
    }
}

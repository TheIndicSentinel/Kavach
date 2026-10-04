//! `kavach init`: a dev project in a directory.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde_json::json;

use crate::output::{CliError, Status, Style, Ui};
use crate::project::{self, ProjectFile, BUNDLE, FILE};

/// The policy pack and model the dev API runs, shipped in the binary.
pub const PACK: &str = include_str!("../../../packs/finance/v0.yaml");
pub const MODEL: &str = include_str!("../../../models/finance/credit-underwriting-v1.yaml");
pub const PACK_FILE: &str = "policy/finance-v0.yaml";
pub const MODEL_FILE: &str = "policy/credit-underwriting-v1.yaml";

/// Access tokens are minted for this long; `kavach doctor` warns before
/// they expire.
const TOKEN_HOURS: i64 = 24 * 30;

fn write(path: &Path, contents: &str) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| CliError::new(format!("cannot create {}", parent.display()), e))?;
    }
    std::fs::write(path, contents)
        .map_err(|e| CliError::new(format!("cannot write {}", path.display()), e))
}

/// Adds the bundle to `.gitignore` (keys and tokens never get committed).
fn ignore_bundle(root: &Path) -> Result<bool, CliError> {
    let path = root.join(".gitignore");
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    let line = format!("/{BUNDLE}/");
    if existing
        .lines()
        .any(|l| l.trim() == line || l.trim() == format!("{BUNDLE}/"))
    {
        return Ok(false);
    }
    let mut text = existing;
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    let _ = writeln!(
        text,
        "# Kavach dev keys and tokens (kavach init)
{line}"
    );
    write(&path, &text)?;
    Ok(true)
}

pub async fn run(ui: &Ui, dir: &Path) -> Result<i32, CliError> {
    std::fs::create_dir_all(dir)
        .map_err(|e| CliError::new(format!("cannot create {}", dir.display()), e))?;
    let root: PathBuf = std::fs::canonicalize(dir)
        .map_err(|e| CliError::new(format!("cannot open {}", dir.display()), e))?;
    if root.join(FILE).exists() || root.join(BUNDLE).exists() {
        return Err(CliError::new(
            "a Kavach project already exists here",
            format!("{} has {FILE} or {BUNDLE}/", root.display()),
        )
        .fix("use another directory, or remove both to start again"));
    }

    let bundle = root.join(BUNDLE);
    let file = ProjectFile::default();
    let summary = kavach_devkit::generate(&kavach_devkit::Options {
        out: bundle.clone(),
        kavach_mount: bundle.join("kavach").display().to_string(),
        provider_endpoint: format!("https://localhost:{}", file.listen.provider.port()),
        provider_hosts: vec!["localhost".into(), "127.0.0.1".into()],
        database_hosts: vec!["localhost".into(), "127.0.0.1".into()],
        token_hours: TOKEN_HOURS,
    })
    .await
    .map_err(|e| CliError::new("cannot generate the dev bundle", e))?;
    write(&bundle.join(PACK_FILE), PACK)?;
    write(&bundle.join(MODEL_FILE), MODEL)?;
    write(&root.join(FILE), &project::render(&file)?)?;
    let ignored = ignore_bundle(&root)?;

    let data = json!({
        "project": root,
        "bundle": bundle,
        "profile": "dev",
        "agents": summary.agents,
        "registry_sha256": summary.registry_sha256,
        "gitignore_updated": ignored,
        "next": ["kavach doctor", "kavach dev up"],
    });
    let human = format!(
        "{} a Kavach dev project in {}\n\n  {FILE}   project settings (loopback, dev profile)\n  {BUNDLE}/   dev keys, tokens and fixtures ({})\n\n{}\n  kavach doctor     check this machine\n  kavach dev up     start Kavach and a mock provider on loopback\n\n{}",
        ui.paint(Style::Ok, "Created"),
        root.display(),
        if ignored { "added to .gitignore" } else { "already git-ignored" },
        ui.paint(Style::Bold, "Next:"),
        ui.paint(
            Style::Dim,
            "Development only: every key is a dev- key, which production refuses."
        ),
    );
    Ok(ui.finish("init", Status::Ok, &data, &human))
}

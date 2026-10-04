//! A Kavach dev project: `kavach.toml` and the dev bundle in `.kavach/`.
//!
//! The project file is the primary configuration (per project, so two
//! projects on one machine never share state). Everything in it is for
//! development only: loopback addresses, `dev-` keys, `--insecure-dev`.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::output::CliError;

pub const FILE: &str = "kavach.toml";
/// The dev bundle (keys, tokens, fixtures), relative to the project.
pub const BUNDLE: &str = ".kavach";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProjectFile {
    /// Version of this file's format.
    pub version: u32,
    /// Always `dev`: a project made by `kavach init` is for development.
    pub profile: String,
    pub listen: Listen,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database: Option<Database>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Listen {
    /// Operator API (`/v1/runtime`, `/metrics`, governance).
    pub operator: SocketAddr,
    /// Agents (`/v1/authorize`, `/v1/tools/{tool}`).
    pub agent: SocketAddr,
    /// System-of-record events (`/v1/sor/events`).
    pub sor: SocketAddr,
    /// The mock resource provider (HTTPS, dev CA).
    pub provider: SocketAddr,
    /// The mock provider's inbox, for `kavach attack` to check that nothing
    /// was delivered (loopback only; projects made before it get the default).
    #[serde(default = "default_inspect")]
    pub inspect: SocketAddr,
}

fn default_inspect() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8444))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Database {
    /// A Postgres URL. Without one, `kavach dev up` keeps everything in
    /// memory.
    pub url: String,
}

impl Default for ProjectFile {
    fn default() -> Self {
        let at = |port: u16| SocketAddr::from(([127, 0, 0, 1], port));
        Self {
            version: 1,
            profile: "dev".into(),
            listen: Listen {
                operator: at(8080),
                agent: at(8091),
                sor: at(8090),
                provider: at(8443),
                inspect: default_inspect(),
            },
            database: None,
        }
    }
}

/// A loaded project.
#[derive(Debug, Clone)]
pub struct Project {
    pub root: PathBuf,
    pub file: ProjectFile,
}

impl Project {
    /// The project in `dir` or the nearest parent that has a `kavach.toml`.
    pub fn find(dir: &Path) -> Result<Self, CliError> {
        let start = std::fs::canonicalize(dir)
            .map_err(|e| CliError::new(format!("cannot open {}", dir.display()), e))?;
        let root = start
            .ancestors()
            .find(|d| d.join(FILE).is_file())
            .ok_or_else(|| {
                CliError::new(
                    "no Kavach project here",
                    format!("no {FILE} in {} or above it", start.display()),
                )
                .fix("run `kavach init` to create one")
            })?
            .to_path_buf();
        let text = std::fs::read_to_string(root.join(FILE))
            .map_err(|e| CliError::new(format!("cannot read {FILE}"), e))?;
        let file: ProjectFile = toml::from_str(&text).map_err(|e| {
            CliError::new(format!("{FILE} is not valid"), e).fix(format!(
                "fix {FILE}, or run `kavach init` in a new directory"
            ))
        })?;
        if file.profile != "dev" {
            return Err(CliError::new(
                format!("{FILE} is not a dev project"),
                format!(
                    "profile is {:?}; this command line runs dev projects only",
                    file.profile
                ),
            ));
        }
        Ok(Self { root, file })
    }

    #[must_use]
    pub fn bundle(&self) -> PathBuf {
        self.root.join(BUNDLE)
    }

    /// The directory kavach-api reads (`<bundle>/kavach`).
    #[must_use]
    pub fn kavach_dir(&self) -> PathBuf {
        self.bundle().join("kavach")
    }
}

/// The project file's text, with a header that says what it is.
pub fn render(file: &ProjectFile) -> Result<String, CliError> {
    let body = toml::to_string_pretty(file)
        .map_err(|e| CliError::new("cannot write the project file", e))?;
    Ok(format!(
        "# Kavach dev project (made by `kavach init`). DEVELOPMENT ONLY:\n\
         # loopback addresses, dev- keys (production refuses them), --insecure-dev.\n\
         # The keys and tokens live in {BUNDLE}/, which is git-ignored.\n\n\
         {body}\n\
         # Uncomment to keep data in Postgres instead of memory:\n\
         # [database]\n\
         # url = \"postgres://kavach:kavach@localhost:5432/kavach?sslmode=disable\"\n"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_file_round_trips_and_is_loopback_dev() {
        let file = ProjectFile::default();
        let text = render(&file).unwrap();
        let back: ProjectFile = toml::from_str(&text).unwrap();
        assert_eq!(back, file);
        // Uncommenting the database example must give a valid file.
        let with_db = text
            .replace("# [database]", "[database]")
            .replace("# url =", "url =");
        let db: ProjectFile = toml::from_str(&with_db).unwrap();
        assert!(db.database.is_some());
        assert_eq!(db.listen, file.listen);
        assert_eq!(back.profile, "dev");
        for addr in [
            back.listen.operator,
            back.listen.agent,
            back.listen.sor,
            back.listen.provider,
            back.listen.inspect,
        ] {
            assert!(addr.ip().is_loopback(), "{addr}");
        }
    }
}

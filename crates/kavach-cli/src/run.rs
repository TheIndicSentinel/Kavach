//! `.kavach/run.json`: where the running `kavach dev up` listens and what
//! its clock says, for `kavach sor event` and `kavach call`.
//!
//! Owner-only, and never a token or key: only addresses, the process id
//! and the clock offset. `dev up` removes it on a clean stop; a file left
//! by a killed process is detected because nothing answers at its address.

use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::output::CliError;
use crate::project::Project;

pub const FILE: &str = "run.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RunFile {
    pub version: u32,
    pub pid: u32,
    /// The stack's clock minus the system clock (`dev up --at`), in ms.
    pub clock_offset_ms: i64,
    pub operator: SocketAddr,
    pub agent: SocketAddr,
    pub sor: SocketAddr,
}

#[must_use]
pub fn path(project: &Project) -> PathBuf {
    project.bundle().join(FILE)
}

impl RunFile {
    /// The stack's time now.
    #[must_use]
    pub fn now(&self) -> DateTime<Utc> {
        Utc::now() + chrono::Duration::milliseconds(self.clock_offset_ms)
    }

    /// Writes the file, readable by its owner only.
    pub fn write(&self, path: &Path) -> Result<(), CliError> {
        let text = serde_json::to_string_pretty(self).unwrap_or_default() + "\n";
        let fail = |e| CliError::new(format!("cannot write {}", path.display()), e);
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path).map_err(fail)?;
        std::io::Write::write_all(&mut file, text.as_bytes()).map_err(fail)
    }

    /// The running stack, or an error that says how to start one.
    pub fn live(project: &Project) -> Result<Self, CliError> {
        let not_running = |why: String| {
            CliError::new("the dev stack is not running", why)
                .fix("start it with `kavach dev up` in another terminal")
        };
        let path = path(project);
        let text = std::fs::read_to_string(&path)
            .map_err(|_| not_running(format!("no {} in {}", FILE, project.bundle().display())))?;
        let run: Self = serde_json::from_str(&text)
            .map_err(|e| CliError::new(format!("{FILE} is not valid"), e))?;
        if TcpStream::connect_timeout(&run.agent, Duration::from_secs(1)).is_err() {
            return Err(not_running(format!(
                "nothing answers at {} (process {} stopped without cleaning up?)",
                run.agent, run.pid
            )));
        }
        Ok(run)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_is_owner_only_and_holds_no_secrets() {
        let dir = std::env::temp_dir().join(format!("kavach-run-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(FILE);
        let at = |port| SocketAddr::from(([127, 0, 0, 1], port));
        let run = RunFile {
            version: 1,
            pid: 42,
            clock_offset_ms: -3_600_000,
            operator: at(1),
            agent: at(2),
            sor: at(3),
        };
        run.write(&path).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("eyJ"), "no tokens: {text}");
        assert_eq!(serde_json::from_str::<RunFile>(&text).unwrap(), run);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        assert!(run.now() < Utc::now());
        std::fs::remove_dir_all(dir).unwrap();
    }
}

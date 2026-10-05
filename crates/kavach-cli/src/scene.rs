//! A throwaway project and its dev stack, for `kavach demo` and `kavach
//! simulate`: a temporary directory (removed afterwards unless kept, also
//! on Ctrl-C), a `kavach dev up` on distinct free loopback ports, started
//! again on other ports if it exits while starting, and stopped with
//! SIGTERM first so it shuts down cleanly.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use crate::output::CliError;

/// The temporary project and its stack, cleaned up however the run ends.
pub struct Scene {
    pub dir: PathBuf,
    stack: Option<Child>,
    /// The stack's pid, for the Ctrl-C handler (0: none).
    stack_pid: Arc<AtomicU32>,
    keep: bool,
    /// `dev up` and its options.
    up_args: Vec<String>,
}

impl Drop for Scene {
    fn drop(&mut self) {
        self.stop_gracefully(Duration::from_secs(4));
        if !self.keep {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

impl Scene {
    /// A fresh `<prefix>-<uuid>` directory in the temporary directory, and
    /// a Ctrl-C handler that stops the stack and removes the directory
    /// (unless `keep`). `up_args` start the stack (`dev up …`).
    pub fn new(prefix: &str, keep: bool, up_args: &[&str]) -> Result<Self, CliError> {
        let dir = throwaway_dir(prefix);
        std::fs::create_dir_all(&dir)
            .map_err(|e| CliError::new(format!("cannot create {}", dir.display()), e))?;
        let stack_pid = Arc::new(AtomicU32::new(0));
        {
            let (dir, pid) = (dir.clone(), Arc::clone(&stack_pid));
            tokio::spawn(async move {
                if tokio::signal::ctrl_c().await.is_ok() {
                    stop(pid.load(Ordering::SeqCst));
                    if !keep {
                        let _ = std::fs::remove_dir_all(&dir);
                    }
                    std::process::exit(130);
                }
            });
        }
        Ok(Self {
            dir,
            stack: None,
            stack_pid,
            keep,
            up_args: up_args.iter().map(ToString::to_string).collect(),
        })
    }

    /// Replaces the `dev up …` arguments (before the stack starts).
    pub fn set_up_args(&mut self, up_args: Vec<String>) {
        self.up_args = up_args;
    }

    /// Runs this binary on the project with `--json`: exit code and output.
    pub fn kavach(&self, args: &[&str]) -> Result<(i32, Value), CliError> {
        let exe = std::env::current_exe()
            .map_err(|e| CliError::new("cannot find the kavach binary", e))?;
        let out = Command::new(exe)
            .arg("-C")
            .arg(&self.dir)
            .arg("--json")
            .args(args)
            .env("NO_COLOR", "1")
            .stdin(Stdio::null())
            .output()
            .map_err(|e| CliError::new("cannot run kavach", e))?;
        Ok((
            out.status.code().unwrap_or(1),
            serde_json::from_slice(&out.stdout).unwrap_or(Value::Null),
        ))
    }

    /// Starts the stack; if it exits while starting (a port taken in the
    /// meantime), moves to other free ports and tries once more.
    pub fn start_stack(&mut self) -> Result<(), CliError> {
        use_free_ports(&self.dir)?;
        if self.try_start().is_ok() {
            return Ok(());
        }
        self.kill_stack();
        use_free_ports(&self.dir)?;
        self.try_start()
    }

    /// Stops the stack with SIGTERM and waits up to `wait` for it to exit;
    /// then kills it. True if it exited by itself (so it ran its shutdown,
    /// such as `--export-on-exit`).
    pub fn stop_gracefully(&mut self, wait: Duration) -> bool {
        let Some(mut stack) = self.stack.take() else {
            return false;
        };
        stop(stack.id());
        let deadline = std::time::Instant::now() + wait;
        let mut clean = false;
        while std::time::Instant::now() < deadline {
            if let Ok(Some(status)) = stack.try_wait() {
                clean = status.success();
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = stack.kill();
        let _ = stack.wait();
        self.stack_pid.store(0, Ordering::SeqCst);
        let _ = std::fs::remove_file(self.dir.join(".kavach/run.json"));
        clean
    }

    fn kill_stack(&mut self) {
        if let Some(mut stack) = self.stack.take() {
            let _ = stack.kill();
            let _ = stack.wait();
        }
        self.stack_pid.store(0, Ordering::SeqCst);
    }

    /// The stack's stderr goes to `.kavach/dev-up.log` in the throwaway
    /// project; its last line explains a stack that did not start.
    fn try_start(&mut self) -> Result<(), CliError> {
        let log_path = self.dir.join(".kavach/dev-up.log");
        let log = std::fs::File::create(&log_path)
            .map_err(|e| CliError::new("cannot write the dev stack's log", e))?;
        let exe = std::env::current_exe()
            .map_err(|e| CliError::new("cannot find the kavach binary", e))?;
        let child = Command::new(exe)
            .arg("-C")
            .arg(&self.dir)
            .args(&self.up_args)
            .env("NO_COLOR", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .map_err(|e| CliError::new("cannot start the dev stack", e))?;
        self.stack_pid.store(child.id(), Ordering::SeqCst);
        self.stack = Some(child);
        let run = self.dir.join(".kavach/run.json");
        for _ in 0..240 {
            if run.is_file() {
                return Ok(());
            }
            if let Some(stack) = self.stack.as_mut() {
                if stack.try_wait().ok().flatten().is_some() {
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        // The stack's own error says why on its `why:` line.
        let last = std::fs::read_to_string(&log_path)
            .ok()
            .and_then(|text| {
                let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
                lines
                    .iter()
                    .rev()
                    .find_map(|l| l.trim().strip_prefix("why:"))
                    .map(|why| why.trim().to_string())
                    .or_else(|| lines.last().map(|l| l.trim().to_string()))
            })
            .unwrap_or_else(|| "no run.json appeared".to_string());
        Err(CliError::new("the dev stack did not start", last)
            .fix("run again with --keep, then `kavach doctor` in the kept directory"))
    }
}

/// A fresh directory name for a throwaway project. The id is a canonical
/// UUID, which output redaction prints as it is: a bare 32-hex id holds ten
/// digits in a row about one time in eleven, and the number rule would mask
/// them, printing a `kept` path that does not exist.
pub fn throwaway_dir(prefix: &str) -> PathBuf {
    std::env::temp_dir().join(format!("{prefix}-{}", uuid::Uuid::new_v4().hyphenated()))
}

/// Asks a process to stop (SIGTERM on Unix); 0 is no process.
fn stop(pid: u32) {
    #[cfg(unix)]
    if pid != 0 {
        let _ = Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// `n` distinct free loopback ports: every probe socket stays open until
/// all are chosen, so the system cannot hand out the same port twice.
fn free_ports(n: usize) -> Vec<u16> {
    let probes: Vec<TcpListener> = (0..n)
        .filter_map(|_| TcpListener::bind("127.0.0.1:0").ok())
        .collect();
    probes
        .iter()
        .filter_map(|l| l.local_addr().ok())
        .map(|a| a.port())
        .collect()
}

/// Moves every listener of the project (`"127.0.0.1:<port>"`) to its own
/// free loopback port. Safe to run again, for a retry.
fn use_free_ports(dir: &Path) -> Result<(), CliError> {
    const HOST: &str = "\"127.0.0.1:";
    let path = dir.join(crate::project::FILE);
    let text = std::fs::read_to_string(&path)
        .map_err(|e| CliError::new("cannot read the throwaway project", e))?;
    let ports = free_ports(text.matches(HOST).count());
    let mut ports = ports.into_iter();
    let mut out = String::with_capacity(text.len());
    let mut rest = text.as_str();
    while let Some(at) = rest.find(HOST) {
        let after = &rest[at + HOST.len()..];
        let digits = after.bytes().take_while(u8::is_ascii_digit).count();
        out.push_str(&rest[..at + HOST.len()]);
        if digits > 0 && after[digits..].starts_with('"') {
            let port = ports.next().ok_or_else(|| {
                CliError::new(
                    "cannot find free loopback ports",
                    "the system has none to spare",
                )
            })?;
            out.push_str(&port.to_string());
            rest = &after[digits..];
        } else {
            rest = after;
        }
    }
    out.push_str(rest);
    std::fs::write(&path, out).map_err(|e| CliError::new("cannot write the throwaway project", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_ports_are_distinct_and_the_project_moves_to_them() {
        let ports = free_ports(5);
        assert_eq!(ports.len(), 5);
        assert_eq!(
            ports
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            5
        );

        let dir = throwaway_dir("kavach-test");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join(crate::project::FILE);
        let listen = "[listen]\noperator = \"127.0.0.1:8080\"\nagent = \"127.0.0.1:8091\"\n\
                      sor = \"127.0.0.1:8090\"\nprovider = \"127.0.0.1:8443\"\n\
                      inspect = \"127.0.0.1:8444\"\nname = \"127.0.0.1:x\"\n";
        std::fs::write(&file, listen).unwrap();
        for _ in 0..2 {
            use_free_ports(&dir).unwrap();
            let text = std::fs::read_to_string(&file).unwrap();
            let used: std::collections::BTreeSet<&str> = text
                .lines()
                .filter_map(|l| l.split("127.0.0.1:").nth(1))
                .filter(|p| p.starts_with(|c: char| c.is_ascii_digit()))
                .collect();
            assert_eq!(used.len(), 5, "{text}");
            assert!(!text.contains(":8080\""), "{text}");
            assert!(text.contains("127.0.0.1:x"), "{text}");
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn throwaway_directories_are_printed_as_they_are() {
        for prefix in ["kavach-demo", "kavach-sim"] {
            for _ in 0..2000 {
                let dir = throwaway_dir(prefix).display().to_string();
                assert_eq!(crate::output::redact(&dir), dir);
            }
        }
    }
}

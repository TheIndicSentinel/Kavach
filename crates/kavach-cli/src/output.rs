//! The one place output is produced (clig.dev conventions).
//!
//! - Human output goes to stdout and errors to stderr; with `--json` every
//!   command prints one JSON document on stdout, in a versioned envelope
//!   ([`SCHEMA`]), errors included.
//! - Colour only on a terminal, never with `NO_COLOR` or `TERM=dumb`.
//! - Everything printed passes through the shared redaction function
//!   (`kavach_telemetry::redact`): no number, token or identifier leaks
//!   into a terminal or a CI log.
//! - Exit codes are stable: [`EXIT_OK`], [`EXIT_FAILED`], [`EXIT_WARNINGS`],
//!   [`EXIT_USAGE`], [`EXIT_INTERNAL`].

use std::fmt::{self, Write as _};
use std::io::{IsTerminal, Write};
use std::sync::OnceLock;

use regex::Regex;

use serde::Serialize;
use serde_json::{json, Value};

/// The JSON envelope's schema: bumped on any breaking change to a command's
/// JSON output. The TUI and CI pipelines build on it.
pub const SCHEMA: &str = "kavach.cli/v1";

pub const EXIT_OK: i32 = 0;
/// A check failed, a call was blocked, or the command could not do its job.
pub const EXIT_FAILED: i32 = 1;
/// Done, with warnings worth reading.
pub const EXIT_WARNINGS: i32 = 2;
/// The command line was wrong (sysexits EX_USAGE).
pub const EXIT_USAGE: i32 = 64;
/// A bug in kavach itself (sysexits EX_SOFTWARE).
pub const EXIT_INTERNAL: i32 = 70;

/// How a command ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Ok,
    Warnings,
    Failed,
}

impl Status {
    #[must_use]
    pub fn exit_code(self) -> i32 {
        match self {
            Self::Ok => EXIT_OK,
            Self::Warnings => EXIT_WARNINGS,
            Self::Failed => EXIT_FAILED,
        }
    }

    /// The worse of two statuses.
    #[must_use]
    pub fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::Failed, _) | (_, Self::Failed) => Self::Failed,
            (Self::Warnings, _) | (_, Self::Warnings) => Self::Warnings,
            _ => Self::Ok,
        }
    }
}

/// An error that says what failed, why, and how to fix it.
#[derive(Debug, Clone)]
pub struct CliError {
    pub what: String,
    pub why: String,
    pub fix: Option<String>,
    pub code: i32,
}

impl CliError {
    pub fn new(what: impl Into<String>, why: impl fmt::Display) -> Self {
        Self {
            what: what.into(),
            why: why.to_string(),
            fix: None,
            code: EXIT_FAILED,
        }
    }

    #[must_use]
    pub fn fix(mut self, fix: impl Into<String>) -> Self {
        self.fix = Some(fix.into());
        self
    }
}

/// Text styles; plain text without colour.
#[derive(Debug, Clone, Copy)]
pub enum Style {
    Ok,
    Warn,
    Fail,
    Dim,
    Bold,
}

/// Where and how output goes, decided once per run.
#[derive(Debug, Clone, Copy)]
pub struct Ui {
    pub json: bool,
    color: bool,
}

impl Ui {
    #[must_use]
    pub fn new(json: bool) -> Self {
        let no_color = std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty())
            || std::env::var("TERM").is_ok_and(|t| t == "dumb");
        Self {
            json,
            color: !json && !no_color && std::io::stdout().is_terminal(),
        }
    }

    /// `text` in `style`, if colour is on.
    #[must_use]
    pub fn paint(self, style: Style, text: &str) -> String {
        if !self.color {
            return text.to_string();
        }
        let code = match style {
            Style::Ok => "32",
            Style::Warn => "33",
            Style::Fail => "31",
            Style::Dim => "2",
            Style::Bold => "1",
        };
        format!("\x1b[{code}m{text}\x1b[0m")
    }

    /// A status word, coloured.
    #[must_use]
    pub fn status(self, status: Status) -> String {
        match status {
            Status::Ok => self.paint(Style::Ok, "ok"),
            Status::Warnings => self.paint(Style::Warn, "warn"),
            Status::Failed => self.paint(Style::Fail, "FAIL"),
        }
    }

    /// Prints a command's result: the envelope with `data` in JSON mode,
    /// `human` otherwise. Returns the exit code.
    pub fn finish(self, command: &str, status: Status, data: &Value, human: &str) -> i32 {
        if self.json {
            print_redacted(&envelope(command, status, data));
        } else {
            print_redacted(human);
        }
        status.exit_code()
    }

    /// Prints an error (stderr for people, the envelope on stdout for
    /// machines). Returns its exit code.
    pub fn error(self, command: &str, error: &CliError) -> i32 {
        if self.json {
            let data = json!({
                "error": { "what": error.what, "why": error.why, "fix": error.fix }
            });
            print_redacted(&envelope(command, Status::Failed, &data));
        } else {
            let mut text = format!(
                "{} {}\n  {} {}",
                self.paint(Style::Fail, "error:"),
                error.what,
                self.paint(Style::Dim, "why:"),
                error.why
            );
            if let Some(fix) = &error.fix {
                let _ = write!(text, "\n  {} {fix}", self.paint(Style::Dim, "fix:"));
            }
            eprintln_redacted(&text);
        }
        error.code
    }
}

fn envelope(command: &str, status: Status, data: &Value) -> String {
    let mut doc = json!({ "schema": SCHEMA, "command": command, "status": status });
    if let (Some(doc), Some(data)) = (doc.as_object_mut(), data.as_object()) {
        doc.extend(data.clone());
    }
    serde_json::to_string_pretty(&doc).unwrap_or_default()
}

/// Printed as they are: canonical UUIDs (mandate, event and request ids)
/// and RFC 3339 timestamps. Both are ours, not personal data, and the
/// number rule would otherwise mask them: a timestamp always holds 14
/// digits, and about one UUID in five holds ten in a row, breaking ids
/// people copy and JSON that machines read.
fn verbatim() -> &'static Regex {
    static VERBATIM: OnceLock<Regex> = OnceLock::new();
    VERBATIM.get_or_init(|| {
        Regex::new(concat!(
            r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
            r"|\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})",
        ))
        .expect("valid regex")
    })
}

/// One line: the shared rules (`kavach_telemetry::redact`) on everything
/// between the [`verbatim`] spans.
fn redact_line(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut last = 0;
    for id in verbatim().find_iter(line) {
        out.push_str(&kavach_telemetry::redact(&line[last..id.start()]));
        out.push_str(id.as_str());
        last = id.end();
    }
    out.push_str(&kavach_telemetry::redact(&line[last..]));
    out
}

/// The single redaction point for everything kavach prints.
#[must_use]
pub fn redact(text: &str) -> String {
    text.lines().map(redact_line).collect::<Vec<_>>().join("\n")
}

pub fn print_redacted(text: &str) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{}", redact(text));
}

pub fn eprintln_redacted(text: &str) {
    let mut err = std::io::stderr().lock();
    let _ = writeln!(err, "{}", redact(text));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_combine_to_the_worst_and_map_to_exit_codes() {
        assert_eq!(Status::Ok.and(Status::Warnings), Status::Warnings);
        assert_eq!(Status::Warnings.and(Status::Failed), Status::Failed);
        assert_eq!(Status::Ok.and(Status::Ok).exit_code(), EXIT_OK);
        assert_eq!(Status::Warnings.exit_code(), EXIT_WARNINGS);
        assert_eq!(Status::Failed.exit_code(), EXIT_FAILED);
    }

    #[test]
    fn the_envelope_carries_schema_command_status_and_data() {
        let doc: Value = serde_json::from_str(&envelope(
            "doctor",
            Status::Warnings,
            &json!({ "checks": [] }),
        ))
        .unwrap();
        assert_eq!(doc["schema"], SCHEMA);
        assert_eq!(doc["command"], "doctor");
        assert_eq!(doc["status"], "warnings");
        assert!(doc["checks"].is_array());
    }

    #[test]
    fn printed_text_is_redacted() {
        let text = redact("call +91 98765 43210 now");
        assert!(!text.contains("98765"), "{text}");
    }

    #[test]
    fn timestamps_survive_but_other_dates_do_not() {
        for ts in ["2026-10-11T05:30:00Z", "2026-10-11T11:00:00.123+05:30"] {
            assert_eq!(redact(&format!("exp {ts}")), format!("exp {ts}"));
        }
        assert!(redact("2026-10-11 11:00:00").contains("[redacted"));
    }

    #[test]
    fn uuids_survive_but_numbers_beside_them_do_not() {
        let id = "3a1f2b9c-1234-5678-9012-345678901234";
        assert!(
            kavach_telemetry::redact(id).contains("[redacted"),
            "the rule alone masks it"
        );
        let text = redact(&format!("mandate {id} for +91 98765 43210"));
        assert!(text.contains(id), "{text}");
        assert!(!text.contains("98765"), "{text}");
        // Not canonical (upper case, wrong grouping): the rules apply.
        assert!(!redact("1234567890-1234").contains("1234567890"));
    }
}

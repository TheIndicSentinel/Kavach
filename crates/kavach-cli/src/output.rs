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
    /// The API problem behind it, when the stack refused (`crate::problem`).
    pub problem: Option<Box<ProblemRef>>,
}

/// What to quote about an API refusal: its code and the request's id.
#[derive(Debug, Clone)]
pub struct ProblemRef {
    pub code: String,
    pub request_id: Option<String>,
}

impl CliError {
    pub fn new(what: impl Into<String>, why: impl fmt::Display) -> Self {
        Self {
            what: what.into(),
            why: why.to_string(),
            fix: None,
            code: EXIT_FAILED,
            problem: None,
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
                "error": {
                    "what": error.what, "why": error.why, "fix": error.fix,
                    "code": error.problem.as_ref().map(|p| &p.code),
                    "request_id": error.problem.as_ref().and_then(|p| p.request_id.as_ref()),
                }
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
            if let Some(problem) = &error.problem {
                let _ = write!(
                    text,
                    "\n  {} {}",
                    self.paint(Style::Dim, "code:"),
                    problem.code
                );
                if let Some(id) = &problem.request_id {
                    let _ = write!(text, " (request {id})");
                }
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
    mark_digest_fields(&mut doc);
    serde_json::to_string_pretty(&doc).unwrap_or_default()
}

/// Fields that hold digests Kavach computed: printed whole, if well formed.
/// Matched by field, never by pattern: a hex string anywhere else (where a
/// caller could choose it) still goes through every masking rule.
const DIGEST_FIELDS: [&str; 5] = [
    "input_digest",
    "cedar",
    "tools",
    "registry_sha256",
    "subject_pseudonym",
];

/// Start and end of a span the output layer vouches for as a digest. Each
/// carries a random per-process nonce, so text from anywhere else (input,
/// a server reply) cannot forge one.
fn markers() -> &'static (String, String) {
    static MARKERS: OnceLock<(String, String)> = OnceLock::new();
    MARKERS.get_or_init(|| {
        let nonce = uuid::Uuid::new_v4().simple().to_string();
        (
            format!("\u{E000}{nonce}\u{E001}"),
            format!("\u{E001}{nonce}\u{E000}"),
        )
    })
}

/// A digest (`sha256:` optional, then 64 lowercase hex characters).
fn lower_hex(text: &str) -> bool {
    text.bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A digest (`[sha256:]` and 64 lowercase hex), or a subject pseudonym
/// (`psn:` and up to 64 lowercase hex: an HMAC, never personal data;
/// `why` shows a prefix of it).
fn is_digest(text: &str) -> bool {
    if let Some(hex) = text.strip_prefix("psn:") {
        return (1..=64).contains(&hex.len()) && lower_hex(hex);
    }
    let hex = text.strip_prefix("sha256:").unwrap_or(text);
    hex.len() == 64 && lower_hex(hex)
}

/// A value from a known digest field, for human output: printed whole if
/// it is a well-formed digest, and redacted like any text if not.
pub struct Digest<'a>(pub &'a str);

impl fmt::Display for Digest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if is_digest(self.0) {
            let (open, close) = markers();
            write!(f, "{open}{}{close}", self.0)
        } else {
            f.write_str(self.0)
        }
    }
}

fn mark_digest_fields(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, v) in map.iter_mut() {
                match v {
                    Value::String(text) if DIGEST_FIELDS.contains(&key.as_str()) => {
                        if is_digest(text) {
                            let (open, close) = markers();
                            *text = format!("{open}{text}{close}");
                        }
                    }
                    other => mark_digest_fields(other),
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(mark_digest_fields),
        _ => {}
    }
}

/// One line: digest spans the output layer marked are kept whole (if they
/// still are digests); everything else goes through the shared rules.
fn redact_line(line: &str) -> String {
    let (open, close) = markers();
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(start) = rest.find(open.as_str()) {
        out.push_str(&kavach_telemetry::redact(&rest[..start]));
        let after = &rest[start + open.len()..];
        let Some(end) = after.find(close.as_str()) else {
            rest = after;
            break;
        };
        let inner = &after[..end];
        if is_digest(inner) {
            out.push_str(inner);
        } else {
            out.push_str(&kavach_telemetry::redact(inner));
        }
        rest = &after[end + close.len()..];
    }
    out.push_str(&kavach_telemetry::redact(rest));
    out
}

/// The single redaction point for everything kavach prints: the shared
/// rules (canonical UUIDs and RFC 3339 timestamps stay whole), except
/// known digest fields, which are printed whole when well formed.
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

    /// 64 hex characters holding a run of ten digits.
    const HEX: &str = "4fb9876543210f278a54cb0bc90724cbb9c37f774dea053c6854bd6cb467eacb";

    #[test]
    fn known_digest_fields_print_whole() {
        assert!(is_digest(HEX) && kavach_telemetry::redact(HEX).contains("[redacted"));
        let doc = envelope(
            "why",
            Status::Ok,
            &json!({ "input_digest": HEX, "policy_versions": { "cedar": format!("sha256:{HEX}") } }),
        );
        let printed = redact(&doc);
        assert!(
            printed.contains(&format!("\"input_digest\": \"{HEX}\"")),
            "{printed}"
        );
        assert!(printed.contains(&format!("sha256:{HEX}")), "{printed}");
        assert!(
            serde_json::from_str::<Value>(&printed).is_ok(),
            "still JSON"
        );
        assert_eq!(
            redact(&format!("digest {}", Digest(HEX))),
            format!("digest {HEX}")
        );
    }

    /// Subject pseudonyms (HMACs) can hold ten digits in a row too; they
    /// print whole from their field, in JSON and as `why` shows them.
    #[test]
    fn subject_pseudonyms_print_whole() {
        // Ten digits at the start, so the prefix `why` shows holds them.
        let psn = format!("psn:9876543210ab{}", &HEX[12..]);
        let printed = redact(&envelope(
            "why",
            Status::Ok,
            &json!({ "record": { "subject_pseudonym": psn } }),
        ));
        assert!(printed.contains(&psn), "{printed}");
        let short: String = psn.chars().take(16).collect();
        assert!(
            short.contains("9876543210"),
            "the fixture has the run in the prefix"
        );
        assert_eq!(
            redact(&format!("pseudonym {}", Digest(&short))),
            format!("pseudonym {short}")
        );
        // Not a pseudonym's shape, or not in its field: masked as before.
        assert!(!redact(&Digest("psn:+91 98765 43210").to_string()).contains("43210"));
        assert!(!redact(&format!("note {psn}")).contains("9876543210"));
    }

    #[test]
    fn the_same_hex_elsewhere_is_still_masked() {
        // A free-text field, or human text not rendered as a Digest.
        let doc = redact(&envelope("why", Status::Ok, &json!({ "note": HEX })));
        assert!(!doc.contains("9876543210"), "{doc}");
        assert!(!redact(&format!("note {HEX}")).contains("9876543210"));
        // A digest field holding something that is not a digest.
        let doc = redact(&envelope(
            "why",
            Status::Ok,
            &json!({ "input_digest": "+91 98765 43210" }),
        ));
        assert!(!doc.contains("43210"), "{doc}");
        assert!(!redact(&Digest("+91 98765 43210").to_string()).contains("43210"));
    }

    #[test]
    fn a_phone_number_in_hex_is_masked_and_markers_cannot_be_forged() {
        assert!(!redact("ab12cd+919876543210ef").contains("9876543210"));
        // Markers without this process's nonce exempt nothing.
        let forged = format!("\u{E000}x\u{E001}{HEX}\u{E001}x\u{E000}");
        assert!(!redact(&forged).contains("9876543210"));
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
        let text = redact(&format!("mandate {id} for +91 98765 43210"));
        assert!(text.contains(id), "{text}");
        assert!(!text.contains("98765"), "{text}");
        // Not canonical (upper case, wrong grouping): the rules apply.
        assert!(!redact("1234567890-1234").contains("1234567890"));
    }
}

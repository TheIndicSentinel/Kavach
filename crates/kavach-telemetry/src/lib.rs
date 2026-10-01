//! Redaction-first logging for Kavach.
//!
//! One global `tracing` subscriber (text or JSON, filtered by `KAVACH_LOG`,
//! default `info`) whose writer scrubs **every line before it is written**:
//! phone-like numbers (any script's digits, with separators), compact
//! JWS/JWE/JWT tokens, `Bearer` / `Kavach-Credential` values, PAN-shaped
//! identifiers and email addresses.
//!
//! This is defence in depth. The primary control is that personal data and
//! secrets never reach a log call at all: `Destination` and `TokenSecret`
//! never print, evidence holds pseudonyms, and replies are allowlists.
//! Logging stays local (stderr); there is no telemetry export.

use std::borrow::Cow;
use std::io::{self, Write};
use std::sync::OnceLock;

use regex::Regex;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::EnvFilter;

/// Environment variable with the log filter (`tracing` directives).
pub const FILTER_ENV: &str = "KAVACH_LOG";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Text,
    Json,
}

impl std::str::FromStr for LogFormat {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "text" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            other => Err(format!("log format {other:?} (expected text or json)")),
        }
    }
}

struct Rules {
    credential_header: Regex,
    jose: Regex,
    number: Regex,
    pan: Regex,
    email: Regex,
}

fn rules() -> &'static Rules {
    static RULES: OnceLock<Rules> = OnceLock::new();
    RULES.get_or_init(|| Rules {
        credential_header: Regex::new(
            r"(?i)\b(bearer|kavach-credential)(\s+|%20)[A-Za-z0-9._~+/=-]+",
        )
        .expect("valid regex"),
        // Compact JOSE: base64url JSON header ("eyJ…") then 2–4 more parts.
        jose: Regex::new(r"\beyJ[A-Za-z0-9_-]{4,}(?:\.[A-Za-z0-9_-]*){2,4}").expect("valid regex"),
        // 10+ digits (any script), at most two separators between digits
        // ("(987) 654-3210", "+91 98765 43210").
        number: Regex::new(r"\+?\(?\d(?:[ ().\-]{0,2}\d){9,}").expect("valid regex"),
        pan: Regex::new(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b").expect("valid regex"),
        email: Regex::new(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b").expect("valid regex"),
    })
}

/// Scrubs one log line.
pub fn redact(line: &str) -> Cow<'_, str> {
    let r = rules();
    let mut out = Cow::Borrowed(line);
    for (regex, replacement) in [
        (&r.credential_header, "$1 [redacted]"),
        (&r.jose, "[redacted-token]"),
        (&r.number, "[redacted-number]"),
        (&r.pan, "[redacted-id]"),
        (&r.email, "[redacted-email]"),
    ] {
        if regex.is_match(&out) {
            out = Cow::Owned(regex.replace_all(&out, replacement).into_owned());
        }
    }
    out
}

/// A writer that redacts each write (the formatter writes whole events).
pub struct RedactingWriter<W>(W);

impl<W: Write> Write for RedactingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let text = String::from_utf8_lossy(buf);
        self.0.write_all(redact(&text).as_bytes())?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

/// Wraps any `MakeWriter` so that everything it writes is redacted.
pub struct Redacting<M>(pub M);

impl<'a, M: MakeWriter<'a>> MakeWriter<'a> for Redacting<M> {
    type Writer = RedactingWriter<M::Writer>;

    fn make_writer(&'a self) -> Self::Writer {
        RedactingWriter(self.0.make_writer())
    }
}

/// Installs the global subscriber, writing redacted lines to stderr.
pub fn init(format: LogFormat) -> Result<(), String> {
    init_with(format, io::stderr)
}

/// Installs the global subscriber with a custom writer (tests capture logs
/// this way). The writer still goes through redaction.
pub fn init_with<M>(format: LogFormat, writer: M) -> Result<(), String>
where
    M: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    let filter = EnvFilter::try_from_env(FILTER_ENV).unwrap_or_else(|_| EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(Redacting(writer))
        .with_target(true)
        .with_ansi(false);
    let result = match format {
        LogFormat::Text => builder.try_init(),
        LogFormat::Json => builder.json().flatten_event(true).try_init(),
    };
    result.map_err(|e| format!("logging: {e}"))
}

/// A caller-supplied correlation id is accepted only if it is short and
/// plain (no log injection); otherwise the server generates one.
#[must_use]
pub fn valid_request_id(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_in_any_script_and_format_are_masked() {
        for raw in [
            "sent to +919876543210 ok",
            "sent to 98765 43210 ok",
            "sent to +91-98765-43210 ok",
            "sent to (987) 654.3210 ok",
            "aadhaar 1234 5678 9012",
            "sent to ९८७६५४३२१० ok",
            "sent to ９８７６５４３２１０ ok",
            "sent to +910000000001 ok",
        ] {
            let out = redact(raw);
            assert!(out.contains("[redacted-number]"), "{raw} -> {out}");
            assert!(!out.contains("43210") && !out.contains("9012"), "{out}");
        }
    }

    #[test]
    fn tokens_and_credential_headers_are_masked() {
        let jws = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl";
        let jwe = "eyJhbGciOiJFQ0RILUVTIn0..aXY.Y2lwaGVy.dGFn";
        for raw in [
            format!("token {jws} used"),
            format!("credential {jwe} sent"),
            "authorization: Bearer abc.def.ghi".to_string(),
            "authorization: Kavach-Credential a.b.c.d.e".to_string(),
            "url ?h=Bearer%20secretvalue".to_string(),
        ] {
            let out = redact(&raw);
            for secret in [
                "c2lnbmF0dXJl",
                "Y2lwaGVy",
                "abc.def",
                "a.b.c.d.e",
                "secretvalue",
            ] {
                assert!(!out.contains(secret), "{raw} -> {out}");
            }
        }
    }

    #[test]
    fn identifiers_are_masked_and_ordinary_lines_untouched() {
        assert_eq!(redact("pan ABCDE1234F seen"), "pan [redacted-id] seen");
        assert_eq!(redact("from borrower@example.com"), "from [redacted-email]");
        for clean in [
            "gateway call tool=send_reminder decision=PASS outcome=delivered",
            "request_id=gw-1 record_id=0af76519-16cd-43dd-8448-eb211c80319c",
            "listening on 127.0.0.1:8091",
            "2026-10-01T05:30:00.123456Z INFO kavach_api: started",
            "latency_ms=12 status=202",
            "ref:borrower:B-9382",
        ] {
            assert_eq!(redact(clean), clean, "must not alter {clean}");
        }
    }

    #[test]
    fn request_ids_are_plain_and_short() {
        assert!(valid_request_id("gw-1"));
        assert!(valid_request_id("0af76519-16cd-43dd-8448-eb211c80319c"));
        for bad in [
            "",
            "a b",
            "x\ny",
            "<script>",
            &"a".repeat(65),
            "id\u{1b}[31m",
        ] {
            assert!(!valid_request_id(bad), "{bad:?}");
        }
    }

    #[test]
    fn the_writer_redacts_what_the_formatter_writes() {
        let mut sink = Vec::new();
        {
            let mut writer = RedactingWriter(&mut sink);
            writer
                .write_all(
                    b"delivered to +919876543210 with eyJhbGciOiJFZERTQSJ9.eyJ4IjoxfQ.c2ln\n",
                )
                .unwrap();
        }
        let text = String::from_utf8(sink).unwrap();
        assert_eq!(
            text,
            "delivered to [redacted-number] with [redacted-token]\n"
        );
    }
}

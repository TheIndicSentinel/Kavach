//! `--require-hardening`: refuse to start unless the process runs with every
//! guarantee on.
//!
//! The flag changes no behaviour of its own. It turns what is a warning, an
//! allowance or a request-time refusal into a startup refusal, and it
//! reports every condition that fails at once, not the first. Without the
//! flag nothing here runs.
//!
//! The conditions (`docs/BYPASS_INVENTORY.md`, section 1):
//! - no relaxation is on: the fixed list in [`crate::relaxations`], which
//!   covers `--insecure-dev`, access control off, the principal header,
//!   weaker database TLS, memory stores, test and development clocks, an
//!   unsigned tool registry, development keys and a test-double broker;
//! - the listeners serve TLS;
//! - every provider endpoint is HTTPS (no exception for loopback or an
//!   "isolated" network: the process cannot verify isolation), and carries no
//!   userinfo, query or fragment;
//! - the TLS private key, the HSM PIN file and the subject-pseudonym key are
//!   readable by their owner only, and the platform can say so;
//! - `POST /v1/dev/clock` is not mounted (see `crate::http`).
//!
//! A refusal prints **names and the scheme, host and port of an endpoint**,
//! never a path, userinfo, query, key or secret.

use std::fmt::Write as _;
use std::path::Path;

use reqwest::Url;

use crate::config::{ApiConfig, TlsConfig};
use crate::relaxations::{self, Relaxation};

/// One condition that does not hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Violation {
    /// A relaxation of [`Relaxation::ALL`] is on.
    Relaxed(Relaxation),
    /// The API listeners are plain HTTP.
    PlainListener,
    /// A provider endpoint is plain HTTP. `origin` is scheme, host and port.
    PlainProvider { audience: String, origin: String },
    /// A provider endpoint carries userinfo, a query or a fragment, or does
    /// not parse. Nothing of it is printed.
    ProviderEndpointForm { audience: String },
    /// The providers file could not be read or parsed.
    ProvidersUnreadable,
    /// A secret file is accessible by group or others.
    SecretFileMode { flag: &'static str, mode: u32 },
    /// A secret file could not be read.
    SecretFileUnreadable { flag: &'static str },
    /// The platform cannot report a file's mode.
    SecretFileUnverifiable { flag: &'static str },
}

impl Violation {
    /// A stable name for the condition.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Relaxed(_) => "relaxation",
            Self::PlainListener => "tls",
            Self::PlainProvider { .. } => "provider_https",
            Self::ProviderEndpointForm { .. } => "provider_endpoint_form",
            Self::ProvidersUnreadable => "providers_unreadable",
            Self::SecretFileMode { .. } => "secret_file_mode",
            Self::SecretFileUnreadable { .. } => "secret_file_unreadable",
            Self::SecretFileUnverifiable { .. } => "secret_file_unverifiable",
        }
    }

    /// One line; no secret, path, userinfo, query or fragment.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::Relaxed(r) => format!("the relaxation `{}` is on", r.as_str()),
            Self::PlainListener => {
                "the API listeners are plain HTTP; set --tls-cert and --tls-key".into()
            }
            Self::PlainProvider { audience, origin } => {
                format!("provider {audience} uses plain HTTP ({origin}); use HTTPS")
            }
            Self::ProviderEndpointForm { audience } => format!(
                "provider {audience} has an endpoint that does not parse, or carries userinfo, \
                 a query or a fragment; it must be a plain https base URL"
            ),
            Self::ProvidersUnreadable => "the providers file could not be read or parsed".into(),
            Self::SecretFileMode { flag, mode } => format!(
                "the {flag} file is mode {mode:o}; it must not be accessible by group or others"
            ),
            Self::SecretFileUnreadable { flag } => {
                format!("the {flag} file could not be read")
            }
            Self::SecretFileUnverifiable { flag } => {
                format!("the {flag} file's mode cannot be verified on this platform")
            }
        }
    }
}

/// `scheme://host[:port]` of an endpoint, and nothing else; `None` when it
/// does not parse or has no host.
#[must_use]
pub fn origin_of(endpoint: &str) -> Option<String> {
    let url = Url::parse(endpoint).ok()?;
    let host = url.host_str()?;
    Some(match url.port() {
        Some(port) => format!("{}://{host}:{port}", url.scheme()),
        None => format!("{}://{host}", url.scheme()),
    })
}

#[cfg(unix)]
fn mode_of(path: &Path) -> Result<Option<u32>, ()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| Some(m.permissions().mode() & 0o777))
        .map_err(|_| ())
}

#[cfg(not(unix))]
fn mode_of(path: &Path) -> Result<Option<u32>, ()> {
    std::fs::metadata(path).map(|_| None).map_err(|_| ())
}

fn check_secret_file(flag: &'static str, path: &Path, out: &mut Vec<Violation>) {
    match mode_of(path) {
        Err(()) => out.push(Violation::SecretFileUnreadable { flag }),
        Ok(None) => out.push(Violation::SecretFileUnverifiable { flag }),
        Ok(Some(mode)) if mode & 0o077 != 0 => out.push(Violation::SecretFileMode { flag, mode }),
        Ok(Some(_)) => {}
    }
}

/// Every condition of the configuration that does not hold. `built` is what
/// only the built agent surfaces know (`Dataplane::relaxations`): empty
/// before the build, the list after it.
#[must_use]
pub fn violations(config: &ApiConfig, built: &[Relaxation]) -> Vec<Violation> {
    let mut out = Vec::new();
    let mut on = relaxations::of_config(config);
    on.extend(built.iter().copied());
    out.extend(on.into_iter().map(Violation::Relaxed));
    if config.tls.is_none() {
        out.push(Violation::PlainListener);
    }
    if let Some(TlsConfig { key_path, .. }) = &config.tls {
        check_secret_file("--tls-key", key_path, &mut out);
    }
    if let Some(dp) = &config.dataplane {
        check_secret_file(
            "--subject-pseudonym-key",
            &dp.subject_pseudonym_key,
            &mut out,
        );
        if let Some(hsm) = &dp.hsm {
            check_secret_file("--hsm-pin-file", &hsm.pin_file, &mut out);
        }
        match crate::dataplane::provider_endpoints(&dp.providers) {
            None => out.push(Violation::ProvidersUnreadable),
            Some(endpoints) => {
                for (audience, endpoint) in endpoints {
                    out.extend(provider_violation(audience, &endpoint));
                }
            }
        }
    }
    out
}

fn provider_violation(audience: String, endpoint: &str) -> Option<Violation> {
    let Ok(url) = Url::parse(endpoint) else {
        return Some(Violation::ProviderEndpointForm { audience });
    };
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Some(Violation::ProviderEndpointForm { audience });
    }
    if url.scheme() == "https" {
        return None;
    }
    // Plain HTTP, or a scheme the gateway would refuse anyway.
    match origin_of(endpoint) {
        Some(origin) => Some(Violation::PlainProvider { audience, origin }),
        None => Some(Violation::ProviderEndpointForm { audience }),
    }
}

/// The text printed when the start is refused.
#[must_use]
pub fn refusal(program: &str, violations: &[Violation]) -> String {
    let mut text = format!(
        "{program}: --require-hardening refused to start. {} condition{} failed:\n",
        violations.len(),
        if violations.len() == 1 { "" } else { "s" }
    );
    for v in violations {
        let _ = writeln!(text, "  - {}: {}", v.name(), v.message());
    }
    text.push_str("Fix these, or start without --require-hardening (development only).");
    text
}

/// The exit status of a refused start (`EX_CONFIG`).
pub const EXIT_REFUSED: i32 = 78;

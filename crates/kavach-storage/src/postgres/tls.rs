//! TLS policy for every Postgres connection.
//!
//! One function, [`connect_options`], turns a database URL into connection
//! options, and every connection in this crate goes through it:
//!
//! - A URL that names no `sslmode` connects with **`verify-full`**: TLS, a
//!   certificate that chains to a trusted root, and a matching host name.
//! - A URL that names a weaker mode (`disable`, `allow`, `prefer`,
//!   `require`, `verify-ca`) is **refused**, unless the caller is in a
//!   development mode ([`DatabaseTls::allow_weaker`]). The development mode
//!   alone never downgrades a connection: the URL must ask for it too.
//! - The mode is always set explicitly on the options, so `PGSSLMODE` in
//!   the environment cannot weaken it.
//!
//! Trusted roots are the system's, plus `ca` (a PEM file) when given, plus
//! `sslrootcert` in the URL.

use std::path::PathBuf;
use std::str::FromStr;

use sqlx::postgres::{PgConnectOptions, PgSslMode};

/// How connections to Postgres are secured.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DatabaseTls {
    /// Development only: accept a mode weaker than `verify-full` **when the
    /// URL asks for one**. Without it such a URL is refused.
    pub allow_weaker: bool,
    /// Extra trusted CA certificates (PEM), e.g. a private CA.
    pub ca: Option<PathBuf>,
}

impl DatabaseTls {
    /// The policy of a process: `development` is its `--insecure-dev` (or
    /// equivalent) switch, `ca` its extra trusted CA file.
    #[must_use]
    pub fn new(development: bool, ca: Option<PathBuf>) -> Self {
        Self {
            allow_weaker: development,
            ca,
        }
    }

    /// For development and test databases: a URL may ask for a weaker mode.
    #[must_use]
    pub fn development() -> Self {
        Self {
            allow_weaker: true,
            ca: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DatabaseTlsError {
    /// The message never contains the URL (it holds a password).
    #[error("the database URL is not valid")]
    Url,
    #[error("the database URL has an unknown sslmode ({0})")]
    UnknownMode(String),
    #[error(
        "the database URL asks for sslmode={0}; connections to Postgres must use verify-full \
         (TLS with a verified certificate and host name). A weaker mode is accepted only in \
         a development mode, when the URL asks for it"
    )]
    Refused(String),
    #[error("the database CA file {0} cannot be read")]
    Ca(String),
}

/// The `sslmode` a URL names, if any (`sslmode` or `ssl-mode`, as sqlx reads
/// them).
fn url_sslmode(database_url: &str) -> Option<&str> {
    let (_, query) = database_url.split_once('?')?;
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .filter(|(key, _)| matches!(*key, "sslmode" | "ssl-mode"))
        .map(|(_, value)| value)
        .next_back()
}

/// Connection options for `database_url` under `tls`. See the module docs.
pub fn connect_options(
    database_url: &str,
    tls: &DatabaseTls,
) -> Result<PgConnectOptions, DatabaseTlsError> {
    let asked = url_sslmode(database_url);
    let mode = match asked {
        None => PgSslMode::VerifyFull,
        Some(value) => {
            let mode = PgSslMode::from_str(value)
                .map_err(|_| DatabaseTlsError::UnknownMode(value.to_string()))?;
            match mode {
                PgSslMode::VerifyFull => mode,
                _ if tls.allow_weaker => {
                    tracing::warn!(
                        sslmode = value,
                        "the database connection is NOT fully protected: the URL asks for a \
                         weaker sslmode and a development mode allows it. Development only."
                    );
                    mode
                }
                _ => return Err(DatabaseTlsError::Refused(value.to_string())),
            }
        }
    };
    let mut options =
        PgConnectOptions::from_str(database_url).map_err(|_| DatabaseTlsError::Url)?;
    if let Some(ca) = &tls.ca {
        if std::fs::metadata(ca).map_or(true, |meta| !meta.is_file()) {
            return Err(DatabaseTlsError::Ca(ca.display().to_string()));
        }
        options = options.ssl_root_cert(ca);
    }
    // Explicitly, always: PGSSLMODE in the environment must not decide.
    Ok(options.ssl_mode(mode))
}

#[cfg(test)]
mod tests {
    use super::*;

    const URL: &str = "postgres://kavach_runtime:secret-pw@db.internal:5432/kavach";
    const WEAKER: [&str; 5] = ["disable", "allow", "prefer", "require", "verify-ca"];

    fn mode(url: &str, tls: &DatabaseTls) -> Result<String, DatabaseTlsError> {
        connect_options(url, tls).map(|options| format!("{:?}", options.get_ssl_mode()))
    }

    #[test]
    fn a_url_without_sslmode_is_verified_in_every_mode() {
        for tls in [DatabaseTls::default(), DatabaseTls::development()] {
            assert_eq!(mode(URL, &tls).unwrap(), "VerifyFull");
            // Other query parameters do not count as a mode.
            let with_options = format!("{URL}?options=-c%20search_path%3Dkt_1&application_name=x");
            assert_eq!(mode(&with_options, &tls).unwrap(), "VerifyFull");
            assert_eq!(
                mode(&format!("{URL}?sslmode=verify-full"), &tls).unwrap(),
                "VerifyFull"
            );
        }
    }

    #[test]
    fn a_weaker_mode_is_refused_outside_development_and_needs_the_url_inside_it() {
        for weaker in WEAKER {
            for key in ["sslmode", "ssl-mode"] {
                let url = format!("{URL}?application_name=x&{key}={weaker}");
                // Outside development: startup is refused.
                assert_eq!(
                    mode(&url, &DatabaseTls::default()),
                    Err(DatabaseTlsError::Refused(weaker.into())),
                    "{key}={weaker}"
                );
                // In development the URL's explicit request is honoured.
                let allowed = mode(&url, &DatabaseTls::development()).unwrap();
                assert_ne!(allowed, "VerifyFull", "{key}={weaker}");
            }
        }
        // The development mode alone downgrades nothing.
        assert_eq!(
            mode(URL, &DatabaseTls::development()).unwrap(),
            "VerifyFull"
        );
        // When a URL names the mode twice, the last one is what sqlx uses,
        // and what is judged.
        let twice = format!("{URL}?sslmode=verify-full&sslmode=disable");
        assert_eq!(
            mode(&twice, &DatabaseTls::default()),
            Err(DatabaseTlsError::Refused("disable".into()))
        );
        assert_eq!(
            mode(&format!("{URL}?sslmode=sometimes"), &DatabaseTls::default()),
            Err(DatabaseTlsError::UnknownMode("sometimes".into()))
        );
    }

    #[test]
    fn the_environment_cannot_weaken_a_connection() {
        // sqlx reads PGSSLMODE when it builds options; the policy sets the
        // mode explicitly afterwards. (No other test in this crate reads
        // these variables, and the result is the same for any value.)
        std::env::set_var("PGSSLMODE", "disable");
        let unspecified = mode(URL, &DatabaseTls::default());
        let verified = mode(
            &format!("{URL}?sslmode=verify-full"),
            &DatabaseTls::default(),
        );
        let development = mode(URL, &DatabaseTls::development());
        std::env::remove_var("PGSSLMODE");
        assert_eq!(unspecified.unwrap(), "VerifyFull");
        assert_eq!(verified.unwrap(), "VerifyFull");
        assert_eq!(
            development.unwrap(),
            "VerifyFull",
            "not even in development"
        );
    }

    #[test]
    fn errors_never_show_the_url_and_a_missing_ca_is_refused() {
        let refused = connect_options(&format!("{URL}?sslmode=require"), &DatabaseTls::default())
            .unwrap_err()
            .to_string();
        assert!(refused.contains("sslmode=require") && refused.contains("verify-full"));
        assert!(
            !refused.contains("secret-pw") && !refused.contains("db.internal"),
            "{refused}"
        );

        let invalid = connect_options(
            "postgres://user:secret-pw@:not-a-port/x",
            &DatabaseTls::default(),
        )
        .unwrap_err();
        assert_eq!(invalid, DatabaseTlsError::Url);
        assert!(!invalid.to_string().contains("secret-pw"));

        let missing = DatabaseTls {
            allow_weaker: false,
            ca: Some("/nonexistent/kavach-db-ca.pem".into()),
        };
        assert!(matches!(
            connect_options(URL, &missing),
            Err(DatabaseTlsError::Ca(_))
        ));
        // A CA that exists is accepted (its contents are read at connect).
        let ca = std::env::temp_dir().join(format!("kavach-db-ca-{}.pem", std::process::id()));
        std::fs::write(&ca, "-----BEGIN CERTIFICATE-----\n").unwrap();
        let with_ca = DatabaseTls {
            allow_weaker: false,
            ca: Some(ca.clone()),
        };
        assert_eq!(mode(URL, &with_ca).unwrap(), "VerifyFull");
        std::fs::remove_file(&ca).unwrap();
    }
}

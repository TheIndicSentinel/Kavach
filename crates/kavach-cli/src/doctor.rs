//! `kavach doctor`: checks this machine and project, and says what to fix.
//!
//! Each check is ok, a warning or a failure, with a fix. Exit status:
//! 0 all ok, 2 warnings, 1 a failure.

use std::fmt::Write as _;
use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::process::Command;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Duration, FixedOffset, Timelike, Utc};
use serde::Serialize;
use serde_json::json;

use crate::init::{MODEL_FILE, PACK_FILE};
use crate::output::{CliError, Status, Style, Ui};
use crate::project::Project;

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub name: &'static str,
    pub status: Status,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
}

fn check(name: &'static str, status: Status, detail: impl Into<String>) -> Check {
    Check {
        name,
        status,
        detail: detail.into(),
        fix: None,
    }
}

impl Check {
    fn fix(mut self, fix: impl Into<String>) -> Self {
        self.fix = Some(fix.into());
        self
    }
}

/// The files `kavach dev up` needs, relative to the bundle.
const BUNDLE_FILES: [&str; 12] = [
    "kavach/jwks.json",
    "kavach/mandate-config.json",
    "kavach/consents.json",
    "kavach/references.json",
    "kavach/providers.json",
    "kavach/tool-signers.json",
    "kavach/tools/agent-tools.yaml",
    "kavach/tools/agent-tools.yaml.sig",
    "kavach/tls/ca.pem",
    "provider/tls.pem",
    PACK_FILE,
    MODEL_FILE,
];

fn bundle(project: &Project) -> Check {
    let missing: Vec<_> = BUNDLE_FILES
        .iter()
        .filter(|f| !project.bundle().join(f).is_file())
        .collect();
    if missing.is_empty() {
        check(
            "bundle",
            Status::Ok,
            "dev keys, tokens and fixtures are in place",
        )
    } else {
        check(
            "bundle",
            Status::Failed,
            format!(
                "missing: {}",
                missing
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )
        .fix("run `kavach init` in a new directory")
    }
}

/// Key and token files must be readable by their owner only.
#[cfg(unix)]
fn secrets(project: &Project) -> Check {
    use std::os::unix::fs::PermissionsExt;
    let mut open = Vec::new();
    for dir in ["kavach/keys", "agents"] {
        let Ok(entries) = std::fs::read_dir(project.bundle().join(dir)) else {
            continue;
        };
        for entry in entries.flatten() {
            let mode = entry.metadata().map_or(0, |m| m.permissions().mode());
            if mode & 0o077 != 0 {
                open.push(format!("{dir}/{}", entry.file_name().to_string_lossy()));
            }
        }
    }
    if open.is_empty() {
        check("secrets", Status::Ok, "key and token files are owner-only")
    } else {
        check(
            "secrets",
            Status::Failed,
            format!("readable by group or others: {}", open.join(", ")),
        )
        .fix(format!(
            "chmod 600 on those files (under {})",
            project.bundle().display()
        ))
    }
}

#[cfg(not(unix))]
fn secrets(_project: &Project) -> Check {
    check(
        "secrets",
        Status::Ok,
        "permissions are not checked on this platform",
    )
}

/// The `exp` of a JWT, without verifying it (the file is our own).
fn token_expiry(path: &Path) -> Option<DateTime<Utc>> {
    let token = std::fs::read_to_string(path).ok()?;
    let payload = URL_SAFE_NO_PAD
        .decode(token.trim().split('.').nth(1)?)
        .ok()?;
    let exp = serde_json::from_slice::<serde_json::Value>(&payload).ok()?["exp"].as_i64()?;
    DateTime::from_timestamp(exp, 0)
}

fn tokens(project: &Project, now: DateTime<Utc>) -> Check {
    let paths = [
        project.bundle().join("operator.jwt"),
        project.bundle().join("agents/collections-agent.jwt"),
    ];
    let soonest = paths.iter().filter_map(|p| token_expiry(p)).min();
    let fix = "run `kavach init` in a new directory for fresh tokens";
    match soonest {
        None => check(
            "tokens",
            Status::Failed,
            "cannot read the dev access tokens",
        )
        .fix(fix),
        Some(exp) if exp <= now => {
            check("tokens", Status::Failed, format!("expired at {exp}")).fix(fix)
        }
        Some(exp) if exp - now < Duration::hours(24) => {
            check("tokens", Status::Warnings, format!("expire at {exp}")).fix(fix)
        }
        Some(exp) => check(
            "tokens",
            Status::Ok,
            format!("valid until {}", exp.date_naive()),
        ),
    }
}

fn ports(project: &Project) -> Check {
    let l = &project.file.listen;
    let all: [(&str, SocketAddr); 4] = [
        ("operator", l.operator),
        ("agent", l.agent),
        ("sor", l.sor),
        ("provider", l.provider),
    ];
    let not_loopback: Vec<_> = all
        .iter()
        .filter(|(_, a)| !a.ip().is_loopback())
        .map(|(n, a)| format!("{n} {a}"))
        .collect();
    if !not_loopback.is_empty() {
        return check(
            "ports",
            Status::Failed,
            format!("not on loopback: {}", not_loopback.join(", ")),
        )
        .fix("a dev project listens on 127.0.0.1 only; fix [listen] in kavach.toml");
    }
    let busy: Vec<_> = all
        .iter()
        .filter(|(_, a)| TcpListener::bind(a).is_err())
        .map(|(n, a)| format!("{n} {a}"))
        .collect();
    if busy.is_empty() {
        check("ports", Status::Ok, "all four loopback ports are free")
    } else {
        check(
            "ports",
            Status::Failed,
            format!("in use: {}", busy.join(", ")),
        )
        .fix("stop what uses them (another `kavach dev up`?), or change [listen] in kavach.toml")
    }
}

/// Free space where the project lives (POSIX `df`).
fn disk(root: &Path) -> Check {
    let output = Command::new("df").arg("-Pk").arg(root).output();
    let free_kib = output.ok().filter(|o| o.status.success()).and_then(|o| {
        let text = String::from_utf8_lossy(&o.stdout).into_owned();
        text.lines()
            .nth(1)?
            .split_whitespace()
            .nth(3)?
            .parse::<u64>()
            .ok()
    });
    match free_kib {
        None => check("disk", Status::Warnings, "cannot measure free space"),
        Some(kib) if kib < 100 * 1024 => {
            check("disk", Status::Failed, format!("{} MiB free", kib / 1024))
                .fix("free some space: Postgres and evidence exports need room")
        }
        Some(kib) if kib < 1024 * 1024 => {
            check("disk", Status::Warnings, format!("{} MiB free", kib / 1024))
                .fix("free some space before long runs")
        }
        Some(kib) => check(
            "disk",
            Status::Ok,
            format!("{} GiB free", kib / (1024 * 1024)),
        ),
    }
}

async fn database(project: &Project) -> Check {
    let Some(db) = &project.file.database else {
        return check(
            "database",
            Status::Ok,
            "none configured: `kavach dev up` keeps data in memory",
        );
    };
    let tls = kavach_storage::DatabaseTls::development();
    let options = match kavach_storage::connect_options(&db.url, &tls) {
        Ok(o) => o,
        Err(e) => {
            return check("database", Status::Failed, format!("the URL is refused: {e}"))
                .fix("use postgres://user:password@localhost:5432/db?sslmode=disable for a local dev database")
        }
    };
    let sslmode = format!("{:?}", options.get_ssl_mode());
    let connect = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(3))
        .connect_with(options)
        .await;
    match connect {
        Ok(pool) => {
            let version: Option<String> = sqlx::query_scalar("SHOW server_version")
                .fetch_one(&pool)
                .await
                .ok();
            pool.close().await;
            check(
                "database",
                Status::Ok,
                format!(
                    "Postgres {} reachable (sslmode {sslmode})",
                    version.unwrap_or_default()
                ),
            )
        }
        Err(e) => check("database", Status::Failed, format!("cannot connect: {e}"))
            .fix("start Postgres, or remove [database] from kavach.toml to use memory"),
    }
}

/// The kernel clock's sync status: what production requires.
fn clock() -> Check {
    use kavach_ports::SyncStatus;
    let reading = kavach_clocksync::read();
    match reading.status {
        SyncStatus::Synced { max_error_ms } => check(
            "clock",
            Status::Ok,
            format!("synced (max error {max_error_ms} ms)"),
        ),
        _ => check(
            "clock",
            Status::Warnings,
            format!(
                "not known to be synced ({}); dev mode does not need it, production does",
                reading.detail
            ),
        )
        .fix("run NTP or chrony before running Kavach for real"),
    }
}

/// Agent contact is allowed 08:00–19:00 IST: outside it, reminders BLOCK.
fn contact_hours(now: DateTime<Utc>) -> Check {
    let ist = FixedOffset::east_opt(5 * 3600 + 1800).map(|o| now.with_timezone(&o));
    match ist {
        Some(t) if (8..19).contains(&t.hour()) => check(
            "contact_hours",
            Status::Ok,
            format!("{:02}:{:02} IST, inside 08:00–19:00", t.hour(), t.minute()),
        ),
        Some(t) => check(
            "contact_hours",
            Status::Warnings,
            format!(
                "{:02}:{:02} IST: reminders are BLOCKed outside 08:00–19:00",
                t.hour(),
                t.minute()
            ),
        )
        .fix("for a demo now, start with `kavach dev up --at 11:00`"),
        None => check("contact_hours", Status::Warnings, "cannot compute IST"),
    }
}

pub async fn run(ui: &Ui, dir: &Path) -> Result<i32, CliError> {
    let project = Project::find(dir)?;
    let now = Utc::now();
    let checks = vec![
        check("project", Status::Ok, format!("{}", project.root.display())),
        bundle(&project),
        secrets(&project),
        tokens(&project, now),
        ports(&project),
        disk(&project.root),
        database(&project).await,
        clock(),
        contact_hours(now),
    ];
    let status = checks.iter().fold(Status::Ok, |s, c| s.and(c.status));
    let mut human = String::new();
    for c in &checks {
        let _ = writeln!(
            human,
            "{:>5}  {:<14} {}",
            ui.status(c.status),
            c.name,
            c.detail
        );
        if let Some(fix) = &c.fix {
            let _ = writeln!(
                human,
                "       {:<14} {} {fix}",
                "",
                ui.paint(Style::Dim, "fix:")
            );
        }
    }
    human.push_str(match status {
        Status::Ok => "\nReady: `kavach dev up`.",
        Status::Warnings => "\nUsable, with warnings above.",
        Status::Failed => "\nFix the failures above first.",
    });
    Ok(ui.finish("doctor", status, &json!({ "checks": checks }), &human))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn contact_hours_follow_ist() {
        let at = |h, m| Utc.with_ymd_and_hms(2026, 10, 2, h, m, 0).unwrap();
        assert_eq!(contact_hours(at(5, 30)).status, Status::Ok); // 11:00 IST
        assert_eq!(contact_hours(at(14, 0)).status, Status::Warnings); // 19:30 IST
        assert_eq!(contact_hours(at(2, 0)).status, Status::Warnings); // 07:30 IST
    }
}

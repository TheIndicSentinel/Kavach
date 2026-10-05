//! The development clock (`kavach dev up --at` / `--clock`).
//!
//! A trusted clock set by hand, for development stacks only: `Dataplane`
//! refuses it unless `--insecure-dev` is on **and** every signing key is a
//! `dev-` key. Everything it times says so: its sync status is
//! [`SyncStatus::DevFixed`], so agent records and checkpoints carry
//! `time_sync: dev_fixed`, which the verifiers refuse unless told they are
//! verifying a development stack.
//!
//! A fixed clock (`--clock`) can be moved with `POST /v1/dev/clock`, only
//! forward: evidence timestamps never run backwards and checkpoints stay in
//! order. A started-at clock (`--at`) runs at real speed and cannot be moved.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Utc};
use kavach_auth::KavachAction;
use kavach_ports::{SyncStatus, TimeSource, TrustedNow};
use kavach_storage::AuditInsert;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::auth::{authorize_credentials, resolve_credentials, Credentials};
use crate::state::AppState;
use crate::strict_json::{StrictJson, StrictJsonRejection};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DevClockKind {
    /// Stays at its time until moved forward (`--clock`).
    Fixed,
    /// Starts at its time and runs at real speed (`--at`).
    StartedAt,
}

#[derive(Debug)]
pub struct DevClock {
    kind: DevClockKind,
    at: Mutex<DateTime<Utc>>,
    since: Instant,
}

impl DevClock {
    #[must_use]
    pub fn fixed(at: DateTime<Utc>) -> Arc<Self> {
        Arc::new(Self {
            kind: DevClockKind::Fixed,
            at: Mutex::new(at),
            since: Instant::now(),
        })
    }

    #[must_use]
    pub fn started_at(at: DateTime<Utc>) -> Arc<Self> {
        Arc::new(Self {
            kind: DevClockKind::StartedAt,
            at: Mutex::new(at),
            since: Instant::now(),
        })
    }

    #[must_use]
    pub fn kind(&self) -> DevClockKind {
        self.kind
    }

    /// The clock's time now.
    #[must_use]
    pub fn time(&self) -> DateTime<Utc> {
        let at = self.at.lock().map_or_else(|e| *e.into_inner(), |t| *t);
        match self.kind {
            DevClockKind::Fixed => at,
            DevClockKind::StartedAt => {
                at + chrono::Duration::from_std(self.since.elapsed()).unwrap_or_default()
            }
        }
    }

    /// Moves a fixed clock to `to`, which must be later than now. Returns
    /// the time it moved from.
    pub fn advance_to(&self, to: DateTime<Utc>) -> Result<DateTime<Utc>, String> {
        if self.kind != DevClockKind::Fixed {
            return Err("only a fixed development clock (--clock) can be moved".into());
        }
        let mut at = self
            .at
            .lock()
            .map_err(|_| "the development clock is poisoned")?;
        if to <= *at {
            return Err(format!(
                "the development clock only moves forward: it is at {}, and {} is not later",
                at.to_rfc3339(),
                to.to_rfc3339()
            ));
        }
        let from = *at;
        *at = to;
        Ok(from)
    }

    /// What `/v1/runtime` shows.
    #[must_use]
    pub fn view(&self) -> serde_json::Value {
        json!({ "kind": self.kind, "at": self.time(), "development_only": true })
    }
}

impl TimeSource for DevClock {
    fn now(&self) -> TrustedNow {
        TrustedNow {
            utc: self.time(),
            sync: SyncStatus::DevFixed,
        }
    }
}

/// The signing key ids a development clock may run with: all `dev-`.
pub fn refuse_unless_dev_keys(ids: &[(&str, &str)]) -> Result<(), String> {
    for (role, id) in ids {
        if !kavach_ports::agent_evidence::is_dev_key(id) {
            return Err(format!(
                "a development clock runs with development keys only; the {role} key is {id:?}"
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetClock {
    pub at: DateTime<Utc>,
}

fn refuse(status: StatusCode, error: &str) -> Response {
    (status, Json(json!({ "error": error }))).into_response()
}

/// `POST /v1/dev/clock`: moves a fixed development clock forward. Exists
/// only on a stack started with one; audited.
pub async fn set_dev_clock(
    State(state): State<Arc<AppState>>,
    credentials: Credentials,
    body: Result<StrictJson<SetClock>, StrictJsonRejection>,
) -> Response {
    let Some(clock) = state
        .dataplane()
        .and_then(|dp| dp.dev_clock())
        .filter(|c| c.kind() == DevClockKind::Fixed)
    else {
        return refuse(
            StatusCode::NOT_FOUND,
            "no fixed development clock: start the stack with `kavach dev up --clock`",
        );
    };
    if let Err(e) = authorize_credentials(&state, &credentials, KavachAction::SetDevClock) {
        return e.into_response();
    }
    let Ok(StrictJson(body)) = body else {
        return refuse(
            StatusCode::BAD_REQUEST,
            "expected {\"at\": <RFC 3339 time>}",
        );
    };
    let from = clock.time();
    if body.at <= from {
        return refuse(
            StatusCode::CONFLICT,
            "the development clock only moves forward (move to the next day instead)",
        );
    }
    let actor = resolve_credentials(&state, &credentials).map_or_else(
        |_| "unauthenticated (access control off)".to_string(),
        |p| p.id,
    );
    let audited = state
        .admin()
        .append_audit(AuditInsert {
            action: "dev_clock_set".into(),
            resource_type: "dev_clock".into(),
            resource_id: "dataplane".into(),
            actor_principal: actor,
            approver_principal: String::new(),
            payload: json!({ "from": from, "to": body.at }),
        })
        .await;
    if audited.is_err() {
        return refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            "the clock change could not be audited",
        );
    }
    match clock.advance_to(body.at) {
        Ok(_) => Json(clock.view()).into_response(),
        Err(e) => refuse(StatusCode::CONFLICT, &e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn a_fixed_clock_stays_put_and_only_moves_forward() {
        let at = Utc.with_ymd_and_hms(2026, 10, 1, 5, 30, 0).unwrap();
        let clock = DevClock::fixed(at);
        assert_eq!(clock.now().utc, at);
        assert_eq!(clock.now().sync, SyncStatus::DevFixed);
        assert!(clock.advance_to(at).is_err(), "not later");
        assert!(
            clock.advance_to(at - chrono::Duration::seconds(1)).is_err(),
            "backwards"
        );
        let later = at + chrono::Duration::hours(9);
        assert_eq!(clock.advance_to(later).unwrap(), at);
        assert_eq!(clock.now().utc, later);
    }

    #[test]
    fn a_started_at_clock_runs_and_cannot_be_moved() {
        let at = Utc.with_ymd_and_hms(2026, 10, 1, 5, 30, 0).unwrap();
        let clock = DevClock::started_at(at);
        assert!(clock.now().utc >= at);
        assert_eq!(clock.now().sync, SyncStatus::DevFixed);
        assert!(clock.advance_to(at + chrono::Duration::hours(1)).is_err());
    }

    #[test]
    fn only_development_keys() {
        assert!(refuse_unless_dev_keys(&[("evidence", "dev-evidence-1")]).is_ok());
        assert!(refuse_unless_dev_keys(&[
            ("evidence", "dev-evidence-1"),
            ("mandate", "kavach-mandate-1")
        ])
        .is_err());
    }
}

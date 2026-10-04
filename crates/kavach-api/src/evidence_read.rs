//! `GET /v1/agent-decisions/{record_id}`: one agent decision record, for
//! `kavach why` (operator listener).
//!
//! Record ids are sequential (`adr:<tenant>:<partition>:<seq>`), so a
//! by-id read does **not** prevent enumeration. What protects records is:
//! an operator token authorised for `read_evidence` (Cedar), a rate limit,
//! and an audit entry for every read, found or not (who read which id).
//! A read that cannot be audited is refused. Records hold pseudonyms and a
//! parameter MAC, never a raw reference, destination, token or credential.

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use kavach_auth::KavachAction;
use kavach_ports::agent_evidence::AgentEvidenceStore;
use kavach_storage::AuditInsert;
use serde_json::json;

use crate::auth::{authorize_credentials, resolve_credentials, Credentials};
use crate::state::AppState;

/// Reads per second across the process, and the burst allowed.
const READS_PER_SECOND: f64 = 5.0;
const BURST: f64 = 20.0;

struct Bucket {
    tokens: f64,
    last: Instant,
}

fn take() -> bool {
    static BUCKET: OnceLock<Mutex<Bucket>> = OnceLock::new();
    let bucket = BUCKET.get_or_init(|| {
        Mutex::new(Bucket {
            tokens: BURST,
            last: Instant::now(),
        })
    });
    let Ok(mut b) = bucket.lock() else {
        return false;
    };
    let now = Instant::now();
    b.tokens = (b.tokens + now.duration_since(b.last).as_secs_f64() * READS_PER_SECOND).min(BURST);
    b.last = now;
    if b.tokens >= 1.0 {
        b.tokens -= 1.0;
        true
    } else {
        false
    }
}

/// `adr:<tenant>:<partition>:<seq>`, bounded and plain.
fn valid_record_id(id: &str) -> bool {
    let parts: Vec<_> = id.split(':').collect();
    id.len() <= 128
        && parts.len() == 4
        && parts[0] == "adr"
        && !parts[1].is_empty()
        && parts[1]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        && (1..=9).contains(&parts[2].len())
        && parts[2].bytes().all(|b| b.is_ascii_digit())
        && (1..=19).contains(&parts[3].len())
        && parts[3].bytes().all(|b| b.is_ascii_digit())
}

fn refuse(status: StatusCode, error: &str) -> Response {
    (status, Json(json!({ "error": error }))).into_response()
}

pub async fn read_agent_decision(
    State(state): State<Arc<AppState>>,
    credentials: Credentials,
    Path(record_id): Path<String>,
) -> Response {
    if let Err(e) = authorize_credentials(&state, &credentials, KavachAction::ReadEvidence) {
        return e.into_response();
    }
    if !valid_record_id(&record_id) {
        return refuse(
            StatusCode::BAD_REQUEST,
            "record_id must be adr:<tenant>:<partition>:<seq>",
        );
    }
    if !take() {
        return refuse(StatusCode::TOO_MANY_REQUESTS, "too many evidence reads");
    }
    let Some(dp) = state.dataplane() else {
        return refuse(StatusCode::NOT_FOUND, "agent surfaces are not configured");
    };
    // Who reads: the authenticated principal. With access control off
    // (development only) the read is still audited, as such.
    let reader = resolve_credentials(&state, &credentials).map_or_else(
        |_| "unauthenticated (access control off)".to_string(),
        |p| p.id,
    );
    let core = dp.core();
    let Ok(record) = core.store().record(core.tenant_id(), &record_id).await else {
        return refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            "evidence store unavailable",
        );
    };
    let audited = state
        .admin()
        .append_audit(AuditInsert {
            action: "read_evidence".into(),
            resource_type: "agent_decision".into(),
            resource_id: record_id.clone(),
            actor_principal: reader,
            approver_principal: String::new(),
            payload: json!({ "found": record.is_some() }),
        })
        .await;
    if audited.is_err() {
        // Never hand out evidence that was not audited.
        return refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            "the read could not be audited",
        );
    }
    let Some(record) = record else {
        return refuse(StatusCode::NOT_FOUND, "no such record");
    };
    let outcome = match record.payload.credential_id.as_deref() {
        Some(credential) => core.outcome(credential).await.ok().flatten(),
        None => None,
    };
    Json(json!({ "record": record, "outcome": outcome })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_ids_are_plain_and_bounded() {
        assert!(valid_record_id("adr:default:0:1"));
        assert!(valid_record_id("adr:nbfc-demo:12:9876543"));
        for bad in [
            "",
            "adr:default:0",
            "adr:default:0:1:2",
            "x:default:0:1",
            "adr::0:1",
            "adr:default:a:1",
            "adr:default:0:-1",
            "adr:de fault:0:1",
            "adr:default:0:12345678901234567890",
        ] {
            assert!(!valid_record_id(bad), "{bad}");
        }
    }
}

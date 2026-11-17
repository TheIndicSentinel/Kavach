//! Evidence reads for `kavach why` (operator listener):
//! `GET /v1/agent-decisions/{record_id}` (agent decision records) and
//! `GET /v1/decision-events/{evidence_id}` (evaluate decision events).
//!
//! Record ids are sequential (`adr:<tenant>:<partition>:<seq>`), so a
//! by-id read does **not** prevent enumeration. What protects records is:
//! an operator token authorised for `read_evidence` (Cedar), a rate limit,
//! and an audit entry for every read, found or not (who read which id).
//! A read that cannot be audited is refused. Records hold pseudonyms and a
//! parameter MAC, never a raw reference, destination, token or credential.

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use kavach_auth::KavachAction;
use kavach_ports::agent_evidence::AgentEvidenceStore;
use kavach_storage::AuditInsert;
use serde::Deserialize;
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
pub(crate) fn valid_record_id(id: &str) -> bool {
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
    crate::problem::Problem::for_status(status, error).into_response()
}

/// Who reads, as the audit row records them.
struct Reader {
    id: String,
    acting_as_superadmin: bool,
}

/// Authorises the read, checks the id and the rate limit; returns who
/// reads. With access control off (development only) the read is still
/// audited, as such.
async fn admit(
    state: &AppState,
    credentials: &Credentials,
    id_ok: bool,
    id_error: &str,
) -> Result<Reader, Box<Response>> {
    let decision = authorize_credentials(state, credentials, KavachAction::ReadEvidence)
        .await
        .map_err(|e| Box::new(e.into_response()))?;
    if !id_ok {
        return Err(Box::new(refuse(StatusCode::BAD_REQUEST, id_error)));
    }
    if !take() {
        return Err(Box::new(refuse(
            StatusCode::TOO_MANY_REQUESTS,
            "too many evidence reads",
        )));
    }
    Ok(Reader {
        id: resolve_credentials(state, credentials).map_or_else(
            |_| "unauthenticated (access control off)".to_string(),
            |p| p.id,
        ),
        acting_as_superadmin: decision.acting_as_superadmin,
    })
}

/// Records the read; a read that cannot be audited is refused.
async fn audit(
    state: &AppState,
    resource_type: &str,
    id: &str,
    reader: Reader,
    found: bool,
) -> Result<(), Box<Response>> {
    state
        .admin()
        .append_audit(AuditInsert {
            acting_as_superadmin: reader.acting_as_superadmin,
            action: "read_evidence".into(),
            resource_type: resource_type.into(),
            resource_id: id.into(),
            actor_principal: reader.id,
            approver_principal: String::new(),
            payload: json!({ "found": found }),
        })
        .await
        .map(|_| ())
        .map_err(|_| {
            // Never hand out evidence that was not audited.
            Box::new(refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "the read could not be audited",
            ))
        })
}

pub async fn read_agent_decision(
    State(state): State<Arc<AppState>>,
    credentials: Credentials,
    Path(record_id): Path<String>,
) -> Response {
    let reader = match admit(
        &state,
        &credentials,
        valid_record_id(&record_id),
        "record_id must be adr:<tenant>:<partition>:<seq>",
    )
    .await
    {
        Ok(reader) => reader,
        Err(refused) => return *refused,
    };
    let Some(dp) = state.dataplane() else {
        return refuse(StatusCode::NOT_FOUND, "agent surfaces are not configured");
    };
    let core = dp.core();
    let Ok(record) = core.store().record(core.tenant_id(), &record_id).await else {
        return refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            "evidence store unavailable",
        );
    };
    if let Err(refused) = audit(
        &state,
        "agent_decision",
        &record_id,
        reader,
        record.is_some(),
    )
    .await
    {
        return *refused;
    }
    let Some(record) = record else {
        return refuse(StatusCode::NOT_FOUND, "no such record");
    };
    let outcome = match record.payload.credential_id.as_deref() {
        Some(credential) => core.outcome(credential).await.ok().flatten(),
        None => None,
    };
    let resolutions = match (record.payload.credential_id.as_deref(), outcome.as_ref()) {
        (Some(credential), Some(outcome))
            if outcome.outcome == kavach_ports::agent_evidence::Outcome::Unknown =>
        {
            match core.store().resolutions(core.tenant_id(), credential).await {
                Ok(rows) => rows,
                Err(_) => {
                    return refuse(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "evidence store unavailable",
                    )
                }
            }
        }
        _ => Vec::new(),
    };
    Json(json!({ "record": record, "outcome": outcome, "resolutions": resolutions }))
        .into_response()
}

#[derive(Debug, Deserialize)]
pub struct UnknownOutcomeQuery {
    limit: Option<u32>,
    cursor: Option<String>,
}

/// `GET /v1/unknown-outcomes`: a tenant-scoped, audited review page. Unlike
/// the reconciler's work queue, this includes every governing state.
pub async fn list_unknown_outcomes(
    State(state): State<Arc<AppState>>,
    credentials: Credentials,
    Query(query): Query<UnknownOutcomeQuery>,
) -> Response {
    const DEFAULT_PAGE: u32 = 50;
    const MAX_PAGE: u32 = 100;
    let limit = query.limit.unwrap_or(DEFAULT_PAGE);
    let cursor_ok = query.cursor.as_deref().is_none_or(valid_event_part);
    let reader = match admit(
        &state,
        &credentials,
        (1..=MAX_PAGE).contains(&limit) && cursor_ok,
        "limit must be 1-100 and cursor must be a bounded credential id",
    )
    .await
    {
        Ok(reader) => reader,
        Err(refused) => return *refused,
    };
    let Some(dp) = state.dataplane() else {
        return refuse(StatusCode::NOT_FOUND, "agent surfaces are not configured");
    };
    let core = dp.core();
    let mut rows = match core
        .store()
        .unknown_outcome_reviews(core.tenant_id(), query.cursor.as_deref(), limit + 1)
        .await
    {
        Ok(rows) => rows,
        Err(_) => {
            return refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "evidence store unavailable",
            )
        }
    };
    let has_more = rows.len() > limit as usize;
    rows.truncate(limit as usize);
    let next_cursor = has_more
        .then(|| rows.last().map(|row| row.outcome.credential_id.clone()))
        .flatten();
    let items: Vec<_> = rows
        .into_iter()
        .map(|row| {
            use kavach_ports::outcome_resolution::Governing;
            let (governing_state, governing_source) =
                match kavach_ports::outcome_resolution::governing(&row.resolutions) {
                    Governing::Unresolved => ("unresolved", None),
                    Governing::Ambiguous => ("ambiguous", None),
                    Governing::Conflicted => ("conflicted", None),
                    Governing::Confirmed { state, source } => {
                        (state.as_str(), Some(source.as_str()))
                    }
                };
            json!({
                "outcome": row.outcome,
                "action": row.action,
                "resolutions": row.resolutions,
                "governing_state": governing_state,
                "governing_source": governing_source,
            })
        })
        .collect();
    if let Err(refused) = audit(
        &state,
        "unknown_outcomes",
        core.tenant_id(),
        reader,
        !items.is_empty(),
    )
    .await
    {
        return *refused;
    }
    Json(json!({ "items": items, "next_cursor": next_cursor })).into_response()
}

/// A system-of-record name or event id: what the SoR listener accepts in
/// an event, bounded.
fn valid_event_part(part: &str) -> bool {
    (1..=128).contains(&part.len())
        && part
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':'))
}

/// `GET /v1/agent-revocations/{system}/{event_id}`: the evidence-chain
/// record of a revocation by a system-of-record event (ADR-012 §7), if one
/// was written. Same protections as agent records: `read_evidence`, the
/// rate limit, an audit entry per read. It names the loan only by its
/// pseudonym.
pub async fn read_revocation_record(
    State(state): State<Arc<AppState>>,
    credentials: Credentials,
    Path((system, event_id)): Path<(String, String)>,
) -> Response {
    let reader = match admit(
        &state,
        &credentials,
        valid_event_part(&system) && valid_event_part(&event_id),
        "system and event_id must be 1-128 of A-Z a-z 0-9 . _ - :",
    )
    .await
    {
        Ok(reader) => reader,
        Err(refused) => return *refused,
    };
    let Some(dp) = state.dataplane() else {
        return refuse(StatusCode::NOT_FOUND, "agent surfaces are not configured");
    };
    let core = dp.core();
    let Ok(record) = core
        .store()
        .revocation_record(core.tenant_id(), &system, &event_id)
        .await
    else {
        return refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            "evidence store unavailable",
        );
    };
    let id = format!("{system}/{event_id}");
    if let Err(refused) = audit(&state, "mandate_revocation", &id, reader, record.is_some()).await {
        return *refused;
    }
    match record {
        Some(record) => Json(json!({ "record": record })).into_response(),
        None => refuse(StatusCode::NOT_FOUND, "no revocation record for this event"),
    }
}

/// A canonical (lowercase) UUID, as evidence ids are.
fn valid_evidence_id(id: &str) -> bool {
    id.len() == 36
        && id.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_digit() || (b'a'..=b'f').contains(&b),
        })
}

/// `GET /v1/decision-events/{evidence_id}`: one evaluate decision event, as
/// export views show it (a tombstoned event is redacted, and says so). It
/// holds `input_digest`, never the input. Same protections as agent
/// records: `read_evidence`, the rate limit, an audit entry per read.
pub async fn read_decision_event(
    State(state): State<Arc<AppState>>,
    credentials: Credentials,
    Path(evidence_id): Path<String>,
) -> Response {
    let reader = match admit(
        &state,
        &credentials,
        valid_evidence_id(&evidence_id),
        "evidence_id must be a lowercase UUID",
    )
    .await
    {
        Ok(reader) => reader,
        Err(refused) => return *refused,
    };
    let Ok(event) = state.decision_event(&evidence_id).await else {
        return refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            "evidence store unavailable",
        );
    };
    if let Err(refused) = audit(
        &state,
        "decision_event",
        &evidence_id,
        reader,
        event.is_some(),
    )
    .await
    {
        return *refused;
    }
    let Some((event, tombstoned)) = event else {
        return refuse(StatusCode::NOT_FOUND, "no such decision event");
    };
    Json(json!({ "event": event, "tombstoned": tombstoned })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_ids_are_canonical_uuids() {
        assert!(valid_evidence_id("9771a6c1-edc5-4b2b-b38d-ffb397b7df55"));
        for bad in [
            "",
            "9771A6C1-EDC5-4B2B-B38D-FFB397B7DF55",
            "9771a6c1edc54b2bb38dffb397b7df55",
            "9771a6c1-edc5-4b2b-b38d-ffb397b7df5",
            "9771a6c1-edc5-4b2b-b38d-ffb397b7df5g",
            "../../etc/passwd",
        ] {
            assert!(!valid_evidence_id(bad), "{bad}");
        }
    }

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

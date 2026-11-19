//! The agent kill switch on the operator listener (ADR-013 §3 and §4):
//!
//! - `POST /v1/agents/{agent_id}/restrict | quarantine | revoke`: one
//!   principal with `stop_agent`, immediately, only ever **tightening**. A
//!   move to a weaker state is refused (it would loosen without approval),
//!   and the same stop again is idempotent. Reinstating is a change request
//!   (`reinstate_agent`) another principal approves.
//! - `GET /v1/agents/{agent_id}`: the agent's state (`read_agent_state`).
//! - `GET /v1/agents?state=&limit=&cursor=`: the tenant's agents (those a
//!   passport names) with their states, by agent id, a page at a time
//!   (`read_agent_state`).
//!
//! The agent id must be one a passport names, exactly: a typo is a 404, not
//! a row nobody reads. Every attempt is audited, refused ones too, and
//! counted; there is a global rate limit on stops. A stop is never held up
//! by the audit log or the evidence chain (the change record follows, by the
//! reconciler if it must): stopping an agent is the safe direction.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use kavach_auth::KavachAction;
use kavach_domain::{AgentState, ReasonCode};
use kavach_ports::agent_state::{AgentStateChange, AgentStateStore};
use kavach_ports::MandateStore as _;
use kavach_storage::AuditInsert;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::auth::{authorize_credentials, resolve_credentials, Credentials};
use crate::error::ApiError;
use crate::state::AppState;
use crate::strict_json::StrictJson;

/// An agent id as a passport names it: bounded and plain. Matched exactly
/// afterwards, with no case folding.
fn valid_agent_id(id: &str) -> bool {
    (1..=128).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':'))
}

fn refuse(status: StatusCode, code: &str, detail: &str) -> Response {
    let _ = code;
    crate::problem::Problem::for_status(status, detail).into_response()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StopBody {
    reason_code: ReasonCode,
    /// The operator's words: kept in the store and the audit log, never in
    /// the evidence chain.
    #[serde(default)]
    note: String,
}

/// `superadmin`: the stop was allowed only by a superadmin policy
/// (ADR-019 §7); false for a refused attempt, which nothing allowed.
async fn audit(state: &AppState, action: &str, agent: &str, actor: (String, bool), payload: Value) {
    let (actor, superadmin) = actor;
    let result = state
        .admin()
        .append_audit(AuditInsert {
            tenant_id: state.tenant_id().into(),
            acting_as_superadmin: superadmin,
            action: action.into(),
            resource_type: "agent".into(),
            resource_id: agent.into(),
            actor_principal: actor,
            approver_principal: String::new(),
            payload,
        })
        .await;
    if let Err(err) = result {
        // Never hold up a stop: the signed record in the chain follows.
        tracing::error!(error = %err, agent = %agent, "an agent state attempt could not be audited");
    }
}

fn actor(state: &AppState, credentials: &Credentials) -> String {
    resolve_credentials(state, credentials).map_or_else(
        |_| "unauthenticated (access control off)".to_string(),
        |p| p.id,
    )
}

fn row_json(agent_id: &str, row: Option<&kavach_ports::agent_state::StoredAgentState>) -> Value {
    match row {
        Some(r) => json!({
            "agent_id": agent_id,
            "state": r.state.as_str(),
            "change_no": r.change_no,
            "reason_code": r.reason_code.as_str(),
            "note": r.note,
            "changed_by": r.changed_by,
            "approved_by": r.approved_by,
            "change_request_id": r.change_request_id,
            "changed_at": r.changed_at,
        }),
        None => json!({ "agent_id": agent_id, "state": "active", "change_no": 0 }),
    }
}

/// What an attempt that passed every check has to work with.
struct Admitted<'a> {
    dp: &'a crate::dataplane::Dataplane,
    tenant: String,
    who: String,
    /// Allowed only by a superadmin policy (ADR-019 §7).
    superadmin: bool,
    from: AgentState,
    current: Option<kavach_ports::agent_state::StoredAgentState>,
}

/// How an attempt was refused: the metric's `result`, the HTTP status and
/// what to tell the caller.
#[derive(Clone, Copy)]
struct Refusal {
    result: &'static str,
    status: StatusCode,
    detail: &'static str,
}

/// An attempt that is refused: counted, audited, and answered.
async fn refused_attempt(
    state: &AppState,
    attempt: (&str, AgentState, String),
    from: Option<AgentState>,
    refusal: Refusal,
) -> Response {
    let (agent_id, to, who) = attempt;
    state
        .metrics()
        .observe_agent_state_change(to.as_str(), refusal.result);
    let mut payload = json!({ "to": to.as_str(), "why": refusal.result });
    if let (Some(from), Value::Object(map)) = (from, &mut payload) {
        map.insert("from".into(), json!(from.as_str()));
    }
    audit(state, "stop_agent_refused", agent_id, (who, false), payload).await;
    refuse(refusal.status, refusal.result, refusal.detail)
}

const FORBIDDEN: Refusal = Refusal {
    result: "forbidden",
    status: StatusCode::FORBIDDEN,
    detail: "forbidden",
};
const ROLES_UNAVAILABLE: Refusal = Refusal {
    result: "unavailable",
    status: StatusCode::SERVICE_UNAVAILABLE,
    detail: "role bindings could not be read",
};
const RATE_LIMITED: Refusal = Refusal {
    result: "rate_limited",
    status: StatusCode::TOO_MANY_REQUESTS,
    detail: "too many agent stops",
};
const UNKNOWN_AGENT: Refusal = Refusal {
    result: "unknown_agent",
    status: StatusCode::NOT_FOUND,
    detail: "no such agent in this configuration",
};
const WOULD_LOOSEN: Refusal = Refusal {
    result: "refused",
    status: StatusCode::CONFLICT,
    detail: "this would loosen the agent's state: reinstating needs a change request \
             another principal approves",
};
const CHANGED: Refusal = Refusal {
    result: "refused",
    status: StatusCode::CONFLICT,
    detail: "the agent's state changed or the change is invalid; read it and retry",
};
const STATE_UNAVAILABLE: Refusal = Refusal {
    result: "unavailable",
    status: StatusCode::SERVICE_UNAVAILABLE,
    detail: "the agent state store is unavailable; nothing was changed, retry",
};

/// Authorises the attempt, checks the id and the limit and the passport, and
/// reads the agent's state. `Err` is the answer to give.
async fn admit<'a>(
    state: &'a AppState,
    credentials: &Credentials,
    agent_id: &str,
    to: AgentState,
) -> Result<Admitted<'a>, Box<Response>> {
    let who = actor(state, credentials);
    let decision = match authorize_credentials(state, credentials, KavachAction::StopAgent).await {
        Ok(decision) => decision,
        Err(err) => {
            // A bindings read failure is not a refusal of this principal.
            let refusal = if matches!(err, ApiError::Unavailable(_)) {
                ROLES_UNAVAILABLE
            } else {
                FORBIDDEN
            };
            let _ = refused_attempt(state, (agent_id, to, who), None, refusal).await;
            return Err(Box::new(err.into_response()));
        }
    };
    if !valid_agent_id(agent_id) {
        return Err(Box::new(refuse(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "agent_id must be 1-128 of A-Z a-z 0-9 . _ - :",
        )));
    }
    let Some(dp) = state.dataplane() else {
        return Err(Box::new(refuse(
            StatusCode::NOT_FOUND,
            "not_found",
            "agent surfaces are not configured",
        )));
    };
    if !dp.admit_stop() {
        return Err(Box::new(
            refused_attempt(state, (agent_id, to, who), None, RATE_LIMITED).await,
        ));
    }
    let core = dp.core();
    let tenant = core.tenant_id().to_string();
    if !dp.mandates().has_passport(&tenant, agent_id) {
        return Err(Box::new(
            refused_attempt(state, (agent_id, to, who), None, UNKNOWN_AGENT).await,
        ));
    }
    let current = match core.store().current(&tenant, agent_id).await {
        Ok(current) => current,
        Err(err) => {
            tracing::warn!(error = %err.message, "agent state unavailable");
            state
                .metrics()
                .observe_agent_state_change(to.as_str(), "unavailable");
            return Err(Box::new(refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                "the agent state store is unavailable; nothing was changed, retry",
            )));
        }
    };
    let from = current.as_ref().map_or(AgentState::Active, |r| r.state);
    Ok(Admitted {
        dp,
        tenant,
        who,
        superadmin: decision.acting_as_superadmin,
        from,
        current,
    })
}

/// Revokes every mandate `agent_id` holds, after its state is `revoked`
/// (which already blocks everything through the chain): a sweep that stops
/// half-way is still safe, and a repeat finishes it. Returns what it revoked
/// and what it could not.
async fn sweep_mandates(
    dp: &crate::dataplane::Dataplane,
    tenant: &str,
    agent_id: &str,
) -> (Vec<String>, Vec<String>) {
    let mut revoked = Vec::new();
    let mut failed = Vec::new();
    match dp.mandates().store().active_held_by(tenant, agent_id).await {
        Ok(held) => {
            for id in held {
                let manual = kavach_domain::mandate::RevocationReason::Manual;
                match dp.mandates().revoke(tenant, &id, manual).await {
                    Ok(done) => revoked.extend(done.revoked),
                    Err(err) => failed.push(format!("{id}: {}", err.message)),
                }
            }
        }
        Err(err) => failed.push(format!("listing: {}", err.message)),
    }
    if !failed.is_empty() {
        tracing::error!(
            agent = %agent_id,
            failed = ?failed,
            "ALERT agent revoked but not all its mandates are: repeat the revoke to finish"
        );
    }
    (revoked, failed)
}

async fn stop(
    state: Arc<AppState>,
    credentials: Credentials,
    agent_id: String,
    to: AgentState,
    body: StopBody,
) -> Response {
    let admitted = match admit(&state, &credentials, &agent_id, to).await {
        Ok(admitted) => admitted,
        Err(response) => return *response,
    };
    let Admitted {
        dp,
        tenant,
        who,
        superadmin,
        from,
        current,
    } = admitted;
    let core = dp.core();

    // Only ever tightening. The same stop again is not a change.
    if to < from {
        let attempt = (agent_id.as_str(), to, who);
        return refused_attempt(&state, attempt, Some(from), WOULD_LOOSEN).await;
    }
    let (mut applied, mut record, mut row) = (false, "unchanged", current);
    if to > from {
        let change = AgentStateChange {
            tenant_id: tenant.clone(),
            agent_id: agent_id.clone(),
            to,
            reason_code: body.reason_code,
            note: body.note.trim().to_string(),
            changed_by: who.clone(),
            approved_by: None,
            change_request_id: None,
            at: core.clock_now(),
        };
        match core.change_agent_state(change).await {
            Ok(done) => {
                applied = true;
                record = if done.record.is_some() {
                    "written"
                } else {
                    "pending"
                };
                if let Some(why) = &done.record_error {
                    tracing::error!(agent = %agent_id, reason = %why, "ALERT agent state record pending: the reconciler will write it");
                }
                row = Some(done.state);
            }
            Err(err) => {
                let refusal = match err.class {
                    kavach_ports::ErrorClass::Unavailable => STATE_UNAVAILABLE,
                    kavach_ports::ErrorClass::Rejected | kavach_ports::ErrorClass::Invalid => {
                        CHANGED
                    }
                };
                let attempt = (agent_id.as_str(), to, who);
                return refused_attempt(&state, attempt, Some(from), refusal).await;
            }
        }
    }

    let (swept, not_swept) = if to == AgentState::Revoked {
        sweep_mandates(dp, &tenant, &agent_id).await
    } else {
        (Vec::new(), Vec::new())
    };

    state
        .metrics()
        .observe_agent_state_change(to.as_str(), if applied { "applied" } else { "unchanged" });
    audit(
        &state,
        "stop_agent",
        &agent_id,
        (who, superadmin),
        json!({
            "from": from.as_str(),
            "to": to.as_str(),
            "reason_code": body.reason_code.as_str(),
            "applied": applied,
            "record": record,
            "mandates_revoked": swept.len(),
            "mandates_failed": not_swept.len(),
        }),
    )
    .await;
    let mut out = row_json(&agent_id, row.as_ref());
    if let Value::Object(map) = &mut out {
        map.insert("applied".into(), json!(applied));
        map.insert("record".into(), json!(record));
        if to == AgentState::Revoked {
            map.insert("mandates_revoked".into(), json!(swept));
            map.insert("mandates_not_revoked".into(), json!(not_swept));
        }
    }
    Json(out).into_response()
}

pub async fn restrict(
    State(state): State<Arc<AppState>>,
    credentials: Credentials,
    Path(agent_id): Path<String>,
    StrictJson(body): StrictJson<StopBody>,
) -> Response {
    stop(state, credentials, agent_id, AgentState::Restricted, body).await
}

pub async fn quarantine(
    State(state): State<Arc<AppState>>,
    credentials: Credentials,
    Path(agent_id): Path<String>,
    StrictJson(body): StrictJson<StopBody>,
) -> Response {
    stop(state, credentials, agent_id, AgentState::Quarantined, body).await
}

pub async fn revoke(
    State(state): State<Arc<AppState>>,
    credentials: Credentials,
    Path(agent_id): Path<String>,
    StrictJson(body): StrictJson<StopBody>,
) -> Response {
    stop(state, credentials, agent_id, AgentState::Revoked, body).await
}

/// `GET /v1/agents/{agent_id}`.
pub async fn get_agent(
    State(state): State<Arc<AppState>>,
    credentials: Credentials,
    Path(agent_id): Path<String>,
) -> Response {
    if let Err(err) =
        authorize_credentials(&state, &credentials, KavachAction::ReadAgentState).await
    {
        return err.into_response();
    }
    if !valid_agent_id(&agent_id) {
        return refuse(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "agent_id must be 1-128 of A-Z a-z 0-9 . _ - :",
        );
    }
    let Some(dp) = state.dataplane() else {
        return refuse(
            StatusCode::NOT_FOUND,
            "not_found",
            "agent surfaces are not configured",
        );
    };
    let core = dp.core();
    if !dp.mandates().has_passport(core.tenant_id(), &agent_id) {
        return refuse(
            StatusCode::NOT_FOUND,
            "not_found",
            "no such agent in this configuration",
        );
    }
    match core.store().current(core.tenant_id(), &agent_id).await {
        Ok(row) => Json(row_json(&agent_id, row.as_ref())).into_response(),
        Err(_) => refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "the agent state store is unavailable",
        ),
    }
}

/// Agents a page holds by default, and at most.
const DEFAULT_PAGE: u32 = 50;
const MAX_PAGE: u32 = 200;
/// Agent ids per batch read of their states while a page is picked.
const STATE_BATCH: usize = 500;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListQuery {
    state: Option<String>,
    limit: Option<u32>,
    cursor: Option<String>,
}

/// A page's size: `limit` clamped to 1..=200, 50 when absent.
fn page_size(limit: Option<u32>) -> usize {
    limit.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_PAGE) as usize
}

/// From `agents` (agent id and state, in agent-id order), those in `wanted`
/// (every one for `None`) up to `room` of them, and whether one that is
/// wanted was left out for lack of room.
fn pick<'a>(
    agents: &[(&'a str, AgentState)],
    wanted: Option<AgentState>,
    room: usize,
) -> (Vec<&'a str>, bool) {
    let mut matching = agents
        .iter()
        .filter(|(_, state)| wanted.is_none_or(|w| w == *state))
        .map(|(id, _)| *id);
    let picked: Vec<&str> = matching.by_ref().take(room).collect();
    (picked, matching.next().is_some())
}

/// `GET /v1/agents`: the tenant's agents and their states, by agent id.
/// `next_cursor` is the last agent id of the page when more may follow.
pub async fn list_agents(
    State(state): State<Arc<AppState>>,
    credentials: Credentials,
    query: Result<axum::extract::Query<ListQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    if let Err(err) =
        authorize_credentials(&state, &credentials, KavachAction::ReadAgentState).await
    {
        return err.into_response();
    }
    let Ok(axum::extract::Query(query)) = query else {
        return refuse(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "the query takes state, limit (an integer) and cursor",
        );
    };
    let wanted = match query.state.as_deref() {
        None => None,
        Some(name) => match AgentState::parse(name) {
            Some(s) => Some(s),
            None => {
                return refuse(
                    StatusCode::BAD_REQUEST,
                    "bad_request",
                    "state must be active, restricted, quarantined or revoked",
                )
            }
        },
    };
    if let Some(cursor) = query.cursor.as_deref() {
        if !valid_agent_id(cursor) {
            return refuse(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "cursor must be an agent id from a previous page",
            );
        }
    }
    let Some(dp) = state.dataplane() else {
        return refuse(
            StatusCode::NOT_FOUND,
            "not_found",
            "agent surfaces are not configured",
        );
    };
    let size = page_size(query.limit);
    let core = dp.core();
    let tenant = core.tenant_id();
    let after: Vec<String> = dp
        .agent_ids()
        .filter(|id| query.cursor.as_deref().is_none_or(|c| *id > c))
        .map(str::to_string)
        .collect();

    let unavailable = || {
        refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "the agent state store is unavailable",
        )
    };
    let mut items = Vec::with_capacity(size);
    // The last agent id the page considered, when more may follow it.
    let mut next_cursor: Option<&str> = None;
    for batch in after.chunks(STATE_BATCH) {
        // A batch read picks the page; each picked agent's row is then read
        // whole. One that changed state in between is left out when the
        // page is filtered by state: it no longer matches.
        let Ok(states) = core.store().states(tenant, batch).await else {
            return unavailable();
        };
        let mut agents: Vec<(&str, AgentState)> = Vec::with_capacity(batch.len());
        for id in batch {
            // The store answers for every id asked; one missing is a store
            // fault, never shown as "active".
            let Some(state) = states.get(id) else {
                return unavailable();
            };
            agents.push((id.as_str(), *state));
        }
        let (picked, left_over) = pick(&agents, wanted, size - items.len());
        let last_picked = picked.last().copied();
        for id in picked {
            let Ok(row) = core.store().current(tenant, id).await else {
                return unavailable();
            };
            let now = row.as_ref().map_or(AgentState::Active, |r| r.state);
            if wanted.is_none_or(|w| w == now) {
                items.push(row_json(id, row.as_ref()));
            }
        }
        // Stop at a full page, or where agents that match were left over
        // (the next page starts after the last one picked, so none is
        // skipped even if one picked dropped out).
        if left_over || items.len() == size {
            let rest_unread = after.last() != batch.last();
            if left_over || rest_unread {
                next_cursor = last_picked;
            }
            break;
        }
    }
    Json(json!({ "items": items, "next_cursor": next_cursor })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_page_holds_50_by_default_and_never_more_than_200() {
        assert_eq!(page_size(None), 50);
        assert_eq!(page_size(Some(0)), 1);
        assert_eq!(page_size(Some(7)), 7);
        assert_eq!(page_size(Some(200)), 200);
        assert_eq!(page_size(Some(201)), 200);
        assert_eq!(page_size(Some(u32::MAX)), 200);
    }

    #[test]
    fn picking_keeps_order_filters_by_state_and_says_when_more_match() {
        let ids: Vec<String> = (0..250).map(|n| format!("agent-{n:03}")).collect();
        let agents: Vec<(&str, AgentState)> = ids
            .iter()
            .enumerate()
            .map(|(n, id)| {
                let state = if n % 5 == 0 {
                    AgentState::Quarantined
                } else {
                    AgentState::Active
                };
                (id.as_str(), state)
            })
            .collect();

        let (page, more) = pick(&agents, None, page_size(Some(1000)));
        assert_eq!(page.len(), 200);
        assert!(more);
        assert_eq!(page[0], "agent-000");
        assert_eq!(page[199], "agent-199");

        let (page, more) = pick(&agents, Some(AgentState::Quarantined), 200);
        assert_eq!(page.len(), 50);
        assert!(!more, "every quarantined agent fits");
        assert!(page.iter().all(|id| id.ends_with('0') || id.ends_with('5')));

        let (page, more) = pick(&agents, Some(AgentState::Quarantined), 50);
        assert_eq!(page.len(), 50);
        assert!(!more, "exactly full: nothing left over");

        let (page, more) = pick(&agents, Some(AgentState::Revoked), 200);
        assert!(page.is_empty());
        assert!(!more);
    }
}

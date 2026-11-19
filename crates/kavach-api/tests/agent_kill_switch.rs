//! The agent kill switch through the operator API (ADR-013, K1-3a): stop,
//! tighten-only, revoke and its mandates, issuance refused to a revoked
//! agent, reinstatement by change request (a second principal; idempotent on
//! the request's id across the two stores), the global stop limit, and an
//! audit entry for every attempt.

mod agent_fixture;
mod contract;

use std::sync::Arc;

use axum::http::StatusCode;
use contract::{agent_router, router as operator_router, sor_router};
use kavach_api::{AppState, EvidenceStoreKind};
use kavach_dataplane::MandateVerifier as _;
use kavach_domain::AgentState;
use kavach_ports::agent_evidence::AgentEvidenceStore as _;
use kavach_ports::agent_state::AgentStateStore;
use serde_json::{json, Value};

use agent_fixture::*;

const AGENT: &str = "collections-agent";

/// The same store kind as `like`, fresh: memory is rebuilt; a Postgres
/// stack is another isolated database.
async fn fresh_like(like: &Gw) -> Gw {
    let dp = like.state.dataplane().unwrap();
    let postgres = matches!(
        dp.core().store().as_ref(),
        kavach_api::dataplane::EvidenceBackend::Postgres(_)
    );
    if postgres {
        postgres_world().await.expect("a database")
    } else {
        world().await
    }
}

/// On Postgres as the least-privilege runtime role, or `None` without a
/// test database.
async fn postgres_world() -> Option<Gw> {
    let (owner, runtime) = kavach_storage::testing::isolated_database_urls().await?;
    let mut api = config(
        EvidenceStoreKind::Postgres {
            database_url: runtime,
        },
        true,
        50,
    );
    api.migration_database_url = Some(owner);
    Some(gateway_on(api, Some(NUMBER), true).await)
}

async fn world() -> Gw {
    gateway_on(
        config(EvidenceStoreKind::Memory, true, 50),
        Some(NUMBER),
        true,
    )
    .await
}

fn as_principal(sub: &str, groups: &[&str]) -> String {
    format!(
        "Bearer {}",
        token("kavach-api", json!({ "sub": sub, "groups": groups }))
    )
}

/// One operator request: status and body.
async fn operator(
    state: &Arc<AppState>,
    who: &str,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", who);
    if body.is_some() {
        request = request.header("content-type", "application/json");
    }
    let response = operator_router(state.clone())
        .oneshot(
            request
                .body(Body::from(body.map(|b| b.to_string()).unwrap_or_default()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn admin() -> String {
    as_principal("ops-1", &["admins"])
}

fn approver() -> String {
    as_principal("ops-2", &["change-approvers"])
}

async fn stop(state: &Arc<AppState>, to: &str, agent: &str) -> (StatusCode, Value) {
    operator(
        state,
        &admin(),
        "POST",
        &format!("/v1/agents/{agent}/{to}"),
        Some(json!({ "reason_code": "rogue_behaviour", "note": "sending outside its task" })),
    )
    .await
}

async fn state_of(state: &Arc<AppState>, agent: &str) -> AgentState {
    let dp = state.dataplane().unwrap();
    dp.core()
        .store()
        .states("default", &[agent.to_string()])
        .await
        .unwrap()[agent]
}

async fn audit_actions(state: &Arc<AppState>) -> Vec<String> {
    state
        .admin()
        .list_audit(200)
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.action)
        .collect()
}

async fn a_quarantine_stops_the_next_call_and_is_recorded(gw: Gw) {
    assert_eq!(gw.remind("before").await.0, StatusCode::OK);
    let (status, body) = stop(&gw.state, "quarantine", AGENT).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["state"], "quarantined");
    assert_eq!(body["applied"], true);
    assert_eq!(body["record"], "written", "{body}");
    assert_eq!(body["changed_by"], "ops-1");

    let (_, reply) = gw.remind("after").await;
    assert_eq!(reply["decision"], "BLOCK", "{reply}");
    assert!(
        reply["reasons"]
            .to_string()
            .contains("agent_state:quarantined"),
        "{reply}"
    );

    // The record is in the chain, signed, and holds the closed code and a
    // digest, never the operator's words.
    let dp = gw.state.dataplane().unwrap();
    let chain = dp.core().store().records("default", 0).await.unwrap();
    let text = serde_json::to_string(&chain).unwrap();
    assert!(text.contains("\"kind\":\"agent_state\""), "{text}");
    assert!(
        !text.contains("outside its task"),
        "the note is not in the chain"
    );
    let (status, view) = operator(
        &gw.state,
        &admin(),
        "GET",
        &format!("/v1/agents/{AGENT}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{view}");
    assert_eq!(view["state"], "quarantined");
    assert_eq!(view["note"], "sending outside its task");
}

#[tokio::test]
async fn a_stop_only_ever_tightens_and_repeating_it_is_not_a_change() {
    let gw = world().await;
    assert_eq!(stop(&gw.state, "quarantine", AGENT).await.0, StatusCode::OK);
    // The same stop again: fine, and nothing new.
    let (status, again) = stop(&gw.state, "quarantine", AGENT).await;
    assert_eq!(status, StatusCode::OK, "{again}");
    assert_eq!(again["applied"], false);
    assert_eq!(again["change_no"], 1);
    // A weaker state would be loosening without approval.
    let (status, body) = stop(&gw.state, "restrict", AGENT).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(state_of(&gw.state, AGENT).await, AgentState::Quarantined);
    // Tighter is fine.
    assert_eq!(stop(&gw.state, "revoke", AGENT).await.0, StatusCode::OK);
    assert_eq!(state_of(&gw.state, AGENT).await, AgentState::Revoked);
}

#[tokio::test]
async fn an_unknown_agent_is_a_404_and_ids_match_exactly() {
    let gw = world().await;
    for id in [
        "Collections-Agent",
        "collections-agent ",
        "nobody",
        "collections",
    ] {
        let path = format!("/v1/agents/{}/quarantine", id.replace(' ', "%20"));
        let (status, body) = operator(
            &gw.state,
            &admin(),
            "POST",
            &path,
            Some(json!({ "reason_code": "other" })),
        )
        .await;
        assert!(
            matches!(status, StatusCode::NOT_FOUND | StatusCode::BAD_REQUEST),
            "{id:?}: {status} {body}"
        );
    }
    assert_eq!(state_of(&gw.state, AGENT).await, AgentState::Active);
    assert!(
        audit_actions(&gw.state)
            .await
            .contains(&"stop_agent_refused".to_string()),
        "a refused attempt is audited"
    );
}

#[tokio::test]
async fn only_admins_stop_and_a_refused_attempt_is_audited() {
    let gw = world().await;
    let viewer = as_principal("viewer-1", &["viewers"]);
    let (status, _) = operator(
        &gw.state,
        &viewer,
        "POST",
        &format!("/v1/agents/{AGENT}/quarantine"),
        Some(json!({ "reason_code": "other" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(state_of(&gw.state, AGENT).await, AgentState::Active);
    let audit = gw.state.admin().list_audit(50).await.unwrap();
    let refused = audit
        .iter()
        .find(|e| e.action == "stop_agent_refused")
        .expect("audited");
    assert_eq!(refused.actor_principal, "viewer-1");
}

async fn a_revoke_revokes_the_mandates_and_a_revoked_agent_is_issued_nothing(gw: Gw) {
    let (status, body) = stop(&gw.state, "revoke", AGENT).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["state"], "revoked");
    assert!(
        body["mandates_revoked"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m == &Value::String(gw.mandate.clone())),
        "{body}"
    );
    assert!(body["mandates_not_revoked"].as_array().unwrap().is_empty());
    let dp = gw.state.dataplane().unwrap();
    assert!(dp.mandates().verify("default", &gw.mandate).await.is_err());

    // Nothing new can be issued to it: not by an event, not by delegation.
    let (status, issued) = send(
        sor_router(gw.state.clone()),
        "/v1/sor/events",
        &[],
        json!({ "event": event_at("evt-after-revoke", "lms:loan/L-9", gw.clock_now()).await }),
    )
    .await;
    assert!(
        status.is_client_error(),
        "a mandate was issued to a revoked agent: {status} {issued}"
    );
    assert!(!issued.to_string().contains("mandate_id"), "{issued}");
}

/// The window between the state becoming `revoked` and the sweep finishing:
/// no mandate can be handed to the agent in it.
async fn nothing_is_issued_to_an_agent_mid_revoke(gw: Gw) {
    let dp = gw.state.dataplane().unwrap();
    // The state only, as a revoke that stopped before its sweep.
    dp.core()
        .change_agent_state(kavach_ports::agent_state::AgentStateChange {
            tenant_id: "default".into(),
            agent_id: AGENT.into(),
            to: AgentState::Revoked,
            reason_code: kavach_domain::ReasonCode::CompromiseSuspected,
            note: String::new(),
            changed_by: "ops-1".into(),
            approved_by: None,
            change_request_id: None,
            at: gw.clock_now(),
        })
        .await
        .unwrap();
    assert!(
        dp.mandates().verify("default", &gw.mandate).await.is_ok(),
        "the sweep has not run: the mandate is still active in the store"
    );
    let (status, body) = send(
        sor_router(gw.state.clone()),
        "/v1/sor/events",
        &[],
        json!({ "event": event_at("evt-mid-revoke", "lms:loan/L-8", gw.clock_now()).await }),
    )
    .await;
    assert!(status.is_client_error(), "{status} {body}");
    // The call itself is refused too: revoked blocks through the chain.
    let (_, reply) = gw.remind("mid-revoke").await;
    assert_eq!(reply["decision"], "BLOCK", "{reply}");
    // A repeat of the revoke finishes the sweep.
    let (status, again) = stop(&gw.state, "revoke", AGENT).await;
    assert_eq!(status, StatusCode::OK, "{again}");
    assert_eq!(again["applied"], false);
    assert!(again["mandates_revoked"]
        .as_array()
        .unwrap()
        .contains(&Value::String(gw.mandate.clone())));
}

async fn propose_reinstatement(state: &Arc<AppState>, to: &str) -> (StatusCode, Value) {
    operator(
        state,
        &admin(),
        "POST",
        "/v1/change-requests",
        Some(json!({
            "kind": "reinstate_agent",
            "params": { "agent_id": AGENT, "to": to, "reason_code": "reviewed", "note": "ok now" },
            "reason": "reviewed the incident",
        })),
    )
    .await
}

async fn approve(state: &Arc<AppState>, who: &str, request: &Value) -> (StatusCode, Value) {
    operator(
        state,
        who,
        "POST",
        &format!(
            "/v1/change-requests/{}/approve",
            request["id"].as_str().unwrap()
        ),
        Some(json!({ "change_digest": request["change_digest"] })),
    )
    .await
}

/// ADR-013 §3 and §2: two principals bring an agent back; its mandates were
/// only suspended, so they work again without being re-issued.
async fn a_reinstatement_needs_a_second_principal_and_restores_the_same_mandates(gw: Gw) {
    assert_eq!(stop(&gw.state, "quarantine", AGENT).await.0, StatusCode::OK);
    assert_eq!(gw.remind("while-stopped").await.1["decision"], "BLOCK");

    let (status, request) = propose_reinstatement(&gw.state, "active").await;
    assert_eq!(status, StatusCode::CREATED, "{request}");

    // The proposer is not the approver, even holding both roles.
    let both = as_principal("ops-1", &["admins", "change-approvers"]);
    let (status, body) = approve(&gw.state, &both, &request).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(state_of(&gw.state, AGENT).await, AgentState::Quarantined);

    let (status, applied) = approve(&gw.state, &approver(), &request).await;
    assert_eq!(status, StatusCode::OK, "{applied}");
    assert_eq!(state_of(&gw.state, AGENT).await, AgentState::Active);

    // The same mandate, not re-issued, authorises again.
    let (_, reply) = gw.remind("after-reinstatement").await;
    assert_eq!(reply["decision"], "PASS", "{reply}");
    let dp = gw.state.dataplane().unwrap();
    let row = dp
        .core()
        .store()
        .current("default", AGENT)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.approved_by.as_deref(), Some("ops-2"));
    assert_eq!(row.changed_by, "ops-1");
    assert_eq!(row.change_request_id.as_deref(), request["id"].as_str());
}

#[tokio::test]
async fn a_revoked_agent_cannot_be_reinstated() {
    let gw = world().await;
    assert_eq!(stop(&gw.state, "revoke", AGENT).await.0, StatusCode::OK);
    let (status, body) = propose_reinstatement(&gw.state, "active").await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(body.to_string().contains("revoked"), "{body}");
    assert_eq!(state_of(&gw.state, AGENT).await, AgentState::Revoked);
}

async fn a_reinstatement_fails_closed_when_the_agent_changed_since_the_proposal(gw: Gw) {
    assert_eq!(stop(&gw.state, "restrict", AGENT).await.0, StatusCode::OK);
    let (_, request) = propose_reinstatement(&gw.state, "active").await;
    // Someone tightens it further before the approval.
    assert_eq!(stop(&gw.state, "quarantine", AGENT).await.0, StatusCode::OK);
    let (status, body) = approve(&gw.state, &approver(), &request).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(state_of(&gw.state, AGENT).await, AgentState::Quarantined);
}

/// The two stores: the state change is written, then the approval is
/// committed. A crash between them must leave a request that completes, not
/// one that reinstates twice or never.
async fn an_approval_that_finds_its_own_change_already_written_completes(gw: Gw) {
    assert_eq!(stop(&gw.state, "quarantine", AGENT).await.0, StatusCode::OK);
    let (_, request) = propose_reinstatement(&gw.state, "active").await;
    let dp = gw.state.dataplane().unwrap();
    let before = dp
        .core()
        .store()
        .current("default", AGENT)
        .await
        .unwrap()
        .unwrap();
    // The first step of the approval, as the crashed attempt left it.
    dp.core()
        .change_agent_state(kavach_ports::agent_state::AgentStateChange {
            tenant_id: "default".into(),
            agent_id: AGENT.into(),
            to: AgentState::Active,
            reason_code: kavach_domain::ReasonCode::Reviewed,
            note: "ok now".into(),
            changed_by: "ops-1".into(),
            approved_by: Some("ops-2".into()),
            change_request_id: request["id"].as_str().map(str::to_string),
            at: gw.clock_now(),
        })
        .await
        .unwrap();
    let (status, applied) = approve(&gw.state, &approver(), &request).await;
    assert_eq!(status, StatusCode::OK, "{applied}");
    assert_eq!(applied["status"], "applied");
    let after = dp
        .core()
        .store()
        .current("default", AGENT)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.change_no, before.change_no + 1, "one change, not two");
    // Approving again is the same applied request.
    let (status, again) = approve(&gw.state, &approver(), &request).await;
    assert_eq!(status, StatusCode::OK, "{again}");

    // Another change of the agent by someone else is not mistaken for it.
    let gw = fresh_like(&gw).await;
    assert_eq!(stop(&gw.state, "quarantine", AGENT).await.0, StatusCode::OK);
    let (_, request) = propose_reinstatement(&gw.state, "active").await;
    let dp = gw.state.dataplane().unwrap();
    dp.core()
        .change_agent_state(kavach_ports::agent_state::AgentStateChange {
            tenant_id: "default".into(),
            agent_id: AGENT.into(),
            to: AgentState::Active,
            reason_code: kavach_domain::ReasonCode::Reviewed,
            note: String::new(),
            changed_by: "someone".into(),
            approved_by: Some("someone-else".into()),
            change_request_id: Some("another-request".into()),
            at: gw.clock_now(),
        })
        .await
        .unwrap();
    let (status, body) = approve(&gw.state, &approver(), &request).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
}

#[tokio::test]
async fn stops_are_rate_limited_and_counted_and_a_burst_is_audited() {
    let gw = world().await;
    let mut limited = 0;
    for _ in 0..16 {
        let (status, _) = stop(&gw.state, "quarantine", AGENT).await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            limited += 1;
        }
    }
    assert!(limited >= 5, "the burst is bounded: {limited} refused");
    let text = gw.state.metrics().gather_text().unwrap();
    assert!(
        text.contains(
            "kavach_agent_state_changes_total{result=\"rate_limited\",to=\"quarantined\",tenant_id=\"default\"}"
        ),
        "{text}"
    );
    assert!(audit_actions(&gw.state)
        .await
        .contains(&"stop_agent_refused".to_string()));
}

#[tokio::test]
async fn a_stop_by_the_agent_listener_is_not_possible() {
    let gw = world().await;
    // The agent's own listener has no such route, whatever its token.
    let (status, _) = send(
        agent_router(gw.state.clone()),
        &format!("/v1/agents/{AGENT}/quarantine"),
        &[("authorization", format!("Bearer {}", agent_token(AGENT)))],
        json!({ "reason_code": "other" }),
    )
    .await;
    assert!(
        matches!(
            status,
            StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
        ),
        "{status}"
    );
    assert_eq!(state_of(&gw.state, AGENT).await, AgentState::Active);
}

// Each scenario on both stores.
#[tokio::test]
async fn a_quarantine_stops_the_next_call_and_is_recorded_on_memory() {
    a_quarantine_stops_the_next_call_and_is_recorded(world().await).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_quarantine_stops_the_next_call_and_is_recorded_on_postgres() {
    let Some(gw) = postgres_world().await else {
        return;
    };
    a_quarantine_stops_the_next_call_and_is_recorded(gw).await;
}

#[tokio::test]
async fn a_revoke_revokes_the_mandates_and_a_revoked_agent_is_issued_nothing_on_memory() {
    a_revoke_revokes_the_mandates_and_a_revoked_agent_is_issued_nothing(world().await).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_revoke_revokes_the_mandates_and_a_revoked_agent_is_issued_nothing_on_postgres() {
    let Some(gw) = postgres_world().await else {
        return;
    };
    a_revoke_revokes_the_mandates_and_a_revoked_agent_is_issued_nothing(gw).await;
}

#[tokio::test]
async fn nothing_is_issued_to_an_agent_mid_revoke_on_memory() {
    nothing_is_issued_to_an_agent_mid_revoke(world().await).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn nothing_is_issued_to_an_agent_mid_revoke_on_postgres() {
    let Some(gw) = postgres_world().await else {
        return;
    };
    nothing_is_issued_to_an_agent_mid_revoke(gw).await;
}

#[tokio::test]
async fn a_reinstatement_needs_a_second_principal_and_restores_the_same_mandates_on_memory() {
    a_reinstatement_needs_a_second_principal_and_restores_the_same_mandates(world().await).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reinstatement_needs_a_second_principal_and_restores_the_same_mandates_on_postgres() {
    let Some(gw) = postgres_world().await else {
        return;
    };
    a_reinstatement_needs_a_second_principal_and_restores_the_same_mandates(gw).await;
}

#[tokio::test]
async fn an_approval_that_finds_its_own_change_already_written_completes_on_memory() {
    an_approval_that_finds_its_own_change_already_written_completes(world().await).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_approval_that_finds_its_own_change_already_written_completes_on_postgres() {
    let Some(gw) = postgres_world().await else {
        return;
    };
    an_approval_that_finds_its_own_change_already_written_completes(gw).await;
}

#[tokio::test]
async fn a_reinstatement_fails_closed_when_the_agent_changed_since_the_proposal_on_memory() {
    a_reinstatement_fails_closed_when_the_agent_changed_since_the_proposal(world().await).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reinstatement_fails_closed_when_the_agent_changed_since_the_proposal_on_postgres() {
    let Some(gw) = postgres_world().await else {
        return;
    };
    a_reinstatement_fails_closed_when_the_agent_changed_since_the_proposal(gw).await;
}

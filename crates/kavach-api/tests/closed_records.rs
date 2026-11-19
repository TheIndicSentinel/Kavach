//! Snapshot reconciliation through the operator API (ADR-012 addendum): the
//! lender's closed loans against the live authority Kavach holds. It reports
//! and revokes nothing.

mod agent_fixture;
mod contract;

use std::sync::Arc;

use axum::http::StatusCode;
use chrono::Duration;
use contract::{router as operator_router, sor_router};
use kavach_api::{AppState, EvidenceStoreKind};
use kavach_ports::TimeSource as _;
use serde_json::{json, Value};

use agent_fixture::*;

const LOAN: &str = "lms:loan/L-1";

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

fn admin() -> String {
    as_principal("ops-1", &["admins"])
}

async fn reconcile(state: &Arc<AppState>, who: &str, body: Value) -> (StatusCode, Value) {
    send(
        operator_router(state.clone()),
        "/v1/reconciliation/closed-records",
        &[("authorization", who.to_string())],
        body,
    )
    .await
}

fn snapshot(state: &str, closed_at: chrono::DateTime<chrono::Utc>) -> Value {
    json!({ "system": "lms", "records": [
        { "record_ref": LOAN, "state": state, "closed_at": closed_at }
    ]})
}

#[tokio::test]
async fn only_an_admin_may_reconcile_and_the_body_is_checked() {
    let gw = world().await;
    let at = gw.clock.now().utc;
    let (status, _) = reconcile(
        &gw.state,
        &as_principal("someone", &["viewers"]),
        snapshot("paid", at),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // An agent's token is for the agent listener: the operator route refuses it.
    let (status, _) = reconcile(
        &gw.state,
        &format!("Bearer {}", agent_token("collections-agent")),
        snapshot("paid", at),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // No credentials at all.
    let (status, _) = send(
        operator_router(gw.state.clone()),
        "/v1/reconciliation/closed-records",
        &[],
        snapshot("paid", at),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // Strict: no unknown member, a known state, at least one record.
    for body in [
        json!({ "system": "lms", "records": [], }),
        json!({ "system": "lms", "records": [{ "record_ref": LOAN, "state": "open", "closed_at": at }] }),
        json!({ "system": "lms", "extra": 1, "records": [{ "record_ref": LOAN, "state": "paid", "closed_at": at }] }),
        json!({ "system": "", "records": [{ "record_ref": LOAN, "state": "paid", "closed_at": at }] }),
    ] {
        let (status, _) = reconcile(&gw.state, &admin(), body).await;
        assert!(
            status == StatusCode::BAD_REQUEST || status == StatusCode::UNPROCESSABLE_ENTITY,
            "{status}"
        );
    }
}

/// The case the feature exists for: a payment event that never arrived. The
/// call finds the mandate, changes nothing, and is clean once the resent
/// event has revoked it.
#[tokio::test]
async fn a_lost_payment_is_found_and_the_resent_event_clears_it() {
    let gw = world().await;
    let now = gw.clock.now().utc;
    let closed_at = now + Duration::seconds(60);

    let (status, body) = reconcile(&gw.state, &admin(), snapshot("paid", closed_at)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["checked"], 1);
    assert_eq!(body["mismatches"], 1, "{body}");
    assert_eq!(body["findings"][0]["kind"], "should_have_been_revoked");
    assert_eq!(body["findings"][0]["mandate_id"], gw.mandate.as_str());
    assert!(body["remedy"].as_str().unwrap().contains("changed nothing"));

    // It changed nothing: asking again gives the same answer.
    let (_, again) = reconcile(&gw.state, &admin(), snapshot("paid", closed_at)).await;
    assert_eq!(again["mismatches"], 1, "{again}");

    // The lender resends the payment event: it revokes through the normal
    // path, and the snapshot is clean.
    let paid = any_event(&AnyEvent {
        event_id: "pay-resent",
        event_type: "loan.paid",
        tenant_id: "default",
        subject_ref: SUBJECT,
        record_ref: LOAN,
        consent_refs: &[],
        assigned_agent: "",
        at: closed_at,
        key: EventKey::Registered,
    })
    .await;
    let (status, reply) = send(
        sor_router(gw.state.clone()),
        "/v1/sor/events",
        &[],
        json!({ "event": paid }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let (_, clean) = reconcile(&gw.state, &admin(), snapshot("paid", closed_at)).await;
    assert_eq!(clean["mismatches"], 0, "{clean}");
    assert_eq!(clean["findings"], json!([]));
}

#[tokio::test]
async fn a_disputed_loan_with_any_live_mandate_is_a_mismatch() {
    let gw = world().await;
    let at = gw.clock.now().utc - Duration::hours(1);
    let (_, body) = reconcile(&gw.state, &admin(), snapshot("disputed", at)).await;
    assert_eq!(body["mismatches"], 1, "{body}");
}

/// Every run is audited with its counts, never with the loan references, and
/// the last run's count is the gauge the alert reads.
#[tokio::test]
async fn a_run_is_audited_by_counts_and_sets_the_gauge() {
    let gw = world().await;
    let closed_at = gw.clock.now().utc + Duration::seconds(60);
    reconcile(&gw.state, &admin(), snapshot("paid", closed_at)).await;

    let entries = gw.state.admin().list_audit(100).await.unwrap();
    let entry = entries
        .iter()
        .find(|e| e.action == "closed_records_reconciled")
        .expect("audited");
    assert_eq!(entry.actor_principal, "ops-1");
    assert_eq!(entry.payload["mismatches"], 1);
    assert!(
        !serde_json::to_string(&entry.payload)
            .unwrap()
            .contains(LOAN),
        "references are not in the audit log"
    );
    let metrics = gw.state.metrics().gather_text().unwrap();
    assert!(
        metrics.contains("kavach_snapshot_mismatches{tenant_id=\"default\"} 1"),
        "{metrics}"
    );
}

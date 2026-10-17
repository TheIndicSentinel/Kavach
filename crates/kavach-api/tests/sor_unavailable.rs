//! The signal for a fail-closed issuing path (S4): a system-of-record event
//! that Kavach cannot act on now (the clock is not synchronised) is answered
//! 503, counted by `kavach_sor_events_unavailable_total`, and never looks like
//! a refusal the sender should drop. A revocation still applies, and is not
//! counted.

mod agent_fixture;
mod contract;

use axum::http::StatusCode;
use contract::sor_router;
use kavach_api::EvidenceStoreKind;
use kavach_ports::{SyncStatus, TimeSource as _};
use serde_json::json;

use agent_fixture::*;

async fn world() -> Gw {
    gateway_on(
        config(EvidenceStoreKind::Memory, true, 50),
        Some(NUMBER),
        true,
    )
    .await
}

#[tokio::test]
async fn refused_issuing_on_an_unsynchronised_clock_is_a_503_and_is_counted() {
    let gw = world().await;
    gw.clock.set_sync(SyncStatus::Unsynced);
    let now = gw.clock.now().utc;

    let (status, body) = send(
        sor_router(gw.state.clone()),
        "/v1/sor/events",
        &[],
        json!({ "event": event_at("evt-unsynced", "lms:loan/L-9", now).await }),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");

    let metrics = gw.state.metrics().gather_text().unwrap();
    assert!(
        metrics.contains("kavach_sor_events_unavailable_total{kind=\"issuing\"} 1"),
        "{metrics}"
    );
    assert!(
        !metrics.contains("kavach_sor_events_unavailable_total{kind=\"revoking\"}"),
        "no revocation was refused: {metrics}"
    );

    // The same event once the clock is back issues: nothing was spent.
    gw.clock.set_sync(SyncStatus::Synced { max_error_ms: 10 });
    let (status, body) = send(
        sor_router(gw.state.clone()),
        "/v1/sor/events",
        &[],
        json!({ "event": event_at("evt-unsynced", "lms:loan/L-9", now).await }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
}

#[tokio::test]
async fn a_revocation_applies_on_an_unsynchronised_clock_and_is_not_counted() {
    let gw = world().await;
    gw.clock.set_sync(SyncStatus::Unsynced);
    let paid = any_event(&AnyEvent {
        event_id: "pay-unsynced",
        event_type: "loan.paid",
        tenant_id: "default",
        subject_ref: SUBJECT,
        record_ref: "lms:loan/L-1",
        consent_refs: &[],
        assigned_agent: "",
        at: gw.clock.now().utc,
        key: EventKey::Registered,
    })
    .await;
    let (status, body) = send(
        sor_router(gw.state.clone()),
        "/v1/sor/events",
        &[],
        json!({ "event": paid }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["revoked"][0], gw.mandate.as_str(), "{body}");
    let metrics = gw.state.metrics().gather_text().unwrap();
    assert!(
        !metrics.contains("kavach_sor_events_unavailable_total{kind=\"revoking\"}"),
        "{metrics}"
    );
}

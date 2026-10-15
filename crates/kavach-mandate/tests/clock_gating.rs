//! S4 (ADR-012 addendum): authority is issued and delegated only on a
//! synchronised clock; a revocation applies on any clock and is flagged.

mod common;

use common::*;
use kavach_domain::mandate::{DelegationRequest, SorEvent};
use kavach_ports::{ErrorClass, SyncStatus};

fn paid(id: &str) -> SorEvent {
    SorEvent {
        event_type: "loan.paid".into(),
        ..event(t0(), id)
    }
}

#[tokio::test]
async fn an_unsynchronised_clock_issues_no_authority() {
    let f = fixture();
    let token = sign_event(&f.sor, "lms-issuer-1", &event(f.now, "dpd-1")).await;
    for sync in [
        SyncStatus::Unsynced,
        SyncStatus::Unknown,
        SyncStatus::Synced {
            max_error_ms: 60_000,
        },
    ] {
        f.clock().set_sync(sync);
        let err = f.service.issue_from_event(&token).await.unwrap_err();
        assert_eq!(err.class, ErrorClass::Unavailable, "{sync:?}: {err}");
    }
    // Nothing was spent: once the clock is back, the same event issues.
    f.clock().set_sync(SyncStatus::Synced { max_error_ms: 10 });
    f.service
        .issue_from_event(&token)
        .await
        .expect("issued on a synchronised clock");
}

#[tokio::test]
async fn an_unsynchronised_clock_delegates_nothing() {
    let f = fixture();
    let token = sign_event(&f.sor, "lms-issuer-1", &event(f.now, "dpd-1")).await;
    let root = f.service.issue_from_event(&token).await.expect("issued");
    f.clock().set_sync(SyncStatus::Unsynced);
    let err = f
        .service
        .delegate(
            TENANT,
            &root.mandate.id,
            "collections-agent",
            "translator-agent",
            &DelegationRequest {
                actions: set(&["read_fields"]),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.class, ErrorClass::Unavailable, "{err}");
}

/// A payment still stops contact on an unsynchronised clock, and says so.
#[tokio::test]
async fn a_revocation_applies_on_an_unsynchronised_clock_and_is_flagged() {
    let f = fixture();
    let issued = f
        .service
        .issue_from_event(&sign_event(&f.sor, "lms-issuer-1", &event(f.now, "dpd-1")).await)
        .await
        .expect("issued");
    f.clock().set_sync(SyncStatus::Unsynced);
    let done = f
        .service
        .revoke_from_event(&sign_event(&f.sor, "lms-issuer-1", &paid("pay-1")).await)
        .await
        .expect("a revocation does not need a synchronised clock");
    assert_eq!(done.revoked, vec![issued.mandate.id.clone()]);
    assert_eq!(done.clock_synced, Some(false), "flagged");

    // A retry on a synchronised clock reports how it was *applied*, not
    // the clock now.
    f.clock().set_sync(SyncStatus::Synced { max_error_ms: 10 });
    let again = f
        .service
        .revoke_from_event(&sign_event(&f.sor, "lms-issuer-1", &paid("pay-1")).await)
        .await
        .unwrap();
    assert!(again.replayed);
    assert_eq!(again.clock_synced, Some(false));
}

/// An unsynchronised clock that is also *behind* must not make a genuine
/// payment look like it is from the future (it would be refused and
/// contact would continue): it is applied and flagged.
#[tokio::test]
async fn a_revocation_on_a_clock_that_is_behind_is_applied() {
    let f = fixture();
    let issued = f
        .service
        .issue_from_event(&sign_event(&f.sor, "lms-issuer-1", &event(f.now, "dpd-1")).await)
        .await
        .expect("issued");
    // This stack's clock says t0, but the payment really occurred ten
    // minutes later: the clock is ten minutes behind and not synchronised.
    f.clock().set_sync(SyncStatus::Unsynced);
    let late_by_the_clock = SorEvent {
        event_type: "loan.paid".into(),
        ..event(f.now + chrono::Duration::minutes(10), "pay-skew")
    };
    let done = f
        .service
        .revoke_from_event(&sign_event(&f.sor, "lms-issuer-1", &late_by_the_clock).await)
        .await
        .expect("applied, not refused as future-dated");
    assert_eq!(done.revoked, vec![issued.mandate.id.clone()]);
    assert_eq!(done.clock_synced, Some(false));

    // On a synchronised clock the same event is accepted as well: a
    // revocation is not refused for being dated ahead (B2 clamps it).
    f.clock().set_sync(SyncStatus::Synced { max_error_ms: 10 });
    let again = SorEvent {
        event_id: "pay-skew-2".into(),
        ..late_by_the_clock
    };
    let done = f
        .service
        .revoke_from_event(&sign_event(&f.sor, "lms-issuer-1", &again).await)
        .await
        .expect("accepted");
    assert_eq!(done.clock_synced, Some(true));
}

/// The bar: 500 ms of clock error issues, 501 does not; a development
/// clock (`DevFixed`) issues and delegates.
#[tokio::test]
async fn the_clock_error_bar_and_the_development_clock() {
    let f = fixture();
    let token = sign_event(&f.sor, "lms-issuer-1", &event(f.now, "dpd-1")).await;
    f.clock().set_sync(SyncStatus::Synced { max_error_ms: 501 });
    assert_eq!(
        f.service.issue_from_event(&token).await.unwrap_err().class,
        ErrorClass::Unavailable
    );
    f.clock().set_sync(SyncStatus::Synced { max_error_ms: 500 });
    let root = f
        .service
        .issue_from_event(&token)
        .await
        .expect("500 issues");

    f.clock().set_sync(SyncStatus::DevFixed);
    f.service
        .delegate(
            TENANT,
            &root.mandate.id,
            "collections-agent",
            "translator-agent",
            &DelegationRequest {
                actions: set(&["read_fields"]),
                ..Default::default()
            },
        )
        .await
        .expect("a development clock delegates");
    let again = sign_event(&f.sor, "lms-issuer-1", &event(f.now, "dpd-2")).await;
    f.service
        .issue_from_event(&again)
        .await
        .expect("a development clock issues");
}

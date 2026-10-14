//! B1 (ADR-012 addendum): a revoking event has no maximum age, and its
//! single use is the permanent stored revocation, not the replay guard
//! (which expires).

mod common;

use chrono::{DateTime, Duration, Utc};
use common::*;
use kavach_domain::mandate::SorEvent;
use kavach_ports::ErrorClass;

fn at(when: DateTime<Utc>, id: &str, kind: &str) -> SorEvent {
    SorEvent {
        event_type: kind.into(),
        ..event(when, id)
    }
}

async fn sign(f: &Fixture, e: &SorEvent) -> String {
    sign_event(&f.sor, "lms-issuer-1", e).await
}

/// An issuing event is still fresh-only: a default found in an old backlog
/// does not make a mandate.
#[tokio::test]
async fn an_old_issuing_event_is_still_refused() {
    let f = fixture();
    f.clock().advance(Duration::minutes(11));
    let err = f
        .service
        .issue_from_event(&sign(&f, &event(f.now, "dpd-old")).await)
        .await
        .unwrap_err();
    assert_eq!(err.class, ErrorClass::Rejected);
}

/// A payment days old revokes the mandate that existed when it occurred,
/// and leaves one issued after it.
#[tokio::test]
async fn an_old_payment_revokes_the_older_mandate_and_leaves_the_newer() {
    let f = fixture();
    let older = f
        .service
        .issue_from_event(&sign(&f, &event(f.now, "dpd-1")).await)
        .await
        .expect("issued");
    f.clock().advance(Duration::days(2));
    let newer = f
        .service
        .issue_from_event(&sign(&f, &event(f.now + Duration::days(2), "dpd-2")).await)
        .await
        .expect("a new default is a new mandate");
    f.clock().advance(Duration::days(3));
    let paid = at(f.now + Duration::seconds(30), "pay-old", "loan.paid");
    let done = f
        .service
        .revoke_from_event(&sign(&f, &paid).await)
        .await
        .expect("a payment five days late is accepted");
    assert_eq!(done.revoked, vec![older.mandate.id.clone()]);
    assert!(f.service.verify_active(&newer.token).await.is_ok());
}

/// The replay guard expires after 24 h; the stored revocation does not. A
/// repeat 25 h later is answered from the stored row and changes nothing,
/// including a mandate issued after the first processing whose `nbf` is
/// still at or before the payment's `occurred_at` (the future-skew gap).
#[tokio::test]
async fn a_repeat_after_the_guard_expired_revokes_nothing() {
    let f = fixture();
    // The payment occurred 200 s ahead of this stack's clock (inside the
    // skew bound) and finds nothing to revoke.
    let paid = at(f.now + Duration::seconds(200), "pay-1", "loan.paid");
    let token = sign(&f, &paid).await;
    let first = f.service.revoke_from_event(&token).await.expect("first");
    assert!(first.revoked.is_empty() && !first.replayed);

    // A default is then processed; its mandate's nbf is before the payment's
    // occurred_at.
    let issued = f
        .service
        .issue_from_event(&sign(&f, &event(f.now, "dpd-1")).await)
        .await
        .expect("issued");

    f.clock().advance(Duration::hours(25));
    let again = f
        .service
        .revoke_from_event(&token)
        .await
        .expect("the same event again");
    assert!(again.replayed, "answered from the stored revocation");
    assert!(again.revoked.is_empty(), "and it revokes nothing now");
    assert!(f.service.verify_active(&issued.token).await.is_ok());
}

/// The same event id with other content is refused after the guard expired.
#[tokio::test]
async fn the_same_id_with_other_content_is_refused_after_the_guard_expired() {
    let f = fixture();
    let paid = at(f.now, "pay-1", "loan.paid");
    f.service
        .revoke_from_event(&sign(&f, &paid).await)
        .await
        .expect("first");
    f.clock().advance(Duration::hours(25));
    let other = SorEvent {
        record_ref: "lms:loan/L-9999".into(),
        ..paid
    };
    let err = f
        .service
        .revoke_from_event(&sign(&f, &other).await)
        .await
        .unwrap_err();
    assert_eq!(err.class, ErrorClass::Rejected);
    assert!(err.message.contains("different content"), "{err}");
}

//! B2 (ADR-012 addendum): a revocation is scoped by when the source says
//! things happened, a recorded payment closes the record to events that
//! occurred before it (whichever arrived first), a dispute holds the record,
//! and a payment dated ahead cannot hold a record closed for long.

mod common;

use chrono::{DateTime, Duration, Utc};
use common::*;
use kavach_domain::mandate::SorEvent;
use kavach_ports::{ErrorClass, TimeSource};

fn at(when: DateTime<Utc>, id: &str, kind: &str) -> SorEvent {
    SorEvent {
        event_type: kind.into(),
        ..event(when, id)
    }
}

async fn sign(f: &Fixture, e: &SorEvent) -> String {
    sign_event(&f.sor, "lms-issuer-1", e).await
}

/// A payment occurring within the skew margin after a default is not
/// provably later: contact stops (the default's mandate is revoked).
#[tokio::test]
async fn an_event_within_the_skew_margin_is_treated_as_not_later() {
    let f = fixture();
    let issued = f
        .service
        .issue_from_event(&sign(&f, &event(f.now, "dpd-1")).await)
        .await
        .expect("issued");
    // The payment occurred 10 s *before* the default (inside the 30 s
    // margin): the order is in doubt, so the mandate is revoked.
    let paid = at(f.now - Duration::seconds(10), "pay-1", "loan.paid");
    let done = f
        .service
        .revoke_from_event(&sign(&f, &paid).await)
        .await
        .expect("revoked");
    assert_eq!(done.revoked, vec![issued.mandate.id.clone()]);
}

/// Beyond the margin the default is provably later and stays.
#[tokio::test]
async fn a_default_provably_after_the_payment_is_a_new_default() {
    let f = fixture();
    let issued = f
        .service
        .issue_from_event(&sign(&f, &event(f.now, "dpd-1")).await)
        .await
        .expect("issued");
    let paid = at(f.now - Duration::seconds(120), "pay-1", "loan.paid");
    let done = f
        .service
        .revoke_from_event(&sign(&f, &paid).await)
        .await
        .expect("accepted");
    assert!(done.revoked.is_empty());
    assert!(f.service.verify_active(&issued.token).await.is_ok());
}

/// The barrier: a default recorded as occurring before the payment is
/// refused when it arrives afterwards, and one provably after is issued.
#[tokio::test]
async fn a_recorded_payment_closes_the_record_to_earlier_events() {
    let f = fixture();
    f.service
        .revoke_from_event(&sign(&f, &at(f.now, "pay-1", "loan.paid")).await)
        .await
        .expect("recorded");

    // Occurred before the payment, and inside its margin after it.
    for (id, offset) in [("dpd-before", -60), ("dpd-within", 20)] {
        let err = f
            .service
            .issue_from_event(
                &sign(&f, &at(f.now + Duration::seconds(offset), id, "loan.dpd30")).await,
            )
            .await
            .unwrap_err();
        assert_eq!(err.class, ErrorClass::Rejected, "{id}: {err}");
    }
    // Provably after (past the 30 s margin, within the 60 s future bound).
    f.service
        .issue_from_event(
            &sign(
                &f,
                &at(f.now + Duration::seconds(50), "dpd-after", "loan.dpd30"),
            )
            .await,
        )
        .await
        .expect("a new default after the payment is issued");
}

/// A payment dated far ahead is clamped to receipt plus the allowance: it
/// closes the record for at most five minutes, not for an hour.
#[tokio::test]
async fn a_payment_dated_ahead_holds_the_record_closed_only_briefly() {
    let f = fixture();
    f.service
        .revoke_from_event(
            &sign(
                &f,
                &at(f.now + Duration::hours(1), "pay-ahead", "loan.paid"),
            )
            .await,
        )
        .await
        .expect("accepted");
    // Ten minutes later a default occurs: not before the clamped barrier.
    f.clock().advance(Duration::minutes(10));
    f.service
        .issue_from_event(
            &sign(
                &f,
                &at(f.now + Duration::minutes(10), "dpd-later", "loan.dpd30"),
            )
            .await,
        )
        .await
        .expect("issued: the barrier was receipt + 5 minutes, not an hour");
}

/// A dispute holds the record whatever the time; a payment does not
/// release it.
#[tokio::test]
async fn a_dispute_holds_the_record_and_a_payment_does_not_release_it() {
    let f = fixture();
    let issued = f
        .service
        .issue_from_event(&sign(&f, &event(f.now, "dpd-1")).await)
        .await
        .expect("issued");
    let done = f
        .service
        .revoke_from_event(
            &sign(
                &f,
                &at(f.now + Duration::seconds(5), "dis-1", "loan.disputed"),
            )
            .await,
        )
        .await
        .expect("revoked");
    assert_eq!(done.revoked, vec![issued.mandate.id.clone()]);

    // A default a day later is held, not issued.
    f.clock().advance(Duration::days(1));
    let later = at(f.clock().now().utc, "dpd-2", "loan.dpd30");
    let err = f
        .service
        .issue_from_event(&sign(&f, &later).await)
        .await
        .unwrap_err();
    assert_eq!(err.class, ErrorClass::Rejected);
    assert!(err.message.contains("held after a dispute"), "{err}");

    // A payment is recorded and revokes; it does not release the hold.
    f.service
        .revoke_from_event(&sign(&f, &at(f.clock().now().utc, "pay-1", "loan.paid")).await)
        .await
        .expect("recorded");
    f.clock().advance(Duration::days(1));
    let err = f
        .service
        .issue_from_event(&sign(&f, &at(f.clock().now().utc, "dpd-3", "loan.dpd30")).await)
        .await
        .unwrap_err();
    assert!(err.message.contains("held after a dispute"), "{err}");
}

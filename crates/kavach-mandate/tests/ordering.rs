//! Reproductions of B1 and B2 (the late revocation and the event-order
//! findings of the execution plan). Each test states the behaviour the
//! decisions D1 and D2 require; before the fix they fail, which is the
//! reproduction.

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

/// B1: the loan defaults at t0 and a mandate is issued; the payment occurs
/// a minute later but its event reaches Kavach ten minutes after that.
#[tokio::test]
async fn b1_a_payment_event_delivered_late_still_revokes() {
    let f = fixture();
    let issued = f
        .service
        .issue_from_event(&sign(&f, &event(f.now, "dpd-1")).await)
        .await
        .expect("issued");

    f.clock().advance(Duration::minutes(11));
    let paid = at(f.now + Duration::minutes(1), "pay-1", "loan.paid");
    let done = f
        .service
        .revoke_from_event(&sign(&f, &paid).await)
        .await
        .expect("a late revocation is accepted (D1)");
    assert_eq!(done.revoked, vec![issued.mandate.id.clone()]);
}

/// B1, the bounds (decision A1): a revocation has no maximum age, so a
/// payment found in a backlog a day later still stops contact; an event
/// from the future is still refused.
#[tokio::test]
async fn b1_a_revocation_has_no_maximum_age_but_not_from_the_future() {
    let f = fixture();
    let issued = f
        .service
        .issue_from_event(&sign(&f, &event(f.now, "dpd-1")).await)
        .await
        .expect("issued");
    f.clock().advance(Duration::hours(25));
    let old = at(f.now + Duration::seconds(30), "pay-old", "loan.paid");
    let done = f
        .service
        .revoke_from_event(&sign(&f, &old).await)
        .await
        .expect("an old payment still revokes");
    assert_eq!(done.revoked, vec![issued.mandate.id.clone()]);

    let future = at(
        f.now + Duration::hours(25) + Duration::minutes(10),
        "pay-future",
        "loan.paid",
    );
    let err = f
        .service
        .revoke_from_event(&sign(&f, &future).await)
        .await
        .unwrap_err();
    assert_eq!(err.class, ErrorClass::Rejected);
}

/// B2, arrival order 1: the payment event arrives first and finds no
/// mandate; the default it follows arrives afterwards.
#[tokio::test]
#[ignore = "B2 (scope by source time, per-record barrier): fails until that change lands"]
async fn b2_a_default_that_arrives_after_the_payment_issues_nothing() {
    let f = fixture();
    let paid = at(f.now, "pay-1", "loan.paid");
    let done = f
        .service
        .revoke_from_event(&sign(&f, &paid).await)
        .await
        .expect("a payment with nothing to revoke is recorded");
    assert!(done.revoked.is_empty());

    f.clock().advance(Duration::seconds(10));
    let default = at(f.now - Duration::seconds(60), "dpd-1", "loan.dpd30");
    let err = f
        .service
        .issue_from_event(&sign(&f, &default).await)
        .await
        .expect_err("a default that occurred before a recorded payment issues nothing (D2)");
    assert_eq!(err.class, ErrorClass::Rejected);
}

/// B2, arrival order 2: the default is processed first, but only after the
/// payment already occurred (within the 300 s freshness window); the
/// payment event then arrives.
#[tokio::test]
#[ignore = "B2 (scope by source time, per-record barrier): fails until that change lands"]
async fn b2_a_payment_that_occurred_before_the_default_was_processed_still_revokes() {
    let f = fixture();
    // The default occurred at t0 and is processed two minutes later.
    let default = at(f.now, "dpd-1", "loan.dpd30");
    f.clock().advance(Duration::seconds(120));
    let issued = f
        .service
        .issue_from_event(&sign(&f, &default).await)
        .await
        .expect("issued");

    // The payment occurred a minute after the default, before it was
    // processed; its event arrives now.
    f.clock().advance(Duration::seconds(10));
    let paid = at(f.now + Duration::seconds(60), "pay-1", "loan.paid");
    let done = f
        .service
        .revoke_from_event(&sign(&f, &paid).await)
        .await
        .expect("revocation");
    assert_eq!(
        done.revoked,
        vec![issued.mandate.id.clone()],
        "the mandate came from a default that occurred before the payment"
    );
}

/// The control that must keep holding: a new default after the payment
/// gets a mandate of its own, and a later copy of the old payment event
/// does not revoke it.
#[tokio::test]
async fn control_a_default_after_the_payment_is_a_new_default() {
    let f = fixture();
    let first = f
        .service
        .issue_from_event(&sign(&f, &event(f.now, "dpd-1")).await)
        .await
        .expect("issued");
    f.clock().advance(Duration::seconds(30));
    let paid = at(f.now + Duration::seconds(20), "pay-1", "loan.paid");
    let done = f
        .service
        .revoke_from_event(&sign(&f, &paid).await)
        .await
        .expect("revoked");
    assert_eq!(done.revoked, vec![first.mandate.id.clone()]);

    f.clock().advance(Duration::minutes(20));
    let again = f
        .service
        .issue_from_event(
            &sign(
                &f,
                &at(
                    f.now + Duration::seconds(30) + Duration::minutes(20),
                    "dpd-2",
                    "loan.dpd30",
                ),
            )
            .await,
        )
        .await
        .expect("a new default after the payment is issued");
    assert_ne!(again.mandate.id, first.mandate.id);

    // The first payment event again returns its stored result and revokes
    // nothing now.
    let retry = f
        .service
        .existing_revocation(&sign(&f, &paid).await)
        .await
        .unwrap()
        .expect("stored");
    assert!(retry.replayed);
    assert!(f.service.verify_active(&again.token).await.is_ok());
}

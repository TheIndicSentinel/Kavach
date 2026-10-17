//! Snapshot reconciliation: the lender's closed loans against the live
//! authority Kavach holds. Reports only; revokes nothing.

mod common;

use chrono::Duration;
use common::*;
use kavach_domain::mandate::SorEvent;
use kavach_mandate::{ClosedRecord, ClosedState, FindingKind};
use kavach_ports::MandateStore as _;

const LOAN: &str = "lms:loan/L-4471";

fn closed(state: ClosedState, at: chrono::DateTime<chrono::Utc>) -> ClosedRecord {
    ClosedRecord {
        system: "lms".into(),
        record_ref: LOAN.into(),
        state,
        closed_at: at,
    }
}

async fn issue(f: &Fixture, id: &str) -> String {
    let token = sign_event(&f.sor, "lms-issuer-1", &event(f.now, id)).await;
    f.service
        .issue_from_event(&token)
        .await
        .expect("issued")
        .mandate
        .id
}

/// The case the feature exists for: the payment event never arrived, so the
/// mandate is live although the lender says the loan is paid.
#[tokio::test]
async fn a_lost_payment_leaves_authority_the_snapshot_finds() {
    let f = fixture();
    let id = issue(&f, "dpd-1").await;
    let report = f
        .service
        .reconcile_closed(
            TENANT,
            &[closed(ClosedState::Paid, f.now + Duration::seconds(60))],
        )
        .await
        .expect("reconciled");
    assert_eq!(report.checked, 1);
    assert_eq!(report.mismatches(), 1);
    let finding = &report.findings[0];
    assert_eq!(finding.kind, FindingKind::ShouldHaveBeenRevoked);
    assert_eq!(finding.mandate_id, id);
    assert_eq!(finding.record_ref, LOAN);
}

/// It reports and does nothing else: the mandate is still live afterwards;
/// and once the payment event does arrive, the snapshot is clean.
#[tokio::test]
async fn it_revokes_nothing_and_is_clean_once_the_event_arrives() {
    let f = fixture();
    let id = issue(&f, "dpd-1").await;
    let snapshot = [closed(ClosedState::Paid, f.now + Duration::seconds(60))];
    f.service.reconcile_closed(TENANT, &snapshot).await.unwrap();
    let token = f
        .service
        .store()
        .get(TENANT, &id)
        .await
        .unwrap()
        .unwrap()
        .token;
    assert!(
        f.service.verify_active(&token).await.is_ok(),
        "not revoked by it"
    );

    let paid = SorEvent {
        event_type: "loan.paid".into(),
        ..event(f.now + Duration::seconds(60), "pay-1")
    };
    f.service
        .revoke_from_event(&sign_event(&f.sor, "lms-issuer-1", &paid).await)
        .await
        .expect("the resent event");
    let report = f.service.reconcile_closed(TENANT, &snapshot).await.unwrap();
    assert!(report.findings.is_empty(), "{report:?}");
}

/// A mandate processed after the closure is reported for confirmation, not
/// as a defect: usually a new default.
#[tokio::test]
async fn a_mandate_issued_after_the_closure_is_information() {
    let f = fixture();
    let id = issue(&f, "dpd-1").await;
    // The lender says the loan was paid two minutes before the default.
    let report = f
        .service
        .reconcile_closed(
            TENANT,
            &[closed(ClosedState::Paid, f.now - Duration::seconds(120))],
        )
        .await
        .unwrap();
    assert_eq!(report.mismatches(), 0);
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].kind, FindingKind::IssuedAfterClosure);
    assert_eq!(report.findings[0].mandate_id, id);
}

/// A dispute holds the loan: any live mandate for it is a defect, whenever
/// it was issued.
#[tokio::test]
async fn any_live_mandate_for_a_disputed_loan_is_a_mismatch() {
    let f = fixture();
    issue(&f, "dpd-1").await;
    let report = f
        .service
        .reconcile_closed(
            TENANT,
            &[closed(ClosedState::Disputed, f.now - Duration::hours(1))],
        )
        .await
        .unwrap();
    assert_eq!(report.mismatches(), 1);
}

/// Expired mandates, revoked mandates and loans Kavach holds nothing for are
/// not findings.
#[tokio::test]
async fn expired_revoked_and_unknown_loans_are_clean() {
    let f = fixture();
    issue(&f, "dpd-1").await;
    // Past the template's seven days: expired, though still `Active` in the
    // store.
    f.clock().advance(Duration::days(8));
    let report = f
        .service
        .reconcile_closed(
            TENANT,
            &[
                closed(ClosedState::Paid, f.now + Duration::seconds(60)),
                ClosedRecord {
                    record_ref: "lms:loan/L-NONE".into(),
                    ..closed(ClosedState::Disputed, f.now)
                },
            ],
        )
        .await
        .unwrap();
    assert_eq!(report.checked, 2);
    assert!(report.findings.is_empty(), "{report:?}");
}

/// The tenant is part of the question: another tenant's snapshot finds
/// nothing of this tenant's.
#[tokio::test]
async fn another_tenants_snapshot_finds_nothing() {
    let f = fixture();
    issue(&f, "dpd-1").await;
    let report = f
        .service
        .reconcile_closed(
            "another-tenant",
            &[closed(ClosedState::Paid, f.now + Duration::seconds(60))],
        )
        .await
        .unwrap();
    assert!(report.findings.is_empty());
}

/// The case a lost payment makes dangerous: a default that occurred *before*
/// the payment but was processed *after* it. Revocation scopes by source
/// time (B2), so the payment's event would have revoked it; reconciliation
/// uses the same rule and must report it as a mismatch, not as information.
#[tokio::test]
async fn a_default_processed_late_is_found_by_its_source_time() {
    let f = fixture();
    // The default occurred at t0; Kavach processed it two minutes later.
    let token = sign_event(&f.sor, "lms-issuer-1", &event(f.now, "dpd-late")).await;
    f.clock().advance(Duration::seconds(120));
    let id = f
        .service
        .issue_from_event(&token)
        .await
        .expect("issued")
        .mandate
        .id;
    // The lender says the loan was paid at t0 + 60 s, after the default
    // occurred and before it was processed (`nbf` is t0 + 120 s).
    let report = f
        .service
        .reconcile_closed(
            TENANT,
            &[closed(ClosedState::Paid, f.now + Duration::seconds(60))],
        )
        .await
        .unwrap();
    assert_eq!(report.mismatches(), 1, "{report:?}");
    assert_eq!(report.findings[0].kind, FindingKind::ShouldHaveBeenRevoked);
    assert_eq!(report.findings[0].mandate_id, id);

    // The payment's event, had it arrived, revokes exactly this mandate: the
    // two rules agree.
    let paid = SorEvent {
        event_type: "loan.paid".into(),
        ..event(f.now + Duration::seconds(60), "pay-1")
    };
    let done = f
        .service
        .revoke_from_event(&sign_event(&f.sor, "lms-issuer-1", &paid).await)
        .await
        .unwrap();
    assert_eq!(done.revoked, vec![id]);
}

/// The boundary is the same on both sides of the rule: a root whose scope time
/// is exactly the margin after the closure is a mismatch (the revocation
/// reaches it), one second later it is not.
#[tokio::test]
async fn the_boundary_is_the_margin_for_a_root_with_a_source_time() {
    let f = fixture();
    issue(&f, "dpd-1").await; // source time f.now, kept with the root
    for (closed_before, expect) in [
        (30, FindingKind::ShouldHaveBeenRevoked), // scope time == closed_at + 30 s
        (31, FindingKind::IssuedAfterClosure),    // one second past it
    ] {
        let report = f
            .service
            .reconcile_closed(
                TENANT,
                &[closed(
                    ClosedState::Paid,
                    f.now - Duration::seconds(closed_before),
                )],
            )
            .await
            .unwrap();
        assert_eq!(report.findings.len(), 1, "{closed_before}: {report:?}");
        assert_eq!(report.findings[0].kind, expect, "{closed_before}");
    }
}

/// A root written before the source time was kept (plain `insert`) is scoped
/// by `nbf`, at the same boundary.
#[tokio::test]
async fn the_boundary_is_the_margin_for_an_older_row_without_a_source_time() {
    let f = fixture();
    let mut old = kavach_ports_testkit::mandate_store::sample("old-row", None, 0);
    old.mandate.tenant_id = TENANT.into();
    old.mandate.source.system = "lms".into();
    old.mandate.source.record_ref = LOAN.into();
    old.mandate.nbf = f.now;
    old.mandate.exp = f.now + Duration::days(7);
    f.service.store().insert(old).await.expect("an older row");
    for (closed_before, expect) in [
        (30, FindingKind::ShouldHaveBeenRevoked),
        (31, FindingKind::IssuedAfterClosure),
    ] {
        let report = f
            .service
            .reconcile_closed(
                TENANT,
                &[closed(
                    ClosedState::Paid,
                    f.now - Duration::seconds(closed_before),
                )],
            )
            .await
            .unwrap();
        assert_eq!(report.findings.len(), 1, "{closed_before}: {report:?}");
        assert_eq!(report.findings[0].kind, expect, "{closed_before}");
    }
}

/// A dispute flags any live mandate whatever the times: before, at or long
/// after the mandate was issued.
#[tokio::test]
async fn a_disputed_loan_flags_a_live_mandate_at_any_time() {
    let f = fixture();
    issue(&f, "dpd-1").await;
    for offset in [-86_400, -31, 0, 31, 86_400] {
        let report = f
            .service
            .reconcile_closed(
                TENANT,
                &[closed(
                    ClosedState::Disputed,
                    f.now + Duration::seconds(offset),
                )],
            )
            .await
            .unwrap();
        assert_eq!(report.mismatches(), 1, "closed at {offset} s");
    }
}

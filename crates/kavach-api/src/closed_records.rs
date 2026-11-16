//! `POST /v1/reconciliation/closed-records`: snapshot reconciliation
//! (ADR-012 addendum). The lender lists the loans it considers closed; Kavach
//! answers with the live authority it still holds for them.
//!
//! It **reports and revokes nothing**. A mandate that outlived its payment
//! means a payment or dispute event never arrived; the remedy is the lender
//! resending the signed event (which revokes through the normal path) or an
//! operator stopping the agent. The request names loans by their reference
//! only; nothing about the borrower is sent or returned.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Utc};
use kavach_auth::KavachAction;
use kavach_mandate::{ClosedRecord, ClosedState, FindingKind};
use kavach_storage::AuditInsert;
use serde::Deserialize;
use serde_json::json;

use crate::auth::{authorize_credentials, resolve_credentials, Credentials};
use crate::state::AppState;
use crate::strict_json::StrictJson;

/// Most loans in one request.
const MAX_RECORDS: usize = 1000;
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Body {
    /// The system of record the references belong to (`lms`).
    system: String,
    records: Vec<ClosedLoan>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClosedLoan {
    record_ref: String,
    state: Closed,
    /// When the lender says the loan was paid or the dispute was raised.
    closed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Closed {
    Paid,
    Disputed,
}

fn refuse(status: StatusCode, detail: &str) -> Response {
    crate::problem::Problem::for_status(status, detail).into_response()
}

fn plain(s: &str, max: usize) -> bool {
    (1..=max).contains(&s.len()) && s.chars().all(|c| !c.is_control())
}

/// The request as the library's records, or why it is refused. Cheap checks
/// only: a refused body costs no reads and no rate-limit token.
fn validated(body: &Body) -> Result<Vec<ClosedRecord>, Box<Response>> {
    if !plain(&body.system, 64) || !(1..=MAX_RECORDS).contains(&body.records.len()) {
        return Err(Box::new(refuse(
            StatusCode::BAD_REQUEST,
            "system must be 1-64 plain characters and records 1-1000 entries",
        )));
    }
    if body.records.iter().any(|r| !plain(&r.record_ref, 256)) {
        return Err(Box::new(refuse(
            StatusCode::BAD_REQUEST,
            "each record_ref must be 1-256 plain characters",
        )));
    }
    Ok(body
        .records
        .iter()
        .map(|r| ClosedRecord {
            system: body.system.clone(),
            record_ref: r.record_ref.clone(),
            state: match r.state {
                Closed::Paid => ClosedState::Paid,
                Closed::Disputed => ClosedState::Disputed,
            },
            closed_at: r.closed_at,
        })
        .collect())
}

/// One finding as the API returns it.
fn finding_json(f: &kavach_mandate::Finding) -> serde_json::Value {
    json!({
        "kind": match f.kind {
            FindingKind::ShouldHaveBeenRevoked => "should_have_been_revoked",
            FindingKind::IssuedAfterClosure => "issued_after_closure",
        },
        "record_ref": f.record_ref,
        "state": match f.state {
            ClosedState::Paid => "paid",
            ClosedState::Disputed => "disputed",
        },
        "mandate_id": f.mandate_id,
        "holder": f.holder,
        "issued_at": f.issued_at,
        "expires_at": f.expires_at,
    })
}

pub async fn reconcile_closed_records(
    State(state): State<Arc<AppState>>,
    credentials: Credentials,
    StrictJson(body): StrictJson<Body>,
) -> Response {
    let decision =
        match authorize_credentials(&state, &credentials, KavachAction::ReconcileClosedRecords)
            .await
        {
            Ok(decision) => decision,
            Err(err) => return err.into_response(),
        };
    let Some(dp) = state.dataplane() else {
        return refuse(StatusCode::NOT_FOUND, "agent surfaces are not configured");
    };
    let closed = match validated(&body) {
        Ok(closed) => closed,
        Err(refusal) => return *refusal,
    };
    if !dp.admit_reconcile() {
        return refuse(StatusCode::TOO_MANY_REQUESTS, "too many reconciliations");
    }
    let core = dp.core();
    let report = match dp
        .mandates()
        .reconcile_closed(core.tenant_id(), &closed)
        .await
    {
        Ok(report) => report,
        Err(err) => {
            tracing::error!(error = %err, "snapshot reconciliation could not read the mandates");
            return refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "the mandate store is unavailable",
            );
        }
    };
    let mismatches = report.mismatches();
    let information = report.findings.len() - mismatches;
    state
        .metrics()
        .observe_snapshot_reconciliation(i64::try_from(mismatches).unwrap_or(i64::MAX));
    if mismatches > 0 {
        tracing::error!(
            mismatches,
            "ALERT closed loans with live authority: a payment or dispute event was likely lost"
        );
    }
    let who = resolve_credentials(&state, &credentials).map_or_else(
        |_| "unauthenticated (access control off)".to_string(),
        |p| p.id,
    );
    if let Err(err) = state
        .admin()
        .append_audit(AuditInsert {
            acting_as_superadmin: decision.acting_as_superadmin,
            action: "closed_records_reconciled".into(),
            resource_type: "reconciliation".into(),
            resource_id: body.system.clone(),
            actor_principal: who,
            approver_principal: String::new(),
            payload: json!({
                "checked": report.checked,
                "mismatches": mismatches,
                "information": information,
            }),
        })
        .await
    {
        tracing::error!(error = %err, "a reconciliation could not be audited");
    }
    Json(json!({
        "checked": report.checked,
        "mismatches": mismatches,
        "information": information,
        "findings": report.findings.iter().map(finding_json).collect::<Vec<_>>(),
        "remedy": "a mismatch means a payment or dispute event did not arrive: resend the signed event (it revokes through the normal path) or stop the agent. This call changed nothing.",
    }))
    .into_response()
}

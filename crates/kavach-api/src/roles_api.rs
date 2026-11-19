//! ADR-019 §8 and §9: who has signed in, who holds which role, the access
//! review, and the caller's own roles.
//!
//! - `GET /v1/principals?q=&limit=&cursor=` (`read_principals`): the
//!   tenant's directory, by issuer then subject.
//! - `GET /v1/role-bindings?include=ended` (`read_principals`): bindings,
//!   active only unless asked.
//! - `GET /v1/access-review?format=json|csv` (`read_access_review`): one row
//!   per active binding, with who granted it and when its person was last
//!   seen; every export writes an audit row, and one that cannot be audited
//!   is refused.
//! - `GET /v1/me`: the caller and the roles bound to them now. It helps the
//!   console show the right pages; the server still decides every request.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::http::{header, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use kavach_auth::KavachAction;
use kavach_storage::{AuditInsert, PrincipalRecord, RoleBinding, SubjectKind, BOOTSTRAP_ACTOR};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::auth::{authorize_credentials, bound_roles, resolve_credentials, Credentials};
use crate::error::ApiError;
use crate::state::AppState;

const DEFAULT_PAGE: u32 = 50;
const MAX_PAGE: u32 = 200;
/// The longest `?q=` accepted.
const MAX_QUERY_CHARS: usize = 200;

/// The groups the policy still honours as aliases (ADR-019 §2). Their
/// membership is in the IdP, so the access review names them but cannot
/// list their members.
pub const ALIAS_GROUPS: [&str; 4] = ["admins", "change-approvers", "operators", "viewers"];

/// The audit action of an access-review export.
pub const ACCESS_REVIEW_AUDIT_ACTION: &str = "export_access_review";

/// A refused query string. The rejection's own text can echo the query, so
/// the answer says only what is accepted.
fn bad_query(takes: &str) -> ApiError {
    ApiError::BadRequest(format!("the query takes {takes}"))
}

fn unavailable(what: &str) -> impl FnOnce(kavach_storage::RoleStoreError) -> ApiError + '_ {
    move |_| ApiError::Unavailable(format!("{what} could not be read"))
}

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

// ---- GET /v1/principals ----

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalsQuery {
    q: Option<String>,
    limit: Option<u32>,
    cursor: Option<String>,
}

/// A page cursor: the last `(issuer, subject)` of the previous page,
/// encoded so it carries no separator a subject could contain.
fn encode_cursor(issuer: &str, subject: &str) -> String {
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(&[issuer, subject]).unwrap_or_default())
}

fn decode_cursor(cursor: &str) -> Option<(String, String)> {
    let bytes = URL_SAFE_NO_PAD.decode(cursor).ok()?;
    let [issuer, subject]: [String; 2] = serde_json::from_slice(&bytes).ok()?;
    Some((issuer, subject))
}

fn matches(record: &PrincipalRecord, needle: &str) -> bool {
    record.display_name.to_lowercase().contains(needle)
        || record.subject.to_lowercase().contains(needle)
}

fn principal_json(record: &PrincipalRecord) -> Value {
    json!({
        "issuer": record.issuer,
        "subject": record.subject,
        "display_name": record.display_name,
        "first_seen_at": record.first_seen_at,
        "last_seen_at": record.last_seen_at,
    })
}

/// One page of `records` (sorted by issuer, then subject): those after
/// `after` that match `needle`, and the cursor for the next page when more
/// may follow.
fn principals_page<'a>(
    records: &'a [PrincipalRecord],
    needle: Option<&str>,
    after: Option<&(String, String)>,
    size: usize,
) -> (Vec<&'a PrincipalRecord>, Option<String>) {
    let mut matching = records
        .iter()
        .filter(|r| after.is_none_or(|(i, s)| (r.issuer.as_str(), r.subject.as_str()) > (i, s)))
        .filter(|r| needle.is_none_or(|n| matches(r, n)));
    let page: Vec<&PrincipalRecord> = matching.by_ref().take(size).collect();
    let next = match (matching.next(), page.last()) {
        (Some(_), Some(last)) => Some(encode_cursor(&last.issuer, &last.subject)),
        _ => None,
    };
    (page, next)
}

pub async fn list_principals(
    State(state): State<Arc<AppState>>,
    credentials: Credentials,
    query: Result<Query<PrincipalsQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    authorize_credentials(&state, &credentials, KavachAction::ReadPrincipals).await?;
    let Query(query) = query.map_err(|_| bad_query("q, limit (an integer) and cursor"))?;
    let needle = match query.q.as_deref().map(str::trim) {
        Some(q) if q.chars().count() > MAX_QUERY_CHARS => {
            return Err(ApiError::BadRequest(format!(
                "q is at most {MAX_QUERY_CHARS} characters"
            )))
        }
        Some(q) if q.chars().any(char::is_control) => {
            return Err(ApiError::BadRequest("q has a control character".into()))
        }
        Some("") | None => None,
        Some(q) => Some(q.to_lowercase()),
    };
    let after = match query.cursor.as_deref() {
        None => None,
        Some(cursor) => Some(decode_cursor(cursor).ok_or_else(|| {
            ApiError::BadRequest("cursor must be a next_cursor from a previous page".into())
        })?),
    };
    let size = query.limit.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_PAGE) as usize;
    let mut records = state
        .roles()
        .list_principals(state.tenant_id())
        .await
        .map_err(unavailable("the principals directory"))?;
    records.sort_by(|a, b| (&a.issuer, &a.subject).cmp(&(&b.issuer, &b.subject)));
    let (page, next) = principals_page(&records, needle.as_deref(), after.as_ref(), size);
    let items: Vec<Value> = page.into_iter().map(principal_json).collect();
    Ok(no_store(
        Json(json!({ "items": items, "next_cursor": next })).into_response(),
    ))
}

// ---- GET /v1/role-bindings ----

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingsQuery {
    include: Option<String>,
}

fn binding_json(binding: &RoleBinding) -> Value {
    json!({
        "id": binding.id,
        "role": binding.role.as_str(),
        "subject": {
            "kind": binding.subject.kind.as_str(),
            "issuer": binding.subject.issuer,
            "value": binding.subject.value,
        },
        "granted_by_change_request": binding.granted_by_change_request,
        "granted_at": binding.granted_at,
        "ended_by_change_request": binding.ended_by_change_request,
        "ended_at": binding.ended_at,
    })
}

pub async fn list_role_bindings(
    State(state): State<Arc<AppState>>,
    credentials: Credentials,
    query: Result<Query<BindingsQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    authorize_credentials(&state, &credentials, KavachAction::ReadPrincipals).await?;
    let Query(query) = query.map_err(|_| bad_query("include=ended"))?;
    let include_ended = match query.include.as_deref() {
        None => false,
        Some("ended") => true,
        Some(_) => return Err(ApiError::BadRequest("include takes only ended".into())),
    };
    let bindings = state
        .roles()
        .list_bindings(state.tenant_id(), include_ended)
        .await
        .map_err(unavailable("role bindings"))?;
    let items: Vec<Value> = bindings.iter().map(binding_json).collect();
    Ok(no_store(Json(json!({ "items": items })).into_response()))
}

// ---- GET /v1/access-review ----

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessReviewQuery {
    format: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    Json,
    Csv,
}

/// One row of the access review.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ReviewRow {
    binding_id: String,
    role: &'static str,
    subject_kind: &'static str,
    issuer: String,
    subject: String,
    display_name: String,
    granted_at: DateTime<Utc>,
    change_request_id: Option<String>,
    proposer: String,
    approver: String,
    /// `None` for a group (its members are in the IdP) and for a person
    /// never seen.
    last_seen_at: Option<DateTime<Utc>>,
    /// `None` for a group: staleness is about one person.
    stale: Option<bool>,
}

/// Whether a person last seen at `last_seen` is stale at `now`: never seen,
/// or seen more than `stale_days` ago.
fn is_stale(last_seen: Option<DateTime<Utc>>, now: DateTime<Utc>, stale_days: u32) -> bool {
    last_seen.is_none_or(|seen| now - seen > Duration::days(i64::from(stale_days)))
}

/// A CSV field: quoted per RFC 4180, with a leading `'` when it starts with
/// a character a spreadsheet would run as a formula.
fn csv_field(value: &str) -> String {
    let guarded = if value.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{value}")
    } else {
        value.to_string()
    };
    format!("\"{}\"", guarded.replace('"', "\"\""))
}

fn csv_line(fields: &[&str]) -> String {
    let mut line = fields
        .iter()
        .map(|f| csv_field(f))
        .collect::<Vec<_>>()
        .join(",");
    line.push_str("\r\n");
    line
}

const CSV_COLUMNS: [&str; 12] = [
    "binding_id",
    "role",
    "subject_kind",
    "issuer",
    "subject",
    "display_name",
    "granted_at",
    "change_request_id",
    "proposer",
    "approver",
    "last_seen_at",
    "stale",
];

fn alias_note() -> String {
    format!(
        "The policy also honours the IdP groups {}; their membership is in the IdP and is not part of this export.",
        ALIAS_GROUPS.join(", ")
    )
}

fn review_csv(
    tenant: &str,
    generated_at: DateTime<Utc>,
    stale_days: u32,
    rows: &[ReviewRow],
) -> String {
    let generated = generated_at.to_rfc3339();
    let stale_after = stale_days.to_string();
    let mut out = String::new();
    out.push_str(&csv_line(&[
        "Kavach access review",
        "tenant",
        tenant,
        "generated_at",
        &generated,
        "stale_after_days",
        &stale_after,
    ]));
    out.push_str(&csv_line(&["note", &alias_note()]));
    out.push_str("\r\n");
    out.push_str(&csv_line(&CSV_COLUMNS));
    for row in rows {
        let granted = row.granted_at.to_rfc3339();
        let seen = row.last_seen_at.map(|t| t.to_rfc3339()).unwrap_or_default();
        let stale = row.stale.map(|s| s.to_string()).unwrap_or_default();
        out.push_str(&csv_line(&[
            &row.binding_id,
            row.role,
            row.subject_kind,
            &row.issuer,
            &row.subject,
            &row.display_name,
            &granted,
            row.change_request_id.as_deref().unwrap_or_default(),
            &row.proposer,
            &row.approver,
            &seen,
            &stale,
        ]));
    }
    out
}

fn review_json(
    tenant: &str,
    generated_at: DateTime<Utc>,
    stale_days: u32,
    rows: &[ReviewRow],
) -> Value {
    let rows: Vec<Value> = rows
        .iter()
        .map(|row| {
            json!({
                "binding_id": row.binding_id,
                "role": row.role,
                "subject_kind": row.subject_kind,
                "issuer": row.issuer,
                "subject": row.subject,
                "display_name": row.display_name,
                "granted_at": row.granted_at,
                "change_request_id": row.change_request_id,
                "proposer": row.proposer,
                "approver": row.approver,
                "last_seen_at": row.last_seen_at,
                "stale": row.stale,
            })
        })
        .collect();
    json!({
        "tenant_id": tenant,
        "generated_at": generated_at,
        "stale_after_days": stale_days,
        "alias_groups": ALIAS_GROUPS,
        "note": alias_note(),
        "rows": rows,
    })
}

/// The review's rows: each active binding, with its grant's proposer and
/// approver read from the change request that granted it.
async fn review_rows(
    state: &AppState,
    now: DateTime<Utc>,
    stale_days: u32,
) -> Result<Vec<ReviewRow>, ApiError> {
    let tenant = state.tenant_id();
    let bindings = state
        .roles()
        .list_bindings(tenant, false)
        .await
        .map_err(unavailable("role bindings"))?;
    let people: HashMap<(String, String), PrincipalRecord> = state
        .roles()
        .list_principals(tenant)
        .await
        .map_err(unavailable("the principals directory"))?
        .into_iter()
        .map(|p| ((p.issuer.clone(), p.subject.clone()), p))
        .collect();
    let mut rows = Vec::with_capacity(bindings.len());
    for binding in bindings {
        let (proposer, approver) = match binding.granted_by_change_request.as_deref() {
            None => (BOOTSTRAP_ACTOR.to_string(), String::new()),
            Some(id) => {
                let request = state.changes().get(tenant, id).await.map_err(|_| {
                    ApiError::Unavailable("the granting change request could not be read".into())
                })?;
                (request.proposer, request.decided_by.unwrap_or_default())
            }
        };
        let is_person = binding.subject.kind == SubjectKind::Principal;
        let seen = is_person
            .then(|| {
                people.get(&(
                    binding.subject.issuer.clone(),
                    binding.subject.value.clone(),
                ))
            })
            .flatten();
        let last_seen_at = seen.map(|p| p.last_seen_at);
        rows.push(ReviewRow {
            binding_id: binding.id,
            role: binding.role.as_str(),
            subject_kind: binding.subject.kind.as_str(),
            issuer: binding.subject.issuer,
            subject: binding.subject.value,
            display_name: seen.map(|p| p.display_name.clone()).unwrap_or_default(),
            granted_at: binding.granted_at,
            change_request_id: binding.granted_by_change_request,
            proposer,
            approver,
            last_seen_at,
            stale: is_person.then(|| is_stale(last_seen_at, now, stale_days)),
        });
    }
    Ok(rows)
}

pub async fn access_review(
    State(state): State<Arc<AppState>>,
    credentials: Credentials,
    query: Result<Query<AccessReviewQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let decision =
        authorize_credentials(&state, &credentials, KavachAction::ReadAccessReview).await?;
    let Query(query) = query.map_err(|_| bad_query("format=json or format=csv"))?;
    let format = match query.format.as_deref() {
        None | Some("json") => Format::Json,
        Some("csv") => Format::Csv,
        Some(_) => return Err(ApiError::BadRequest("format is json or csv".into())),
    };
    let now = Utc::now();
    let stale_days = state.access_review_stale_days();
    let rows = review_rows(&state, now, stale_days).await?;

    // The export is recorded before it is handed out; one that cannot be
    // recorded is refused.
    let actor = resolve_credentials(&state, &credentials).map_or_else(
        |_| "unauthenticated (access control off)".to_string(),
        |p| p.id,
    );
    state
        .admin()
        .append_audit(AuditInsert {
            tenant_id: state.tenant_id().into(),
            acting_as_superadmin: decision.acting_as_superadmin,
            action: ACCESS_REVIEW_AUDIT_ACTION.into(),
            resource_type: "access_review".into(),
            resource_id: state.tenant_id().into(),
            actor_principal: actor,
            approver_principal: String::new(),
            payload: json!({
                "format": if format == Format::Csv { "csv" } else { "json" },
                "rows": rows.len(),
            }),
        })
        .await
        .map_err(|_| ApiError::Unavailable("the export could not be audited".into()))?;

    let tenant = state.tenant_id();
    let response = match format {
        Format::Json => Json(review_json(tenant, now, stale_days, &rows)).into_response(),
        Format::Csv => (
            [
                (
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("text/csv; charset=utf-8"),
                ),
                (
                    header::CONTENT_DISPOSITION,
                    HeaderValue::from_static("attachment; filename=\"access-review.csv\""),
                ),
            ],
            review_csv(tenant, now, stale_days, &rows),
        )
            .into_response(),
    };
    Ok(no_store(response))
}

// ---- GET /v1/me ----

/// The caller and the roles bound to them now. Needs an authenticated
/// caller and no Cedar action; it decides nothing. Like any authenticated
/// request, it moves the caller's `last_seen_at` on.
pub async fn me(
    State(state): State<Arc<AppState>>,
    credentials: Credentials,
) -> Result<Response, ApiError> {
    let principal = resolve_credentials(&state, &credentials)?;
    let roles = bound_roles(&state, &principal).await?;
    crate::auth::record_seen(&state, &principal).await;
    Ok(no_store(
        Json(json!({ "principal": principal.id, "roles": roles })).into_response(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(issuer: &str, subject: &str, name: &str) -> PrincipalRecord {
        let now = Utc::now();
        PrincipalRecord {
            tenant_id: "t".into(),
            issuer: issuer.into(),
            subject: subject.into(),
            display_name: name.into(),
            first_seen_at: now,
            last_seen_at: now,
        }
    }

    #[test]
    fn a_formula_never_reaches_a_spreadsheet_as_one() {
        assert_eq!(csv_field("plain"), "\"plain\"");
        assert_eq!(csv_field("=HYPERLINK(\"x\")"), "\"'=HYPERLINK(\"\"x\"\")\"");
        for lead in ["+1", "-1", "@SUM(A1)", "\tx", "\rx"] {
            assert!(csv_field(lead).starts_with("\"'"), "{lead:?}");
        }
        assert_eq!(csv_field("a,b\r\nc"), "\"a,b\r\nc\"");
        assert_eq!(csv_field(""), "\"\"");
    }

    #[test]
    fn a_person_is_stale_when_never_seen_or_seen_too_long_ago() {
        let now = Utc::now();
        assert!(is_stale(None, now, 90));
        assert!(is_stale(Some(now - Duration::days(91)), now, 90));
        assert!(!is_stale(Some(now - Duration::days(90)), now, 90));
        assert!(!is_stale(Some(now), now, 90));
        assert!(is_stale(Some(now - Duration::days(2)), now, 1));
    }

    #[test]
    fn principal_pages_follow_the_cursor_and_the_filter() {
        let records = vec![
            record("https://a", "1", "Asha Rao"),
            record("https://a", "2", "Ravi"),
            record("https://a", "3", "asha k"),
            record("https://b", "1", "Meera"),
        ];
        let (page, next) = principals_page(&records, None, None, 2);
        assert_eq!(page.len(), 2);
        let after = decode_cursor(next.as_deref().unwrap()).unwrap();
        assert_eq!(after, ("https://a".into(), "2".into()));
        let (page, next) = principals_page(&records, None, Some(&after), 2);
        assert_eq!(
            page.iter().map(|r| r.subject.as_str()).collect::<Vec<_>>(),
            ["3", "1"]
        );
        assert_eq!(next, None);

        let (page, next) = principals_page(&records, Some("asha"), None, 1);
        assert_eq!(page[0].display_name, "Asha Rao");
        let after = decode_cursor(next.as_deref().unwrap()).unwrap();
        let (page, next) = principals_page(&records, Some("asha"), Some(&after), 1);
        assert_eq!(page[0].display_name, "asha k");
        assert_eq!(next, None);
        assert!(decode_cursor("not a cursor").is_none());
    }

    #[test]
    fn the_csv_names_the_alias_groups_and_leaves_group_staleness_empty() {
        let now = Utc::now();
        let row = ReviewRow {
            binding_id: "rb_1".into(),
            role: "auditor",
            subject_kind: "group",
            issuer: "https://idp".into(),
            subject: "=cmd".into(),
            display_name: String::new(),
            granted_at: now,
            change_request_id: Some("cr_1".into()),
            proposer: "a".into(),
            approver: "b".into(),
            last_seen_at: None,
            stale: None,
        };
        let csv = review_csv("default", now, 90, &[row]);
        assert!(csv.contains("admins, change-approvers, operators, viewers"));
        assert!(csv.contains("\"'=cmd\""));
        assert!(csv.trim_end().ends_with(",\"\",\"\""));
    }
}

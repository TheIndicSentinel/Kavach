//! `GET /v1/agents` (UI track): the tenant's agents, a page at a time, by
//! agent id, with their states; only this tenant's passports; admins only.
//! Every response is held to `docs/openapi.yaml`.

mod agent_fixture;
mod contract;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use kavach_api::{AppState, EvidenceStoreKind};
use serde_json::{json, Value};
use tower::ServiceExt;

use agent_fixture::*;

/// The fixture's configuration, plus passports in another tenant: one with
/// an agent id of its own and one with the same id as this tenant's agent.
fn with_another_tenant(api: &kavach_api::ApiConfig) {
    let path = &api.dataplane.as_ref().unwrap().mandate_config;
    let mut file: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let passports = file["passports"].as_array_mut().unwrap();
    for agent in ["other-tenant-agent", "collections-agent"] {
        let mut passport = passports[0].clone();
        passport["agent_id"] = json!(agent);
        passport["tenant_id"] = json!("attack-other-tenant");
        passports.push(passport);
    }
    std::fs::write(path, file.to_string()).unwrap();
}

async fn memory_world() -> Gw {
    let api = config(EvidenceStoreKind::Memory, true, 50);
    with_another_tenant(&api);
    gateway_on(api, Some(NUMBER), true).await
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
    with_another_tenant(&api);
    Some(gateway_on(api, Some(NUMBER), true).await)
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

async fn request(
    state: &Arc<AppState>,
    who: &str,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", who);
    if body.is_some() {
        request = request.header("content-type", "application/json");
    }
    let response = contract::router(state.clone())
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

async fn list(state: &Arc<AppState>, query: &str) -> Value {
    let (status, body) = request(state, &admin(), "GET", &format!("/v1/agents{query}"), None).await;
    assert_eq!(status, StatusCode::OK, "{query}: {body}");
    body
}

fn ids(page: &Value) -> Vec<&str> {
    page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["agent_id"].as_str().unwrap())
        .collect()
}

async fn lists_pages_and_filters(gw: Gw) {
    let state = &gw.state;
    // Only this tenant's agents, in agent-id order; never changed: active.
    let page = list(state, "").await;
    assert_eq!(ids(&page), ["collections-agent", "translation-agent"]);
    assert_eq!(page["next_cursor"], Value::Null);
    for item in page["items"].as_array().unwrap() {
        assert_eq!(item["state"], "active", "{item}");
        assert_eq!(item["change_no"], 0, "{item}");
    }

    // A page of one, then the next from its cursor.
    let first = list(state, "?limit=1").await;
    assert_eq!(ids(&first), ["collections-agent"]);
    assert_eq!(first["next_cursor"], "collections-agent");
    let second = list(state, "?limit=1&cursor=collections-agent").await;
    assert_eq!(ids(&second), ["translation-agent"]);
    assert_eq!(second["next_cursor"], Value::Null);
    // A limit of 0 is clamped up to 1, not "everything".
    assert_eq!(ids(&list(state, "?limit=0").await), ["collections-agent"]);

    // Quarantine one agent: the filter finds it, with its whole row.
    let (status, body) = request(
        state,
        &admin(),
        "POST",
        "/v1/agents/translation-agent/quarantine",
        Some(json!({ "reason_code": "rogue_behaviour", "note": "listing test" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let quarantined = list(state, "?state=quarantined").await;
    assert_eq!(ids(&quarantined), ["translation-agent"]);
    assert_eq!(quarantined["items"][0]["change_no"], 1);
    assert_eq!(quarantined["items"][0]["changed_by"], "ops-1");
    assert_eq!(quarantined["next_cursor"], Value::Null);
    assert_eq!(
        ids(&list(state, "?state=active").await),
        ["collections-agent"]
    );
    // A filtered page of one: the cursor carries on past the agents that do
    // not match.
    let first = list(state, "?state=active&limit=1").await;
    assert_eq!(ids(&first), ["collections-agent"]);
    // The filter picks the page, not only trims it: a page of one is the
    // first agent that matches.
    let first = list(state, "?state=quarantined&limit=1").await;
    assert_eq!(ids(&first), ["translation-agent"], "{first}");
    assert_eq!(first["next_cursor"], Value::Null);
    assert_eq!(
        ids(&list(state, "?state=revoked").await),
        Vec::<&str>::new()
    );
}

#[tokio::test]
async fn agents_are_listed_paged_and_filtered_on_memory() {
    lists_pages_and_filters(memory_world().await).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn agents_are_listed_paged_and_filtered_on_postgres() {
    let Some(gw) = postgres_world().await else {
        eprintln!("skipped: KAVACH_TEST_DATABASE_URL is not set");
        return;
    };
    lists_pages_and_filters(gw).await;
}

#[tokio::test]
async fn another_tenants_agents_are_not_listed_or_reachable() {
    let gw = memory_world().await;
    let page = list(&gw.state, "?limit=200").await;
    assert!(!ids(&page).contains(&"other-tenant-agent"), "{page}");
    // A cursor just before one of theirs reaches only this tenant's.
    let page = list(&gw.state, "?cursor=other-tenant-agen").await;
    assert_eq!(ids(&page), ["translation-agent"], "{page}");
    // And the single read is a 404 for them, as before.
    let (status, _) = request(
        &gw.state,
        &admin(),
        "GET",
        "/v1/agents/other-tenant-agent",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn only_admins_list_agents() {
    let gw = memory_world().await;
    let viewer = as_principal("viewer-1", &["viewers"]);
    let (status, body) = request(&gw.state, &viewer, "GET", "/v1/agents", None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body.get("items").is_none(), "{body}");
    let (status, _) = request(&gw.state, "Bearer not-a-token", "GET", "/v1/agents", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_bad_query_is_a_400_problem() {
    let gw = memory_world().await;
    for query in [
        "?state=paused",
        "?state=Active",
        "?limit=-1",
        "?limit=ten",
        "?cursor=",
        "?cursor=a%20b",
        "?order=desc",
    ] {
        let (status, body) = request(
            &gw.state,
            &admin(),
            "GET",
            &format!("/v1/agents{query}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{query}: {body}");
    }
}

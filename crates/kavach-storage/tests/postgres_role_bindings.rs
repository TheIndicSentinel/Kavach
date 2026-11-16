//! Role bindings and the principals directory against a real database
//! (ADR-019). Each test runs in its own schema.

use chrono::{Duration, Utc};
use kavach_storage::testing::isolated_database_url;
use kavach_storage::{
    BindingSubject, BootstrapOutcome, Role, RoleBackend, StoragePool, SubjectKind,
    BOOTSTRAP_AUDIT_ACTION,
};

const ISS: &str = "https://idp.example";

async fn pool() -> Option<StoragePool> {
    let url = isolated_database_url().await?;
    Some(
        StoragePool::connect(&url, &kavach_storage::DatabaseTls::development())
            .await
            .expect("connect + migrate"),
    )
}

fn person(sub: &str) -> BindingSubject {
    BindingSubject {
        kind: SubjectKind::Principal,
        issuer: ISS.into(),
        value: sub.into(),
    }
}

async fn bind(pool: &StoragePool, id: &str, tenant: &str, role: &str, kind: &str, subject: &str) {
    sqlx::query(
        "INSERT INTO role_bindings (id, tenant_id, role, subject_kind, issuer, subject, granted_at) \
         VALUES ($1, $2, $3, $4, $5, $6, now())",
    )
    .bind(id)
    .bind(tenant)
    .bind(role)
    .bind(kind)
    .bind(ISS)
    .bind(subject)
    .execute(&pool.pool)
    .await
    .expect("insert binding");
}

fn groups(names: &[&str]) -> Vec<String> {
    names.iter().map(|s| (*s).to_string()).collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn roles_come_from_person_and_group_bindings_in_the_tenant_only() {
    let Some(pool) = pool().await else { return };
    let store = RoleBackend::Postgres(pool.role_store());
    bind(&pool, "rb_1", "t1", "approver", "principal", "alice").await;
    bind(&pool, "rb_2", "t1", "auditor", "group", "audit-team").await;
    bind(&pool, "rb_3", "t2", "superadmin", "principal", "alice").await;
    bind(&pool, "rb_4", "t1", "operator", "principal", "bob").await;

    let roles = store
        .roles_for("t1", ISS, "alice", &groups(&["audit-team", "other"]))
        .await;
    let roles = roles_of(roles);
    assert_eq!(roles, vec![Role::Approver, Role::Auditor]);

    // Same subject under another issuer: nothing.
    let other = RoleBackend::Postgres(pool.role_store())
        .roles_for("t1", "https://other.example", "alice", &[])
        .await
        .expect("lookup");
    assert!(other.is_empty());

    // Tenant t2's superadmin binding does not reach t1, and vice versa.
    let t2 = roles_of(store.roles_for("t2", ISS, "alice", &groups(&["audit-team"])).await);
    assert_eq!(t2, vec![Role::Superadmin]);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_ended_binding_gives_no_role_and_a_second_active_one_is_refused() {
    let Some(pool) = pool().await else { return };
    let store = RoleBackend::Postgres(pool.role_store());
    bind(&pool, "rb_1", "t1", "approver", "principal", "alice").await;

    let dup = sqlx::query(
        "INSERT INTO role_bindings (id, tenant_id, role, subject_kind, issuer, subject, granted_at) \
         VALUES ('rb_2', 't1', 'approver', 'principal', $1, 'alice', now())",
    )
    .bind(ISS)
    .execute(&pool.pool)
    .await
    .expect_err("one active binding per role and subject");
    assert!(dup.to_string().contains("role_bindings_one_active"), "{dup}");

    sqlx::query("UPDATE role_bindings SET ended_at = now() WHERE id = 'rb_1'")
        .execute(&pool.pool)
        .await
        .expect("end binding");
    assert!(roles_of(store.roles_for("t1", ISS, "alice", &[]).await).is_empty());
    // Once ended, the same role can be bound again.
    bind(&pool, "rb_3", "t1", "approver", "principal", "alice").await;
    let all = store.list_bindings("t1", true).await.expect("list");
    assert_eq!(all.len(), 2);
    assert_eq!(store.list_bindings("t1", false).await.expect("list").len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_database_refuses_unknown_roles_and_inconsistent_ends() {
    let Some(pool) = pool().await else { return };
    for (statement, constraint) in [
        (
            "INSERT INTO role_bindings (id, tenant_id, role, subject_kind, issuer, subject, granted_at) \
             VALUES ('x', 't', 'admins', 'principal', 'i', 's', now())",
            "role_bindings_role_known",
        ),
        (
            "INSERT INTO role_bindings (id, tenant_id, role, subject_kind, issuer, subject, granted_at) \
             VALUES ('x', 't', 'viewer', 'team', 'i', 's', now())",
            "role_bindings_subject_kind_known",
        ),
        (
            "INSERT INTO role_bindings (id, tenant_id, role, subject_kind, issuer, subject, granted_at, \
                ended_at) VALUES ('x', 't', 'viewer', 'group', 'i', 's', now(), now() - interval '1 day')",
            "role_bindings_end_consistent",
        ),
        (
            "INSERT INTO role_bindings (id, tenant_id, role, subject_kind, issuer, subject, granted_at, \
                granted_by_change_request) VALUES ('x', 't', 'viewer', 'group', 'i', 's', now(), 'cr_nope')",
            "role_bindings_granted_by_fk",
        ),
    ] {
        let err = sqlx::query(statement)
            .execute(&pool.pool)
            .await
            .expect_err(constraint);
        assert!(err.to_string().contains(constraint), "{constraint}: {err}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_stored_role_fails_the_lookup_closed() {
    let Some(pool) = pool().await else { return };
    // Simulates a row the code does not know (a newer release, or tampering).
    sqlx::query("ALTER TABLE role_bindings DROP CONSTRAINT role_bindings_role_known")
        .execute(&pool.pool)
        .await
        .expect("drop check as owner");
    bind(&pool, "rb_1", "t1", "root", "principal", "alice").await;
    let err = RoleBackend::Postgres(pool.role_store())
        .roles_for("t1", ISS, "alice", &[])
        .await
        .expect_err("unknown role is an error, not an empty set");
    assert!(err.to_string().contains("unknown"), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_bootstrap_writes_two_flagged_superadmins_once() {
    let Some(pool) = pool().await else { return };
    let store = RoleBackend::Postgres(pool.role_store());
    let now = Utc::now();

    let err = store
        .bootstrap_superadmins("t1", &[person("alice"), person("alice")], now)
        .await
        .expect_err("one person twice");
    assert!(err.to_string().contains("two different"), "{err}");

    let first = store
        .bootstrap_superadmins("t1", &[person("alice"), person("bob")], now)
        .await
        .expect("bootstrap");
    let BootstrapOutcome::Written(written) = first else {
        panic!("first run writes");
    };
    assert_eq!(written.len(), 2);
    assert!(written.iter().all(|b| b.role == Role::Superadmin
        && b.granted_by_change_request.is_none()));

    let again = store
        .bootstrap_superadmins("t1", &[person("carol"), person("dave")], now)
        .await
        .expect("second run");
    assert_eq!(again, BootstrapOutcome::AlreadyPresent);
    assert_eq!(store.list_bindings("t1", true).await.expect("list").len(), 2);
    assert!(roles_of(store.roles_for("t1", ISS, "carol", &[]).await).is_empty());

    let audit = pool.admin_store().list_audit(50).await.expect("audit");
    let rows: Vec<_> = audit
        .iter()
        .filter(|e| e.action == BOOTSTRAP_AUDIT_ACTION)
        .collect();
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|e| e.acting_as_superadmin));
    assert!(audit
        .iter()
        .filter(|e| e.action != BOOTSTRAP_AUDIT_ACTION)
        .all(|e| !e.acting_as_superadmin));

    // Another tenant has its own bootstrap.
    let t2 = store
        .bootstrap_superadmins("t2", &[person("carol"), person("dave")], now)
        .await
        .expect("t2 bootstrap");
    assert!(matches!(t2, BootstrapOutcome::Written(_)));
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_bootstraps_write_one_pair() {
    let Some(pool) = pool().await else { return };
    let now = Utc::now();
    let tasks: Vec<_> = (0..4)
        .map(|i| {
            let store = RoleBackend::Postgres(pool.role_store());
            tokio::spawn(async move {
                store
                    .bootstrap_superadmins(
                        "t1",
                        &[person(&format!("a{i}")), person(&format!("b{i}"))],
                        now,
                    )
                    .await
                    .expect("bootstrap")
            })
        })
        .collect();
    let mut written = 0;
    for task in tasks {
        if matches!(task.await.expect("join"), BootstrapOutcome::Written(_)) {
            written += 1;
        }
    }
    assert_eq!(written, 1);
    let store = RoleBackend::Postgres(pool.role_store());
    assert_eq!(store.list_bindings("t1", true).await.expect("list").len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn last_seen_moves_at_most_hourly_and_names_are_capped() {
    let Some(pool) = pool().await else { return };
    let store = RoleBackend::Postgres(pool.role_store());
    let t0 = Utc::now() - Duration::hours(3);

    store
        .record_principal_seen("t1", ISS, "alice", &"x".repeat(300), t0)
        .await
        .expect("first sight");
    let seen = |list: Vec<kavach_storage::PrincipalRecord>| list[0].clone();
    let first = seen(store.list_principals("t1").await.expect("list"));
    assert_eq!(first.display_name.chars().count(), 200);
    assert_eq!(first.first_seen_at, first.last_seen_at);

    // Within the hour: no write.
    store
        .record_principal_seen("t1", ISS, "alice", &"x".repeat(300), t0 + Duration::minutes(30))
        .await
        .expect("again");
    let p = seen(store.list_principals("t1").await.expect("list"));
    assert_eq!(p.last_seen_at, first.last_seen_at);

    // After the hour: moved on; first_seen kept.
    let later = t0 + Duration::minutes(61);
    store
        .record_principal_seen("t1", ISS, "alice", "Alice", later)
        .await
        .expect("later");
    let p = seen(store.list_principals("t1").await.expect("list"));
    assert_eq!(p.first_seen_at, first.first_seen_at);
    assert_eq!(p.display_name, "Alice");
    assert!(p.last_seen_at > first.last_seen_at);

    // An older timestamp never moves last_seen back.
    store
        .record_principal_seen("t1", ISS, "alice", "Alice B", t0)
        .await
        .expect("stale");
    let p2 = seen(store.list_principals("t1").await.expect("list"));
    assert_eq!(p2.last_seen_at, p.last_seen_at);

    assert!(store.list_principals("t2").await.expect("list").is_empty());
}

fn roles_of(
    result: Result<std::collections::BTreeSet<Role>, kavach_storage::RoleStoreError>,
) -> Vec<Role> {
    result.expect("lookup").into_iter().collect()
}

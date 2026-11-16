//! Role grants and revokes applied by approved change requests against a
//! real database (ADR-019 §4): the binding is written or ended only in the
//! approval transaction, duplicates and the last guarded person are refused
//! under the tenant lock, and two concurrent revokes cannot both pass.

use chrono::{Duration, Utc};
use kavach_storage::testing::isolated_database_url;
use kavach_storage::{
    binding_not_active_reason, duplicate_binding_reason, last_admin_reason, ApprovalCommit,
    AuditInsert, BindingSubject, ChangeKind, ChangeRequest, ChangeStatus, ChangeStoreError,
    GovernanceEffect, PostgresChangeStore, Role, RoleBackend, StoragePool, SubjectKind,
};
use serde_json::json;

const ISS: &str = "https://idp.example";
const TENANT: &str = "t1";

async fn pool() -> Option<StoragePool> {
    let url = isolated_database_url().await?;
    Some(
        StoragePool::connect(&url, &kavach_storage::DatabaseTls::development())
            .await
            .expect("connect + migrate"),
    )
}

fn subject(kind: SubjectKind, value: &str) -> BindingSubject {
    BindingSubject {
        kind,
        issuer: ISS.into(),
        value: value.into(),
    }
}

fn person(sub: &str) -> BindingSubject {
    subject(SubjectKind::Principal, sub)
}

fn audit(action: &str, id: &str) -> AuditInsert {
    AuditInsert {
        acting_as_superadmin: false,
        action: action.into(),
        resource_type: "change_request".into(),
        resource_id: id.into(),
        actor_principal: "proposer".into(),
        approver_principal: String::new(),
        payload: json!({}),
    }
}

/// A pending request of `kind`, stored.
async fn pending(store: &PostgresChangeStore, kind: ChangeKind) -> ChangeRequest {
    let now = Utc::now();
    let id = format!("cr_{}", uuid::Uuid::new_v4().simple());
    let request = ChangeRequest {
        id: id.clone(),
        tenant_id: "default".into(),
        kind,
        params: json!({}),
        binding: json!({}),
        change_digest: format!("digest-{id}"),
        reason: None,
        proposer: "proposer".into(),
        proposer_key: "oidc:proposer".into(),
        status: ChangeStatus::Pending,
        decided_by: None,
        decided_by_key: None,
        outcome: None,
        created_at: now,
        expires_at: now + Duration::hours(1),
        decided_at: None,
    };
    store
        .create(&request, &audit("change_request_proposed", &id))
        .await
        .expect("create");
    request
}

fn approval(request: &ChangeRequest, effect: GovernanceEffect) -> ApprovalCommit {
    ApprovalCommit {
        request_id: request.id.clone(),
        change_digest: request.change_digest.clone(),
        approver: "approver".into(),
        approver_key: "oidc:approver".into(),
        expected_pointer_version: None,
        effects: vec![effect],
        audit: audit(request.kind.as_str(), &request.id),
        outcome: json!({}),
        now: Utc::now(),
    }
}

fn grant(role: Role, who: BindingSubject) -> GovernanceEffect {
    GovernanceEffect::GrantRole {
        binding_id: format!("rb_{}", uuid::Uuid::new_v4().simple()),
        tenant_id: TENANT.into(),
        role,
        subject: who,
    }
}

fn end(tenant: &str, binding_id: &str) -> GovernanceEffect {
    GovernanceEffect::EndRoleBinding {
        tenant_id: tenant.into(),
        binding_id: binding_id.into(),
    }
}

/// Grants `role` to `who` through an approved request; returns the binding id.
async fn granted(store: &PostgresChangeStore, role: Role, who: BindingSubject) -> String {
    let effect = grant(role, who);
    let GovernanceEffect::GrantRole { binding_id, .. } = &effect else {
        unreachable!()
    };
    let binding_id = binding_id.clone();
    let request = pending(store, ChangeKind::GrantRole).await;
    store
        .commit_approval(approval(&request, effect))
        .await
        .expect("grant applies");
    binding_id
}

fn stale_reason(result: Result<ChangeRequest, ChangeStoreError>) -> String {
    match result {
        Err(ChangeStoreError::Stale { reason, request }) => {
            assert_eq!(request.status, ChangeStatus::Failed);
            reason
        }
        other => panic!("expected a refused approval, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_grant_is_written_only_by_its_approval_and_never_twice() {
    let Some(pool) = pool().await else { return };
    let store = pool.change_request_store();
    let roles = RoleBackend::Postgres(pool.role_store());

    let request = pending(&store, ChangeKind::GrantRole).await;
    assert!(roles
        .roles_for(TENANT, ISS, Some("alice"), &[])
        .await
        .unwrap()
        .is_empty());
    let applied = store
        .commit_approval(approval(&request, grant(Role::Approver, person("alice"))))
        .await
        .unwrap();
    assert_eq!(applied.status, ChangeStatus::Applied);
    let bindings = roles.list_bindings(TENANT, false).await.unwrap();
    assert_eq!(bindings.len(), 1);
    assert_eq!(
        bindings[0].granted_by_change_request.as_deref(),
        Some(request.id.as_str())
    );
    assert!(roles
        .roles_for(TENANT, ISS, Some("alice"), &[])
        .await
        .unwrap()
        .contains(&Role::Approver));

    let again = pending(&store, ChangeKind::GrantRole).await;
    let reason = stale_reason(
        store
            .commit_approval(approval(&again, grant(Role::Approver, person("alice"))))
            .await,
    );
    assert_eq!(reason, duplicate_binding_reason(Role::Approver));
    assert_eq!(roles.list_bindings(TENANT, false).await.unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_revoke_ends_the_binding_once_and_only_in_its_tenant() {
    let Some(pool) = pool().await else { return };
    let store = pool.change_request_store();
    let roles = RoleBackend::Postgres(pool.role_store());
    let id = granted(&store, Role::Operator, person("olga")).await;

    // Named from another tenant, the binding is not found.
    let elsewhere = pending(&store, ChangeKind::RevokeRole).await;
    let reason = stale_reason(
        store
            .commit_approval(approval(&elsewhere, end("t2", &id)))
            .await,
    );
    assert_eq!(reason, binding_not_active_reason(&id));

    let revoke = pending(&store, ChangeKind::RevokeRole).await;
    store
        .commit_approval(approval(&revoke, end(TENANT, &id)))
        .await
        .unwrap();
    let all = roles.list_bindings(TENANT, true).await.unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(
        all[0].ended_by_change_request.as_deref(),
        Some(revoke.id.as_str())
    );
    assert!(roles
        .roles_for(TENANT, ISS, Some("olga"), &[])
        .await
        .unwrap()
        .is_empty());

    let twice = pending(&store, ChangeKind::RevokeRole).await;
    let reason = stale_reason(
        store
            .commit_approval(approval(&twice, end(TENANT, &id)))
            .await,
    );
    assert_eq!(reason, binding_not_active_reason(&id));
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_revokes_of_the_last_two_superadmins_leave_one() {
    let Some(pool) = pool().await else { return };
    let store = pool.change_request_store();
    let roles = RoleBackend::Postgres(pool.role_store());
    let a = granted(&store, Role::Superadmin, person("root-a")).await;
    let b = granted(&store, Role::Superadmin, person("root-b")).await;
    // A group superadmin is not a person and does not keep the tenant safe.
    granted(
        &store,
        Role::Superadmin,
        subject(SubjectKind::Group, "root-team"),
    )
    .await;

    for round in 0..5 {
        let (first, second) = if round == 0 {
            (a.clone(), b.clone())
        } else {
            // Re-arm: put the ended one back as a fresh binding.
            let active = roles.list_bindings(TENANT, false).await.unwrap();
            let people: Vec<_> = active
                .iter()
                .filter(|x| x.subject.kind == SubjectKind::Principal)
                .collect();
            assert_eq!(people.len(), 1, "round {round}: one person remains");
            let missing = if people[0].subject.value == "root-a" {
                "root-b"
            } else {
                "root-a"
            };
            let fresh = granted(&store, Role::Superadmin, person(missing)).await;
            (people[0].id.clone(), fresh)
        };
        let r1 = pending(&store, ChangeKind::RevokeRole).await;
        let r2 = pending(&store, ChangeKind::RevokeRole).await;
        let (s1, s2) = (store.clone(), store.clone());
        let c1 = approval(&r1, end(TENANT, &first));
        let c2 = approval(&r2, end(TENANT, &second));
        let (o1, o2) = tokio::join!(
            tokio::spawn(async move { s1.commit_approval(c1).await }),
            tokio::spawn(async move { s2.commit_approval(c2).await }),
        );
        let outcomes = [o1.unwrap(), o2.unwrap()];
        let applied = outcomes.iter().filter(|o| o.is_ok()).count();
        assert_eq!(applied, 1, "round {round}: exactly one revoke applies");
        let refused = outcomes
            .into_iter()
            .find(Result::is_err)
            .expect("one refused");
        assert_eq!(stale_reason(refused), last_admin_reason(Role::Superadmin));
    }
}

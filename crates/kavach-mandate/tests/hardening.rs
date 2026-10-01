//! H4 hardening (ADR-011): configuration validation, full-chain verification,
//! re-delegation, and the mandate store contract.

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;

use common::*;
use kavach_domain::mandate::{AgentPassport, ContactWindow, DelegationRequest, TimeZoneId};
use kavach_mandate::memory::InMemoryMandateStore;
use kavach_ports::{ErrorClass, MandateStore};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn in_memory_store_meets_the_contract() {
    kavach_ports_testkit::mandate_store::conformance(Arc::new(InMemoryMandateStore::new())).await;
}

fn rejected(
    templates: Vec<kavach_domain::mandate::MandateTemplate>,
    passports: Vec<AgentPassport>,
) -> String {
    match try_fixture(vec![consent(t0())], templates, passports) {
        Ok(_) => panic!("config should be refused"),
        Err(err) => {
            assert_eq!(err.class, ErrorClass::Invalid);
            err.message
        }
    }
}

#[test]
fn validate_rejects_unsafe_configuration() {
    let with = |edit: fn(&mut kavach_domain::mandate::MandateTemplate)| {
        let mut t = template();
        edit(&mut t);
        rejected(vec![t], passports())
    };
    assert!(rejected(vec![template(), template()], passports()).contains("duplicate"));
    let mut dup = passports();
    dup.push(dup[0].clone());
    assert!(rejected(vec![template()], dup).contains("duplicate passport"));
    assert!(with(|t| t.ttl_seconds = 31 * 24 * 3600).contains("ttl_seconds"));
    assert!(with(|t| {
        t.channels.insert("email".into());
    })
    .contains("unknown channel"));
    assert!(with(|t| t.window = Some(ContactWindow {
        from_min: 7 * 60,
        ..window()
    }))
    .contains("floor"));
    assert!(with(|t| t.window = Some(ContactWindow {
        to_min: 20 * 60,
        ..window()
    }))
    .contains("floor"));
    assert!(with(|t| t.window = Some(ContactWindow {
        max_per_day: 0,
        ..window()
    }))
    .contains("floor"));
    assert!(with(|t| t.window = None).contains("contact window"));
    assert!(with(|t| {
        t.ceilings.insert("waiver_bps".into(), -1);
    })
    .contains("out of range"));
    assert!(with(|t| t.delegation.max_depth = 5).contains("max_depth"));
    assert!(with(|t| {
        t.delegation.allowed_agents.insert("ghost-agent".into());
    })
    .contains("no passport"));
    let mut bad = passports();
    bad[0].ceilings.insert("waiver_bps".into(), 10_001);
    assert!(rejected(vec![template()], bad).contains("out of range"));
    // A window that is fine for the floor still needs the right time zone
    // (only Asia/Kolkata exists) and passes.
    let ok = ContactWindow {
        tz: TimeZoneId::AsiaKolkata,
        from_min: 9 * 60,
        to_min: 18 * 60,
        max_per_day: 2,
    };
    let mut t = template();
    t.window = Some(ok);
    assert!(try_fixture(vec![consent(t0())], vec![t], passports()).is_ok());
}

/// collections -> translator -> summary, with explicit re-delegation.
async fn chain() -> (Fixture, String, String, String) {
    let mut t = template();
    t.delegation.max_depth = 2;
    t.delegation.allowed_agents = set(&["translator-agent", "summary-agent"]);
    let mut ps = passports();
    ps.push(AgentPassport {
        agent_id: "summary-agent".into(),
        owner: "collections-ops".into(),
        actions: set(&["read_fields"]),
        data_fields: set(&["name"]),
        ceilings: BTreeMap::new(),
        ..ps[1].clone()
    });
    let f = try_fixture(vec![consent(t0())], vec![t], ps).expect("config");
    let token = sign_event(&f.sor, "lms-issuer-1", &event(f.now, "evt-chain")).await;
    let root = f.service.issue_from_event(&token).await.unwrap();
    let read_only = DelegationRequest {
        actions: set(&["read_fields"]),
        ..Default::default()
    };

    // Without naming who may receive it next, the child cannot re-delegate.
    let closed = f
        .service
        .delegate(
            TENANT,
            &root.mandate.id,
            "collections-agent",
            "translator-agent",
            &read_only,
        )
        .await
        .unwrap();
    assert!(closed.mandate.delegation.allowed_agents.is_empty());
    assert!(f
        .service
        .delegate(
            TENANT,
            &closed.mandate.id,
            "translator-agent",
            "summary-agent",
            &read_only
        )
        .await
        .is_err());

    let open = DelegationRequest {
        allowed_agents: set(&["summary-agent"]),
        ..read_only.clone()
    };
    let middle = f
        .service
        .delegate(
            TENANT,
            &root.mandate.id,
            "collections-agent",
            "translator-agent",
            &open,
        )
        .await
        .unwrap();
    let leaf = f
        .service
        .delegate(
            TENANT,
            &middle.mandate.id,
            "translator-agent",
            "summary-agent",
            &read_only,
        )
        .await
        .unwrap();
    f.service
        .verify_active(&leaf.token)
        .await
        .expect("valid chain");
    (f, root.mandate.id, middle.mandate.id, leaf.token)
}

#[tokio::test]
async fn verification_checks_every_ancestor() {
    // A store that broke the invariant: root revoked, leaf still active.
    let (f, root, _, leaf) = chain().await;
    let store: &InMemoryMandateStore = f.service.store();
    let mut record = store.get(TENANT, &root).await.unwrap().unwrap();
    record.status = kavach_domain::mandate::MandateStatus::Revoked;
    store.overwrite_unchecked(TENANT, &root, Some(record));
    let err = f.service.verify_active(&leaf).await.unwrap_err();
    assert!(err.message.contains("revoked"), "{}", err.message);

    // A tampered ancestor (stored value no longer matches its signed token).
    let (f, root, _, leaf) = chain().await;
    let store: &InMemoryMandateStore = f.service.store();
    let mut record = store.get(TENANT, &root).await.unwrap().unwrap();
    record.mandate.exp += chrono::Duration::days(365);
    store.overwrite_unchecked(TENANT, &root, Some(record));
    let err = f.service.verify_active(&leaf).await.unwrap_err();
    assert!(
        err.message.contains("differs from its signed token"),
        "{}",
        err.message
    );

    // A missing link.
    let (f, _, middle, leaf) = chain().await;
    f.service.store().overwrite_unchecked(TENANT, &middle, None);
    let err = f.service.verify_active(&leaf).await.unwrap_err();
    assert!(
        err.message.contains("incomplete delegation chain"),
        "{}",
        err.message
    );

    // Expiry is checked on the chain too: after the root expires, nothing verifies.
    let (f, _, _, leaf) = chain().await;
    f.clock().advance(chrono::Duration::days(8));
    assert!(f.service.verify_active(&leaf).await.is_err());
}

#[tokio::test]
async fn revocation_reaches_the_whole_chain_and_blocks_new_children() {
    let (f, root, middle, leaf) = chain().await;
    let outcome = f
        .service
        .revoke(
            TENANT,
            &root,
            kavach_domain::mandate::RevocationReason::Dispute,
        )
        .await
        .unwrap();
    // root, the non-re-delegating child, middle and leaf.
    assert_eq!(outcome.revoked.len(), 4);
    assert_eq!(
        outcome.publish_errors.len(),
        0,
        "{:?}",
        outcome.publish_errors
    );
    assert!(f.service.verify_active(&leaf).await.is_err());
    let again = DelegationRequest {
        actions: set(&["read_fields"]),
        ..Default::default()
    };
    assert!(f
        .service
        .delegate(TENANT, &middle, "translator-agent", "summary-agent", &again)
        .await
        .is_err());
}

//! Signed consent grants and withdrawals commit their history and effects together.

use chrono::{Duration, Utc};
use kavach_domain::authority::{AuthorityChange, AuthorityUpdateEvent};
use kavach_domain::mandate::{ConsentArtefactSubset, ConsentRecord, ConsentStatus};
use kavach_keys::InMemoryKeyProvider;
use kavach_mandate::jws::{self, KeySet, TYP_AUTHORITY_UPDATE};
use kavach_mandate::{AuthorityVerifier, MandateConfig, SorIssuer};
use kavach_ports::{ClosureRule, ConsentSource, ErrorClass, MandateStore, SyncStatus, TrustedNow};
use kavach_storage::testing::isolated_database_urls;
use kavach_storage::{connect_runtime, DatabaseTls, StoragePool};

fn consent_for_tenant(
    tenant_id: &str,
    subject_ref: &str,
    now: chrono::DateTime<Utc>,
    active: bool,
) -> ConsentRecord {
    ConsentRecord {
        consent_id: "C-1".into(),
        tenant_id: tenant_id.into(),
        subject_ref: subject_ref.into(),
        purposes: ["loan_recovery".into()].into(),
        expires_at: now + Duration::days(30),
        active,
        artefact: Some(ConsentArtefactSubset {
            data_types: ["account_transactions".into()].into(),
            valid_from: now - Duration::hours(1),
            data_from: now - Duration::days(30),
            data_to: now,
            status: if active {
                ConsentStatus::Active
            } else {
                ConsentStatus::Revoked
            },
        }),
    }
}

fn event(
    tenant_id: &str,
    subject_ref: &str,
    now: chrono::DateTime<Utc>,
    id: &str,
    active: bool,
) -> AuthorityUpdateEvent {
    AuthorityUpdateEvent {
        update_id: id.into(),
        tenant_id: tenant_id.into(),
        system: "lms".into(),
        occurred_at: now,
        nonce: format!("nonce-{id}"),
        change: AuthorityChange::Consent(consent_for_tenant(tenant_id, subject_ref, now, active)),
    }
}

fn make_verifier(tenant_id: &str, public_key: kavach_ports::PublicKey) -> AuthorityVerifier {
    AuthorityVerifier::new(
        tenant_id,
        MandateConfig {
            issuer_id: "test".into(),
            signing_kid: "unused".into(),
            mandate_keys: KeySet::new([public_key.clone()]),
            sor_issuers: vec![SorIssuer {
                tenant_id: tenant_id.into(),
                system: "lms".into(),
                key: public_key,
            }],
            templates: Vec::new(),
            passports: Vec::new(),
            event_freshness_seconds: 300,
            replay_window_seconds: 3600,
            max_clock_error_ms: 500,
        },
    )
    .unwrap()
}

#[tokio::test]
async fn signed_consent_grants_and_withdrawals_are_atomic_and_idempotent() {
    let Some((owner_url, runtime_url)) = isolated_database_urls().await else {
        return;
    };
    let tls = DatabaseTls::development();
    let owner = StoragePool::connect(&owner_url, &tls).await.unwrap();
    let runtime = connect_runtime(&runtime_url, &tls).await.unwrap();
    let store = runtime.authority_update_store();
    let now = Utc::now();
    let trusted = TrustedNow {
        utc: now,
        sync: SyncStatus::Synced { max_error_ms: 0 },
    };
    let mut signer = InMemoryKeyProvider::new();
    let public_key = signer.insert_seed("lms-1", [7; 32]).unwrap();
    let other_tenant_key = signer.insert_seed("lms-b-1", [8; 32]).unwrap();
    let verifier = make_verifier("tenant-a", public_key);
    let other_tenant_verifier = make_verifier("tenant-b", other_tenant_key);
    let grant = event("tenant-a", "ref:borrower:B-1", now, "consent-1", true);
    let token = jws::sign(&signer, "lms-1", TYP_AUTHORITY_UPDATE, &grant)
        .await
        .unwrap();
    let verified_grant = verifier.verify(&token, trusted).unwrap();

    let (first, retry) = tokio::join!(
        store.apply_consent_grant(&verified_grant),
        store.apply_consent_grant(&verified_grant)
    );
    assert_ne!(first.unwrap().replayed, retry.unwrap().replayed);
    let other_tenant_grant = event("tenant-b", "ref:borrower:B-2", now, "consent-b-1", true);
    let token = jws::sign(
        &signer,
        "lms-b-1",
        TYP_AUTHORITY_UPDATE,
        &other_tenant_grant,
    )
    .await
    .unwrap();
    let verified_other = other_tenant_verifier.verify(&token, trusted).unwrap();
    assert!(
        !store
            .apply_consent_grant(&verified_other)
            .await
            .unwrap()
            .replayed
    );
    let consent_source = runtime.consent_source();
    assert_eq!(
        consent_source
            .get("tenant-a", "C-1")
            .await
            .unwrap()
            .unwrap()
            .subject_ref,
        "ref:borrower:B-1"
    );
    let other_consent = consent_source
        .get("tenant-b", "C-1")
        .await
        .unwrap()
        .expect("same consent ID is scoped to tenant B");
    assert_eq!(other_consent.tenant_id, "tenant-b");
    assert_eq!(other_consent.subject_ref, "ref:borrower:B-2");
    assert!(consent_source
        .get("tenant-c", "C-1")
        .await
        .unwrap()
        .is_none());
    let history_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM authority_updates")
        .fetch_one(&runtime.pool)
        .await
        .unwrap();
    assert_eq!(history_count, 2);
    let version: i64 = sqlx::query_scalar(
        "SELECT version FROM consent_current WHERE tenant_id = 'tenant-a' AND consent_id = 'C-1'",
    )
    .fetch_one(&runtime.pool)
    .await
    .unwrap();
    assert_eq!(version, 1);

    let mut conflicting_grant = grant;
    if let AuthorityChange::Consent(record) = &mut conflicting_grant.change {
        record.purposes = ["different_purpose".into()].into();
    }
    let token = jws::sign(&signer, "lms-1", TYP_AUTHORITY_UPDATE, &conflicting_grant)
        .await
        .unwrap();
    let conflict = verifier.verify(&token, trusted).unwrap();
    assert_eq!(
        store
            .apply_consent_grant(&conflict)
            .await
            .unwrap_err()
            .class,
        ErrorClass::Rejected
    );

    insert_mandate_tree(&owner, now).await;
    let withdrawal = event(
        "tenant-a",
        "ref:borrower:B-1",
        now + Duration::seconds(1),
        "consent-2",
        false,
    );
    let token = jws::sign(&signer, "lms-1", TYP_AUTHORITY_UPDATE, &withdrawal)
        .await
        .unwrap();
    let withdrawal_clock = TrustedNow {
        utc: now + Duration::seconds(1),
        sync: SyncStatus::Unsynced,
    };
    let verified_withdrawal = verifier.verify(&token, withdrawal_clock).unwrap();
    assert!(!verified_withdrawal.clock_synced());

    sqlx::query("REVOKE INSERT ON mandate_revocations FROM kavach_runtime")
        .execute(&owner.pool)
        .await
        .unwrap();
    assert_eq!(
        store
            .apply_consent_withdrawal(&verified_withdrawal)
            .await
            .unwrap_err()
            .class,
        ErrorClass::Unavailable
    );
    let current_active: bool = sqlx::query_scalar(
        "SELECT (record->>'active')::boolean FROM consent_current \
         WHERE tenant_id = 'tenant-a' AND consent_id = 'C-1'",
    )
    .fetch_one(&runtime.pool)
    .await
    .unwrap();
    assert!(current_active);
    let active_mandates: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM mandates WHERE tenant_id = 'tenant-a' AND status = 'active'",
    )
    .fetch_one(&runtime.pool)
    .await
    .unwrap();
    assert_eq!(active_mandates, 2);
    let history_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM authority_updates")
        .fetch_one(&runtime.pool)
        .await
        .unwrap();
    assert_eq!(history_count, 2);

    sqlx::query("GRANT INSERT ON mandate_revocations TO kavach_runtime")
        .execute(&owner.pool)
        .await
        .unwrap();
    let applied = store
        .apply_consent_withdrawal(&verified_withdrawal)
        .await
        .unwrap();
    assert!(!applied.replayed);
    assert_eq!(applied.revoked, ["child-1", "root-1"]);
    let inactive: bool = sqlx::query_scalar(
        "SELECT NOT (record->>'active')::boolean FROM consent_current \
         WHERE tenant_id = 'tenant-a' AND consent_id = 'C-1'",
    )
    .fetch_one(&runtime.pool)
    .await
    .unwrap();
    assert!(inactive);
    let revoked_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM mandates WHERE tenant_id = 'tenant-a' AND status = 'revoked'",
    )
    .fetch_one(&runtime.pool)
    .await
    .unwrap();
    assert_eq!(revoked_count, 2);
    let revocation_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mandate_revocations")
        .fetch_one(&runtime.pool)
        .await
        .unwrap();
    assert_eq!(revocation_count, 1);
    let clock_synced: bool =
        sqlx::query_scalar("SELECT clock_synced FROM mandate_revocations LIMIT 1")
            .fetch_one(&runtime.pool)
            .await
            .unwrap();
    assert!(!clock_synced);

    let retry = store
        .apply_consent_withdrawal(&verified_withdrawal)
        .await
        .unwrap();
    assert!(retry.replayed);
    assert_eq!(retry.revoked, applied.revoked);

    let mut after_withdrawal =
        kavach_ports_testkit::mandate_store::sample("after-withdrawal", None, 0);
    after_withdrawal.mandate.tenant_id = "tenant-a".into();
    after_withdrawal.mandate.source.record_ref = "loan-2".into();
    after_withdrawal.mandate.source.event_id = "source-2".into();
    let mandate_store = owner.mandate_store();
    assert_eq!(
        mandate_store
            .insert(after_withdrawal.clone())
            .await
            .unwrap_err()
            .class,
        ErrorClass::Rejected
    );
    assert_eq!(
        mandate_store
            .insert_unless_closed(
                after_withdrawal,
                now + Duration::seconds(2),
                ClosureRule {
                    future_allowance_seconds: 300,
                    skew_margin_seconds: 30,
                },
            )
            .await
            .unwrap_err()
            .class,
        ErrorClass::Rejected
    );

    let mut conflicting_withdrawal = withdrawal;
    if let AuthorityChange::Consent(record) = &mut conflicting_withdrawal.change {
        record.purposes = ["different_purpose".into()].into();
    }
    let token = jws::sign(
        &signer,
        "lms-1",
        TYP_AUTHORITY_UPDATE,
        &conflicting_withdrawal,
    )
    .await
    .unwrap();
    let conflict = verifier.verify(&token, trusted).unwrap();
    assert_eq!(
        store
            .apply_consent_withdrawal(&conflict)
            .await
            .unwrap_err()
            .class,
        ErrorClass::Rejected
    );

    let history_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM authority_updates")
        .fetch_one(&runtime.pool)
        .await
        .unwrap();
    assert_eq!(history_count, 2);

    let consent_update_allowed: bool = sqlx::query_scalar(
        "SELECT has_table_privilege('kavach_runtime', 'consent_current', 'UPDATE')",
    )
    .fetch_one(&owner.pool)
    .await
    .unwrap();
    assert!(consent_update_allowed);
    let revocation_insert_allowed: bool = sqlx::query_scalar(
        "SELECT has_table_privilege('kavach_runtime', 'mandate_revocations', 'INSERT')",
    )
    .fetch_one(&owner.pool)
    .await
    .unwrap();
    assert!(revocation_insert_allowed);
}

async fn insert_mandate_tree(owner: &StoragePool, now: chrono::DateTime<Utc>) {
    for (id, parent_id, depth) in [("root-1", None, 0_i16), ("child-1", Some("root-1"), 1)] {
        let mandate = serde_json::json!({
            "mv": 1,
            "id": id,
            "tenant_id": "tenant-a",
            "issuer": "test",
            "source": {
                "system": "lms",
                "record_ref": "loan-1",
                "event_id": "source-1"
            },
            "principal": "borrower",
            "holder": "agent-1",
            "subject_ref": "ref:borrower:B-1",
            "purpose": "loan_recovery",
            "consent_refs": ["C-1"],
            "actions": ["send_message"],
            "data_fields": [],
            "channels": ["sms"],
            "window": null,
            "ceilings": {},
            "delegation": {"max_depth": 1, "allowed_agents": []},
            "parent_id": parent_id,
            "depth": depth,
            "nbf": now,
            "exp": now + Duration::days(1),
            "nonce": format!("nonce-{id}")
        });
        sqlx::query(
            "INSERT INTO mandates (tenant_id, id, parent_id, depth, status, \
             revoked_reason, token, mandate, source_system, source_event_id, source_occurred_at) \
             VALUES ('tenant-a', $1, $2, $3, 'active', NULL, 'test-token', $4, \
                     'lms', $1, $5)",
        )
        .bind(id)
        .bind(parent_id)
        .bind(depth)
        .bind(mandate)
        .bind(now)
        .execute(&owner.pool)
        .await
        .unwrap();
    }
}

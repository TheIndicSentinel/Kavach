//! Signed preference changes commit their history and projection together.

use chrono::{Duration, Utc};
use kavach_domain::authority::{AuthorityChange, AuthorityUpdateEvent};
use kavach_domain::mandate::{ContactPreferenceRecord, ContactPreferenceStatus};
use kavach_keys::InMemoryKeyProvider;
use kavach_mandate::jws::{self, KeySet, TYP_AUTHORITY_UPDATE};
use kavach_mandate::{AuthorityVerifier, MandateConfig, SorIssuer};
use kavach_ports::{
    require_contact_permission, ContactPreferenceSource, ErrorClass, SyncStatus, TrustedNow,
};
use kavach_storage::testing::isolated_database_urls;
use kavach_storage::{connect_runtime, DatabaseTls, StoragePool};

fn event_for_tenant(
    tenant_id: &str,
    now: chrono::DateTime<Utc>,
    id: &str,
    status: ContactPreferenceStatus,
) -> AuthorityUpdateEvent {
    AuthorityUpdateEvent {
        update_id: id.into(),
        tenant_id: tenant_id.into(),
        system: "lms".into(),
        occurred_at: now,
        nonce: format!("nonce-{id}"),
        change: AuthorityChange::ContactPreference(ContactPreferenceRecord {
            tenant_id: tenant_id.into(),
            subject_ref: "ref:borrower:B-1".into(),
            channel: "sms".into(),
            status,
            valid_from: now - Duration::hours(1),
            expires_at: now + Duration::days(1),
        }),
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
async fn signed_preference_updates_are_atomic_idempotent_and_fail_closed() {
    let Some((owner_url, runtime_url)) = isolated_database_urls().await else {
        return;
    };
    let tls = DatabaseTls::development();
    let owner = StoragePool::connect(&owner_url, &tls).await.unwrap();
    let runtime = connect_runtime(&runtime_url, &tls).await.unwrap();
    let store = runtime.authority_update_store();
    let source = runtime.contact_preference_source();
    let now = Utc::now();
    let trusted = TrustedNow {
        utc: now,
        sync: SyncStatus::Synced { max_error_ms: 0 },
    };
    let mut signer = InMemoryKeyProvider::new();
    let public_key = signer.insert_seed("lms-1", [9; 32]).unwrap();
    let other_tenant_key = signer.insert_seed("lms-b-1", [10; 32]).unwrap();
    let verifier = make_verifier("tenant-a", public_key);
    let other_tenant_verifier = make_verifier("tenant-b", other_tenant_key);
    let initial = event_for_tenant("tenant-a", now, "pref-1", ContactPreferenceStatus::Allowed);
    let token = jws::sign(&signer, "lms-1", TYP_AUTHORITY_UPDATE, &initial)
        .await
        .unwrap();
    let accepted = verifier.verify(&token, trusted).unwrap();
    let (first, retry) = tokio::join!(
        store.apply_preference(&accepted),
        store.apply_preference(&accepted)
    );
    assert_ne!(first.unwrap().replayed, retry.unwrap().replayed);
    let history_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM authority_updates")
        .fetch_one(&runtime.pool)
        .await
        .unwrap();
    assert_eq!(history_count, 1);
    assert!(
        require_contact_permission(&source, "tenant-a", "ref:borrower:B-1", "sms", now)
            .await
            .is_ok()
    );
    let other_tenant_preference = event_for_tenant(
        "tenant-b",
        now,
        "pref-b-1",
        ContactPreferenceStatus::OptedOut,
    );
    let token = jws::sign(
        &signer,
        "lms-b-1",
        TYP_AUTHORITY_UPDATE,
        &other_tenant_preference,
    )
    .await
    .unwrap();
    let accepted_other = other_tenant_verifier.verify(&token, trusted).unwrap();
    assert!(
        !store
            .apply_preference(&accepted_other)
            .await
            .unwrap()
            .replayed
    );
    let other_current = source
        .get("tenant-b", "ref:borrower:B-1", "sms")
        .await
        .unwrap()
        .expect("tenant B has its own preference");
    assert_eq!(other_current.status, ContactPreferenceStatus::OptedOut);
    assert!(
        require_contact_permission(&source, "tenant-a", "ref:borrower:B-1", "sms", now)
            .await
            .is_ok()
    );
    assert_eq!(
        require_contact_permission(&source, "tenant-b", "ref:borrower:B-1", "sms", now)
            .await
            .unwrap_err()
            .class,
        ErrorClass::Rejected
    );

    let mut changed = event_for_tenant("tenant-a", now, "pref-1", ContactPreferenceStatus::Allowed);
    if let AuthorityChange::ContactPreference(record) = &mut changed.change {
        record.status = ContactPreferenceStatus::OptedOut;
    }
    let token = jws::sign(&signer, "lms-1", TYP_AUTHORITY_UPDATE, &changed)
        .await
        .unwrap();
    let conflict = verifier.verify(&token, trusted).unwrap();
    assert_eq!(
        store.apply_preference(&conflict).await.unwrap_err().class,
        ErrorClass::Rejected
    );
    assert!(
        require_contact_permission(&source, "tenant-a", "ref:borrower:B-1", "sms", now)
            .await
            .is_ok()
    );

    assert_stop_and_no_reopen(&owner, &runtime, &signer, &verifier, now).await;
}

async fn assert_stop_and_no_reopen(
    owner: &StoragePool,
    runtime: &StoragePool,
    signer: &InMemoryKeyProvider,
    verifier: &AuthorityVerifier,
    now: chrono::DateTime<Utc>,
) {
    let store = runtime.authority_update_store();
    let source = runtime.contact_preference_source();
    let mut stop = event_for_tenant(
        "tenant-a",
        now - Duration::days(10),
        "pref-2",
        ContactPreferenceStatus::OptedOut,
    );
    if let AuthorityChange::ContactPreference(record) = &mut stop.change {
        record.expires_at = now + Duration::days(1);
    }
    let token = jws::sign(signer, "lms-1", TYP_AUTHORITY_UPDATE, &stop)
        .await
        .unwrap();
    let accepted_stop = verifier
        .verify(
            &token,
            TrustedNow {
                utc: now,
                sync: SyncStatus::Unsynced,
            },
        )
        .unwrap();
    sqlx::query("REVOKE UPDATE ON contact_preference_current FROM kavach_runtime")
        .execute(&owner.pool)
        .await
        .unwrap();
    assert_eq!(
        store
            .apply_preference(&accepted_stop)
            .await
            .unwrap_err()
            .class,
        ErrorClass::Unavailable
    );
    let history_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM authority_updates")
        .fetch_one(&runtime.pool)
        .await
        .unwrap();
    assert_eq!(history_count, 2);
    sqlx::query("GRANT UPDATE ON contact_preference_current TO kavach_runtime")
        .execute(&owner.pool)
        .await
        .unwrap();
    assert!(
        !store
            .apply_preference(&accepted_stop)
            .await
            .unwrap()
            .replayed
    );
    assert_eq!(
        require_contact_permission(&source, "tenant-a", "ref:borrower:B-1", "sms", now)
            .await
            .unwrap_err()
            .class,
        ErrorClass::Rejected
    );
    assert!(
        store
            .apply_preference(&accepted_stop)
            .await
            .unwrap()
            .replayed
    );
    let version: i64 = sqlx::query_scalar(
        "SELECT version FROM contact_preference_current \
         WHERE tenant_id = 'tenant-a' AND subject_ref = 'ref:borrower:B-1' AND channel = 'sms'",
    )
    .fetch_one(&runtime.pool)
    .await
    .unwrap();
    assert_eq!(version, 2);

    let reopen = event_for_tenant("tenant-a", now, "pref-3", ContactPreferenceStatus::Allowed);
    let token = jws::sign(signer, "lms-1", TYP_AUTHORITY_UPDATE, &reopen)
        .await
        .unwrap();
    let attempted = verifier
        .verify(
            &token,
            TrustedNow {
                utc: now,
                sync: SyncStatus::Synced { max_error_ms: 0 },
            },
        )
        .unwrap();
    assert_eq!(
        store.apply_preference(&attempted).await.unwrap_err().class,
        ErrorClass::Rejected
    );
    let current = source
        .get("tenant-a", "ref:borrower:B-1", "sms")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current.status, ContactPreferenceStatus::OptedOut);
}
